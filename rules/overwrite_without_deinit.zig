//! oven-sh/bun#28633 / #29864 class — `<this>.<field> = <RHS>;` for a
//! heap-owning field without a prior `<this>.<field>.deinit()` (or
//! `.deref()` / `<allocator>.free(<this>.<field>)`) in the same
//! scope.  Each re-assignment leaks the prior allocation.
//!
//! Detection (per fn, with Db lookups for field-type → deinit-existence):
//!   1. For each fn_decl, get its first param name (`this` / `self`)
//!      and the containing type.
//!   2. Walk the body for `<this>.<field> = <RHS>;` patterns at
//!      statement position.
//!   3. Look up `<field>`'s declared type via `Db.field_types`.  If
//!      that type has a `deinit` method in the Db, the field is
//!      heap-owning per our heuristic.
//!   4. Scan backward through the K=80 preceding tokens (~5–8
//!      statements) for any of:
//!        - `<this>.<field>.<deinit|deref|destroy|close|free>(`
//!        - `<x>.free(<this>.<field>)` / `.destroy(<this>.<field>)`
//!        - `if (<this>.<field>)` (guard implies inspection-then-cleanup)
//!      If none found, fire at the assignment site.
//!
//! Constructor allowlist: skip fns named `init` / `create` / `new` /
//! `from*` / `parse*` — those are first-time-set patterns where the
//! prior field state is the declared default and there's nothing to
//! free.

const std = @import("std");
const Ast = std.zig.Ast;

const fmodel = @import("../model.zig");
const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const lexer = @import("../lexer.zig");
const testing = @import("../testing.zig");
const findStmtSemicolon = lexer.findStmtSemicolon;
const fnProto = lexer.fnProto;
const bodyOf = lexer.bodyOf;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .overwrite_without_deinit)) return;

    const model = try cache.fileModel();
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const fp = fnProto(tree, &buf, node) orelse continue;
        if (returnsType(tree, fp)) continue;
        const name_tok = fp.name_token orelse continue;
        if (isConstructorName(tree.tokenSlice(name_tok))) continue;
        const ct_ti = model.containingTypeOf(node) orelse continue;
        const this_name = lexer.firstParamName(tree, fp) orelse continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, model, ct_ti.name, this_name, body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    model: *const fmodel.FileModel,
    ct: []const u8,
    this_name: []const u8,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    var t: Ast.TokenIndex = first;
    while (t + 3 < last) : (t += 1) {
        // Skip past nested fns.
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        // Match `<this>.<field> = …;` at statement position.
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), this_name)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .equal) continue;
        // Confirm `=` is at statement depth via paren/brace tracking
        // forward to the semicolon.
        const sc = findStmtSemicolon(tags, t + 4, last) orelse continue;
        const field_name = tree.tokenSlice(t + 2);
        // Field-type lookup: must have a known type whose `deinit` is
        // declared in this file AND non-trivial.  Trivial deinit
        // bodies (`{}` or `{ _ = self; }`) are common for trait
        // uniformity (CSS value types in Bun) — overwriting such a
        // field can't leak anything.
        const field_type = model.fieldType(ct, field_name) orelse {
            t = sc;
            continue;
        };
        const inner_ti = model.findType(field_type) orelse {
            t = sc;
            continue;
        };
        if (!hasNonTrivialDeinit(tree, inner_ti)) {
            t = sc;
            continue;
        }
        // Skip optional fields with a `null` default — first write
        // initializes the field rather than overwriting an owned
        // prior value (`signal: ?*Ref = null` lazy-init pattern).
        if (model.fieldIsOptionalNullDefault(ct, field_name)) {
            t = sc;
            continue;
        }
        // Skip when RHS is a `null` / `undefined` sentinel write —
        // canonical "clear after draining" pattern (event-loop free
        // lists, optional resets after consumption).  The leak, if
        // any, was already produced by the drain itself; this
        // statement's job is just to mark the field empty.
        if (rhsIsNullOrUndefined(tree, t + 4, sc)) {
            t = sc;
            continue;
        }
        // Skip when the assignment is inside `<…> orelse { … }`
        // where the orelse's LHS is the same `<this>.<field>` —
        // the assignment runs only when the prior value was null,
        // so there's nothing to leak.
        if (insideOrelseGuard(tree, first, t, this_name, field_name)) {
            t = sc;
            continue;
        }
        // Skip when the assignment is inside `if (!<X>) { ... }` —
        // the negation guard means the write runs on the FALSE
        // path, i.e. when the prior state was empty/uninitialized
        // (canonical lazy-init shape).  Common for `if
        // (!this.loaded) { this.X = ... }`.
        if (insideNegationGuard(tree, first, t)) {
            t = sc;
            continue;
        }
        // Skip inline `defer <this>.<field> = saved;` and
        // `errdefer <this>.<field> = saved;` — the save/restore
        // pattern where the prior value was captured to a local and
        // the defer restores it.  Not an overwrite, no leak.
        if (insideInlineDefer(tags, t)) {
            t = sc;
            continue;
        }
        // Skip when the immediately-preceding statement is an assert
        // that mentions `<this>.<field>` — the author is asserting
        // the prior state is known/empty/default ("first set" guard,
        // common with lazy init).  K=30 tokens is enough to span an
        // `assert(condition);` statement of any reasonable shape.
        if (priorAssertOnField(tree, first, t, this_name, field_name)) {
            t = sc;
            continue;
        }
        // Save-then-deinit (imperative variant of defer-restore):
        //     var prev = this.field;
        //     this.field = new;
        //     prev.deinit();
        // The prior value was saved to a local; the cleanup happens
        // AFTER the overwrite on that local.  Scan backward for the
        // save binding, forward for `<saved>.<cleanup>(`.
        if (savedAndCleanedUp(tree, first, last, t, sc, this_name, field_name)) {
            t = sc;
            continue;
        }
        // Scan backward up to K tokens looking for prior cleanup
        // of <this>.<field>.
        if (priorCleanupExists(tree, first, t, this_name, field_name)) {
            t = sc;
            continue;
        }
        // Tagged-union variant analysis: if the field's type is
        // `union(enum)` AND the RHS is `.{ .<tag> = ... }` AND we
        // can reason about the PRIOR variant (either the field's
        // declared default OR a chronologically-prior assignment
        // in this fn scope), AND that prior variant carries no
        // owned payload, the retag doesn't leak — there was
        // nothing to deinit.
        if (model.isTaggedUnion(field_type)) {
            if (taggedUnionRetagIsSafe(tree, model, field_type,
                first, t, sc, this_name, field_name, ct)) {
                t = sc;
                continue;
            }
        }
        try report(gpa, problems, tree, t, this_name, field_name, ct);
        t = sc;
    }
}

/// Tagged-union retag safety analysis.  For a `<this>.<field> =
/// .{ .<tag> = ... };` where `<field>`'s type is `union(enum)`,
/// the retag is safe iff the PRIOR variant carried no owned
/// payload.  The prior variant is determined by:
///   1. Walking BACK from the current assignment for a chronologically
///      prior `<this>.<field> = .{ .<other> = ... };` in scope.
///   2. If none found in this fn, falling back to the field's
///      declared default `.<tag>`.
/// "Owned" payload = a payload type that has a `deinit` method (or
/// equivalent); empty / primitive payloads are non-owned.
fn taggedUnionRetagIsSafe(
    tree: *const Ast,
    model: *const fmodel.FileModel,
    union_type_name: []const u8,
    body_first: Ast.TokenIndex,
    assign_tok: Ast.TokenIndex,
    sc: Ast.TokenIndex,
    this_name: []const u8,
    field_name: []const u8,
    outer_type_name: []const u8,
) bool {
    _ = sc;
    // Walk back for a prior assignment to this lvalue in the
    // SAME fn body — order matters for variant flow.  Stop at
    // the fn body start (no scope-restriction: any earlier write
    // in this fn establishes the live variant).
    if (priorVariantInFn(tree, body_first, assign_tok, this_name, field_name)) |prior_tag| {
        // We know the prior variant.  Safe iff it's non-owned.
        return (model.unionVariantIsOwned(union_type_name, prior_tag) orelse true) == false;
    }
    // No prior assignment in this fn.  Look for the field's
    // declared default tag first; if the type uses an init()
    // function instead of a field default (Bun convention), scan
    // that for the initial tag.
    const default_tag = model.fieldDefaultUnionTag(outer_type_name, field_name) orelse
        initFnDefaultUnionTag(tree, model, outer_type_name, field_name) orelse return false;
    return (model.unionVariantIsOwned(union_type_name, default_tag) orelse true) == false;
}

/// Fallback: when the field has no inline default `= .<tag>`,
/// scan the containing type's `init` method body for the first
/// `.<field> = .<tag>` (in a struct-init literal) or
/// `<recv>.<field> = .<tag>` (imperative).  Returns the tag name
/// when found.  Common in Bun's codebase where init() sets the
/// initial union variant explicitly rather than declaring a
/// field default.
fn initFnDefaultUnionTag(
    tree: *const Ast,
    model: *const fmodel.FileModel,
    outer_type_name: []const u8,
    field_name: []const u8,
) ?[]const u8 {
    const ti = model.findType(outer_type_name) orelse return null;
    const init_method = ti.findMethod("init") orelse return null;
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = init_method.body_first;
    const last = init_method.body_last;
    while (t + 4 <= last) : (t += 1) {
        // Struct-init form: `. <field> = . <tag>`.
        if (tags[t] == .period and
            tags[t + 1] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t + 1), field_name) and
            tags[t + 2] == .equal and
            tags[t + 3] == .period and
            tags[t + 4] == .identifier)
        {
            return tree.tokenSlice(t + 4);
        }
        // Imperative form: `<recv> . <field> = . <tag>` — needs
        // one more token before the period.
        if (t > 0 and tags[t - 1] == .identifier and
            tags[t] == .period and
            tags[t + 1] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t + 1), field_name) and
            tags[t + 2] == .equal and
            tags[t + 3] == .period and
            tags[t + 4] == .identifier)
        {
            return tree.tokenSlice(t + 4);
        }
    }
    return null;
}

/// Walk backward from `assign_tok` to `body_first` looking for the
/// most-recent prior assignment `<this>.<field> = .{ .<tag> = ... };`.
/// Returns the prior tag name on hit, null on miss.  Brace depth
/// is NOT tracked: any earlier write in the same fn body establishes
/// the variant that the abstract state holds when the current write
/// executes (since assignments earlier in source order dominate later
/// ones in the common straight-line case; nested-block writes are a
/// conservative overestimate of "could have run").
fn priorVariantInFn(
    tree: *const Ast,
    body_first: Ast.TokenIndex,
    assign_tok: Ast.TokenIndex,
    this_name: []const u8,
    field_name: []const u8,
) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (assign_tok < body_first + 5) return null;
    var t: Ast.TokenIndex = assign_tok;
    while (t > body_first + 4) {
        t -= 1;
        // Look for `<this> . <field> = . <tag>` at this position.
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), this_name)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), field_name)) continue;
        if (tags[t + 3] != .equal) continue;
        // Two RHS shapes for tag extraction:
        //   a) `.<tag>` — bare tag (no payload).
        //   b) `.{ .<tag> = ... }` — struct-init form.
        if (t + 5 >= tags.len) continue;
        // Shape (a): `= .<tag>` then `;` or `,`.
        if (tags[t + 4] == .period and tags[t + 5] == .identifier) {
            const after = t + 6;
            if (after < tags.len) {
                switch (tags[after]) {
                    .semicolon, .comma => return tree.tokenSlice(t + 5),
                    else => {},
                }
            }
        }
        // Shape (b): `= . { . <tag> = …`.
        if (t + 7 < tags.len and
            tags[t + 4] == .period and
            tags[t + 5] == .l_brace and
            tags[t + 6] == .period and
            tags[t + 7] == .identifier)
        {
            return tree.tokenSlice(t + 7);
        }
        // Other RHS shape (call returning union) — we can't extract
        // a literal tag from here.  Treat as "prior variant unknown"
        // by returning null so the caller falls back to default.
        return null;
    }
    return null;
}

/// True iff there's a backward `var <X> = <this>.<field>;` binding
/// BEFORE the assignment AND a forward `<X>.<cleanup>(` call AFTER
/// the assignment, both within the same enclosing block.  Catches
/// the imperative save-then-deinit pattern:
///     var prev = this.field;
///     this.field = new;
///     prev.deinit();
fn savedAndCleanedUp(
    tree: *const Ast,
    body_first: Ast.TokenIndex,
    body_last: Ast.TokenIndex,
    assign_tok: Ast.TokenIndex,
    sc: Ast.TokenIndex,
    this_name: []const u8,
    field_name: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    // Backward scan for `<keyword_var|const> <X> = <this>.<field>;`
    // — bounded to K=30 tokens or the enclosing block start.
    const K: u32 = 30;
    var saved_name: ?[]const u8 = null;
    var depth: i32 = 0;
    var i: u32 = 0;
    var t: Ast.TokenIndex = assign_tok;
    while (t > body_first and i < K) : (i += 1) {
        t -= 1;
        switch (tags[t]) {
            .r_brace => depth += 1,
            .l_brace => {
                if (depth == 0) break;
                depth -= 1;
            },
            else => {},
        }
        if (depth != 0) continue;
        // Match `keyword_var <ident> = <this_name> . <field_name>`.
        if (tags[t] != .keyword_var and tags[t] != .keyword_const) continue;
        if (t + 5 > body_last) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .equal) continue;
        if (tags[t + 3] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 3), this_name)) continue;
        if (tags[t + 4] != .period) continue;
        if (tags[t + 5] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 5), field_name)) continue;
        saved_name = tree.tokenSlice(t + 1);
        break;
    }
    const name = saved_name orelse return false;
    // Forward scan from after the `;` for `<name>.<cleanup>(`.
    var k: Ast.TokenIndex = sc + 1;
    depth = 0;
    i = 0;
    while (k <= body_last and i < K) : ({
        k += 1;
        i += 1;
    }) {
        switch (tags[k]) {
            .l_brace => depth += 1,
            .r_brace => {
                if (depth == 0) return false;
                depth -= 1;
            },
            else => {},
        }
        if (depth != 0) continue;
        if (tags[k] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k), name)) continue;
        if (k + 3 > body_last) continue;
        if (tags[k + 1] != .period) continue;
        if (tags[k + 2] != .identifier) continue;
        if (tags[k + 3] != .l_paren) continue;
        const m = tree.tokenSlice(k + 2);
        if (std.mem.eql(u8, m, "deinit") or std.mem.eql(u8, m, "deref") or
            std.mem.eql(u8, m, "destroy") or std.mem.eql(u8, m, "close") or
            std.mem.eql(u8, m, "free") or std.mem.eql(u8, m, "finalize") or
            std.mem.eql(u8, m, "dispose"))
        {
            return true;
        }
    }
    return false;
}

/// True iff `ti` has a `deinit` method with a non-trivial body —
/// any statement that's not a `_ = <expr>;` discard.  Mirrors the
/// same check in owned-field-no-outer-cleanup.  Returns false for
/// types whose deinit is `{}` or only discards (CSS uniform-API
/// conformance); overwriting such a field can't leak anything.
fn hasNonTrivialDeinit(tree: *const Ast, ti: *const fmodel.TypeInfo) bool {
    for (ti.methods) |m| {
        if (!std.mem.eql(u8, m.name, "deinit")) continue;
        if (!isTrivialBody(tree, m.body_first, m.body_last)) return true;
    }
    return false;
}

fn isTrivialBody(tree: *const Ast, body_first: Ast.TokenIndex, body_last: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    if (body_first >= body_last) return true;
    if (body_first + 1 == body_last) return true;
    var t: Ast.TokenIndex = body_first + 1;
    while (t < body_last) {
        if (tags[t] != .identifier) return false;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "_")) return false;
        if (t + 1 >= body_last or tags[t + 1] != .equal) return false;
        var depth: u32 = 0;
        var k = t + 2;
        while (k < body_last) : (k += 1) {
            switch (tags[k]) {
                .l_paren, .l_brace, .l_bracket => depth += 1,
                .r_paren, .r_brace, .r_bracket => {
                    if (depth == 0) return false;
                    depth -= 1;
                },
                .semicolon => if (depth == 0) break,
                else => {},
            }
        }
        if (k >= body_last or tags[k] != .semicolon) return false;
        t = k + 1;
    }
    return true;
}

/// True iff `assign_tok` (the `<this>` ident in `<this>.<field> = …`)
/// is the body of an inline `defer` / `errdefer` statement.  Matches:
///   `defer <this>.<field> = saved;`
///   `errdefer <this>.<field> = saved;`
///   `errdefer |err| <this>.<field> = saved;`
///   `defer { <this>.<field> = saved; ... }` (first stmt in block)
fn insideInlineDefer(tags: []const std.zig.Token.Tag, assign_tok: Ast.TokenIndex) bool {
    if (assign_tok == 0) return false;
    const t = assign_tok - 1;
    // Bare `defer` / `errdefer` immediately before.
    if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) return true;
    // `errdefer |err|` — peel `|err|`.
    if (tags[t] == .pipe and t >= 3) {
        if (tags[t - 1] == .identifier and tags[t - 2] == .pipe) {
            if (t >= 4 and tags[t - 3] == .keyword_errdefer) return true;
        }
    }
    // Block form: `defer { <stmt>; … }` — first stmt has `{` then
    // `defer`/`errdefer` directly before it.
    if (tags[t] == .l_brace and t >= 1) {
        if (tags[t - 1] == .keyword_defer or tags[t - 1] == .keyword_errdefer) return true;
    }
    return false;
}

/// True iff a recent `assert(<expr involving this.field>)` /
/// `bun.assert(...)` / `std.debug.assert(...)` precedes `assign_tok`.
/// Bounded to a 30-token lookback so we don't pick up unrelated
/// asserts earlier in the fn.
fn priorAssertOnField(
    tree: *const Ast,
    start: Ast.TokenIndex,
    assign_tok: Ast.TokenIndex,
    this_name: []const u8,
    field_name: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    const K: u32 = 64;
    var i: u32 = 0;
    var t: Ast.TokenIndex = assign_tok;
    var saw_field = false;
    while (t > start and i < K) : (i += 1) {
        t -= 1;
        if (tags[t] == .identifier) {
            const s = tree.tokenSlice(t);
            // Look for the field-name ident followed (going forward)
            // by the this name — i.e. `<this>.<field>` shape.
            if (std.mem.eql(u8, s, field_name) and t >= 2 and
                tags[t - 1] == .period and tags[t - 2] == .identifier and
                std.mem.eql(u8, tree.tokenSlice(t - 2), this_name))
            {
                saw_field = true;
            }
            // The assert identifier.  Recognize `assert` and the
            // last-segment of `bun.assert` / `std.debug.assert` etc.
            if (saw_field and std.mem.eql(u8, s, "assert")) return true;
        }
    }
    return false;
}

/// True iff the RHS at `[start, end)` is exactly `null`, `undefined`,
/// or `.{}` / `&.{}` / `.empty` — the canonical "clear" sentinels.
fn rhsIsNullOrUndefined(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    if (start >= end) return false;
    // Single-token forms.
    if (start + 1 == end) {
        if (tags[start] != .identifier) return false;
        const s = tree.tokenSlice(start);
        return std.mem.eql(u8, s, "null") or std.mem.eql(u8, s, "undefined");
    }
    // `.{}` / `&.{}` / `.empty`.
    if (start + 3 == end and
        tags[start] == .period and
        tags[start + 1] == .l_brace and
        tags[start + 2] == .r_brace) return true;
    if (start + 4 == end and
        tags[start] == .ampersand and
        tags[start + 1] == .period and
        tags[start + 2] == .l_brace and
        tags[start + 3] == .r_brace) return true;
    if (start + 2 == end and
        tags[start] == .period and
        tags[start + 1] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(start + 1), "empty")) return true;
    return false;
}

/// True iff the assignment at `assign_tok` is inside an
/// `<this>.<field> orelse { … }` block — i.e. the enclosing `{`
/// is preceded by `keyword_orelse`, and the immediately-preceding
/// tokens before that `orelse` are the same `<this>.<field>` chain.
/// Inside such a block the prior value is guaranteed null, so the
/// assignment isn't an overwrite.
/// True iff the assignment sits inside `if (!<expr>) { ... }` —
/// the negation-guarded init pattern.  Walk back to the enclosing
/// `{`, check that the matching token sequence reading back is
/// `(` ... `!` ... `)` ... `{`.  Conservative: only the very
/// outermost expression's first non-paren token after the `(` is
/// inspected; nested `!` isn't required.
fn insideNegationGuard(
    tree: *const Ast,
    start: Ast.TokenIndex,
    assign_tok: Ast.TokenIndex,
) bool {
    const tags = tree.tokens.items(.tag);
    var depth: i32 = 0;
    var t: Ast.TokenIndex = assign_tok;
    while (t > start) {
        t -= 1;
        switch (tags[t]) {
            .r_brace => depth += 1,
            .l_brace => {
                if (depth == 0) {
                    // Found the opening brace of our enclosing block.
                    // Must be preceded by `)` (the if-condition's close).
                    if (t < 3) return false;
                    if (tags[t - 1] != .r_paren) return false;
                    // Walk back paren-balanced to the `(`.
                    var p_depth: i32 = 1;
                    var p: Ast.TokenIndex = t - 1;
                    while (p > start and p_depth > 0) {
                        p -= 1;
                        switch (tags[p]) {
                            .r_paren => p_depth += 1,
                            .l_paren => p_depth -= 1,
                            else => {},
                        }
                    }
                    if (p_depth != 0) return false;
                    // Token before `(` should be `if`.
                    if (p == 0 or tags[p - 1] != .keyword_if) return false;
                    // First token inside `(` must be `!`.
                    if (p + 1 >= t - 1) return false;
                    return tags[p + 1] == .bang;
                }
                depth -= 1;
            },
            else => {},
        }
    }
    return false;
}

fn insideOrelseGuard(
    tree: *const Ast,
    start: Ast.TokenIndex,
    assign_tok: Ast.TokenIndex,
    this_name: []const u8,
    field_name: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    // Walk back finding the matching `{` for our enclosing block,
    // tracking brace depth.
    var depth: i32 = 0;
    var t: Ast.TokenIndex = assign_tok;
    while (t > start) {
        t -= 1;
        switch (tags[t]) {
            .r_brace => depth += 1,
            .l_brace => {
                if (depth == 0) {
                    // Found the opening brace.  Check what precedes it.
                    if (t < 3) return false;
                    if (tags[t - 1] != .keyword_orelse) return false;
                    // Token at t-2 should be the field ident, t-3
                    // the period, t-4 the this ident.
                    if (t < 4) return false;
                    if (tags[t - 2] != .identifier or
                        !std.mem.eql(u8, tree.tokenSlice(t - 2), field_name)) return false;
                    if (tags[t - 3] != .period) return false;
                    if (tags[t - 4] != .identifier or
                        !std.mem.eql(u8, tree.tokenSlice(t - 4), this_name)) return false;
                    return true;
                }
                depth -= 1;
            },
            else => {},
        }
    }
    return false;
}

/// Walk tokens backward from `assign_tok` (the `<this>` ident) up
/// to `start` (body's firstToken) or 80 tokens — whichever is closer
/// — looking for prior cleanup of `<this>.<field>`.  Accepts:
///   - `<this>.<field>.deinit(` / `.deref(` / `.destroy(` / `.close(` / `.free(` / `.finalize(`
///   - `<x>.free(<this>.<field>)` / `.destroy(<this>.<field>)`
///   - `if (<this>.<field>) |…|` (guard implies cleanup-on-some-path)
fn priorCleanupExists(
    tree: *const Ast,
    start: Ast.TokenIndex,
    assign_tok: Ast.TokenIndex,
    this_name: []const u8,
    field_name: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    const win_size: u32 = 80;
    var window_start: Ast.TokenIndex = start;
    if (assign_tok > start + win_size) window_start = assign_tok - win_size;
    var t: Ast.TokenIndex = window_start;
    while (t + 3 < assign_tok) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), this_name)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), field_name)) continue;
        // Pattern A: `<this>.<field>.<cleanup>(`.
        if (t + 4 < assign_tok and
            tags[t + 3] == .period and
            tags[t + 4] == .identifier and
            isCleanupMethodName(tree.tokenSlice(t + 4)))
        {
            return true;
        }
        // Pattern B: `if (<this>.<field>)` guard.
        if (t >= 2 and tags[t - 1] == .l_paren and tags[t - 2] == .keyword_if) {
            return true;
        }
        // Pattern C: `<x>.<free/destroy>(<this>.<field>)`.
        // Token before the start of `<this>.<field>` would be `l_paren`,
        // preceded by `.free` / `.destroy`.
        if (t >= 3 and tags[t - 1] == .l_paren and
            tags[t - 2] == .identifier)
        {
            const callee = tree.tokenSlice(t - 2);
            if (isFreeOrDestroy(callee)) return true;
        }
    }
    return false;
}

fn isCleanupMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "deref") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "close") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "release") or
        std.mem.eql(u8, name, "finalize");
}

fn isFreeOrDestroy(name: []const u8) bool {
    return std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "destroy");
}

fn isConstructorName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "init")) return true;
    if (std.mem.eql(u8, name, "create")) return true;
    if (std.mem.eql(u8, name, "new")) return true;
    if (std.mem.startsWith(u8, name, "init")) return true;
    if (std.mem.startsWith(u8, name, "from")) return true;
    if (std.mem.startsWith(u8, name, "parse")) return true;
    if (std.mem.startsWith(u8, name, "decode")) return true;
    return false;
}

fn returnsType(tree: *const Ast, fp: Ast.full.FnProto) bool {
    const rt = fp.ast.return_type.unwrap() orelse return false;
    const first = tree.firstToken(rt);
    const last = tree.lastToken(rt);
    if (first != last) return false;
    return tree.tokens.items(.tag)[first] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(first), "type");
}

fn skipNestedFn(tags: []const std.zig.Token.Tag, kw_fn: Ast.TokenIndex, last: Ast.TokenIndex) Ast.TokenIndex {
    var t: Ast.TokenIndex = kw_fn + 1;
    while (t <= last and tags[t] != .l_paren) : (t += 1) {}
    if (t > last) return last;
    var depth: u32 = 1;
    t += 1;
    while (t <= last and depth > 0) : (t += 1) {
        switch (tags[t]) {
            .l_paren => depth += 1,
            .r_paren => depth -= 1,
            else => {},
        }
    }
    while (t <= last and tags[t] != .l_brace) : (t += 1) {
        if (tags[t] == .semicolon or tags[t] == .comma or tags[t] == .keyword_fn) return t;
    }
    if (t > last or tags[t] != .l_brace) return @min(t, last);
    depth = 1;
    t += 1;
    while (t <= last and depth > 0) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => depth -= 1,
            else => {},
        }
    }
    return @min(t -| 1, last);
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    this_tok: Ast.TokenIndex,
    this_name: []const u8,
    field_name: []const u8,
    ct: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}.{s}` is overwritten here without first calling `{s}.{s}.deinit()` (or `.deref()` / `<allocator>.free(...)`); the prior value of `{s}.{s}` (which is `{s}.{s}` — a type with a `deinit` method) leaks every time this assignment runs",
        .{ this_name, field_name, this_name, field_name, this_name, field_name, ct, field_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "overwrite-without-deinit",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, this_tok),
        .end = Pos.fromTokenEnd(tree, this_tok + 2),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "overwrite-without-deinit: reassign deinit-able field without prior cleanup fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Owned = struct {
        \\    buf: []u8,
        \\    pub fn deinit(self: *Owned) void { self.buf.len = 0; }
        \\};
        \\const NameOrIndex = union(enum) {
        \\    name: Owned,
        \\    index: u32,
        \\    duplicate,
        \\    pub fn deinit(self: *NameOrIndex) void { _ = self; self.* = .duplicate; }
        \\};
        \\const Field = struct {
        \\    name_or_index: NameOrIndex = .name,
        \\    pub fn markDup(this: *Field) void {
        \\        this.name_or_index = .duplicate;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("overwrite-without-deinit", problems.items[0].rule_id);
}

test "overwrite-without-deinit: prior `.deinit()` is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const NameOrIndex = union(enum) {
        \\    name: u32,
        \\    duplicate,
        \\    pub fn deinit(self: *NameOrIndex) void { _ = self; self.* = .duplicate; }
        \\};
        \\const Field = struct {
        \\    name_or_index: NameOrIndex = .duplicate,
        \\    pub fn markDup(this: *Field) void {
        \\        this.name_or_index.deinit();
        \\        this.name_or_index = .duplicate;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "overwrite-without-deinit: field type has no `deinit` method — skip" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Plain = struct { a: u32 = 0 };
        \\const Owner = struct {
        \\    inner: Plain = .{},
        \\    pub fn set(this: *Owner, p: Plain) void {
        \\        this.inner = p;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "overwrite-without-deinit: constructor fn (init/create/from*) is skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const NameOrIndex = union(enum) {
        \\    name: u32,
        \\    duplicate,
        \\    pub fn deinit(self: *NameOrIndex) void { _ = self; self.* = .duplicate; }
        \\};
        \\const Field = struct {
        \\    name_or_index: NameOrIndex = .duplicate,
        \\    pub fn init(this: *Field) void {
        \\        this.name_or_index = .duplicate;
        \\    }
        \\    pub fn fromJS(this: *Field) void {
        \\        this.name_or_index = .duplicate;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "overwrite-without-deinit: explicit `<allocator>.free(this.field)` cleanup is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Inner = struct { pub fn deinit(self: *Inner) void { self.* = undefined; } };
        \\const Owner = struct {
        \\    inner: Inner = .{},
        \\    pub fn replace(this: *Owner, new_inner: Inner, a: std.mem.Allocator) void {
        \\        a.destroy(this.inner);
        \\        this.inner = new_inner;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "overwrite-without-deinit: `if (this.field) |…|` guard counts as cleanup" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Inner = struct { pub fn deinit(self: *Inner) void { self.* = undefined; } };
        \\const Owner = struct {
        \\    inner: ?Inner = null,
        \\    pub fn swap(this: *Owner, new_inner: Inner) void {
        \\        if (this.inner) |*old| old.deinit();
        \\        this.inner = new_inner;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "overwrite-without-deinit: inline `defer this.field = saved;` (save/restore) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Inner = struct { pub fn deinit(self: *Inner) void { self.* = undefined; } };
        \\const Owner = struct {
        \\    inner: Inner,
        \\    pub fn withTemp(this: *Owner, new_inner: Inner) void {
        \\        const prev = this.inner;
        \\        defer this.inner = prev;
        \\        this.inner = new_inner;
        \\        _ = new_inner;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    // The `defer this.inner = prev;` line is a restore — no FP there.
    // The unguarded `this.inner = new_inner` IS a real overwrite
    // without prior cleanup → should fire exactly once.
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "overwrite-without-deinit: assert(this.field == default) gates the write — no fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Inner = struct { pub fn deinit(self: *Inner) void { self.* = undefined; } };
        \\const Owner = struct {
        \\    inner: Inner,
        \\    pub fn lazyInit(this: *Owner, new_inner: Inner) void {
        \\        bun.assert(this.inner == .empty);
        \\        this.inner = new_inner;
        \\    }
        \\};
        \\const bun = struct { pub fn assert(_: bool) void {} };
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
