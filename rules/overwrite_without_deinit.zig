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

const annotations_mod = @import("../annotations.zig");
const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");

const Db = annotations_mod.Db;
const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: *const Db,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .overwrite_without_deinit)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const fp = fnProto(tree, &buf, node) orelse continue;
        if (returnsType(tree, fp)) continue;
        const name_tok = fp.name_token orelse continue;
        if (isConstructorName(tree.tokenSlice(name_tok))) continue;
        const ct = db.containingType(node) orelse continue;
        const this_name = firstParamName(tree, fp) orelse continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, db, ct, this_name, body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: *const Db,
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
        // in the Db.  Skip otherwise.
        const field_type = db.fieldType(ct, field_name) orelse {
            t = sc;
            continue;
        };
        if (db.lookupTyped(field_type, "deinit") == null) {
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
        // Scan backward up to K tokens looking for prior cleanup
        // of <this>.<field>.
        if (priorCleanupExists(tree, first, t, this_name, field_name)) {
            t = sc;
            continue;
        }
        try report(gpa, problems, tree, t, this_name, field_name, ct);
        t = sc;
    }
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

fn findStmtSemicolon(tags: []const std.zig.Token.Tag, start: Ast.TokenIndex, last: Ast.TokenIndex) ?Ast.TokenIndex {
    var paren: u32 = 0;
    var brace: u32 = 0;
    var bracket: u32 = 0;
    var t: Ast.TokenIndex = start;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_paren => paren += 1,
            .r_paren => if (paren > 0) {
                paren -= 1;
            },
            .l_brace => brace += 1,
            .r_brace => if (brace > 0) {
                brace -= 1;
            },
            .l_bracket => bracket += 1,
            .r_bracket => if (bracket > 0) {
                bracket -= 1;
            },
            .semicolon => if (paren == 0 and brace == 0 and bracket == 0) return t,
            else => {},
        }
    }
    return null;
}

fn returnsType(tree: *const Ast, fp: Ast.full.FnProto) bool {
    const rt = fp.ast.return_type.unwrap() orelse return false;
    const first = tree.firstToken(rt);
    const last = tree.lastToken(rt);
    if (first != last) return false;
    return tree.tokens.items(.tag)[first] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(first), "type");
}

fn firstParamName(tree: *const Ast, fp: Ast.full.FnProto) ?[]const u8 {
    var it = fp.iterate(tree);
    const first = it.next() orelse return null;
    const tok = first.name_token orelse return null;
    return tree.tokenSlice(tok);
}

fn fnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) ?Ast.full.FnProto {
    return switch (tree.nodeTag(node)) {
        .fn_decl => switch (tree.nodeTag(tree.nodeData(node).node_and_node[0])) {
            .fn_proto => tree.fnProto(tree.nodeData(node).node_and_node[0]),
            .fn_proto_multi => tree.fnProtoMulti(tree.nodeData(node).node_and_node[0]),
            .fn_proto_one => tree.fnProtoOne(buf, tree.nodeData(node).node_and_node[0]),
            .fn_proto_simple => tree.fnProtoSimple(buf, tree.nodeData(node).node_and_node[0]),
            else => null,
        },
        else => null,
    };
}

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
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
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);
    var db = try annotations_mod.buildFull(gpa, &tree, null, null);
    defer db.deinit(gpa);
    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    try check(gpa, &tree, &db, &config_mod.Default, &problems);
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(Problem)) void {
    for (p.items) |*x| x.deinit(gpa);
    p.deinit(gpa);
}

test "overwrite-without-deinit: reassign deinit-able field without prior cleanup fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const NameOrIndex = union(enum) {
        \\    name: u32,
        \\    index: u32,
        \\    duplicate,
        \\    pub fn deinit(_: *NameOrIndex) void {}
        \\};
        \\const Field = struct {
        \\    name_or_index: NameOrIndex = .duplicate,
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
        \\    pub fn deinit(_: *NameOrIndex) void {}
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
        \\    pub fn deinit(_: *NameOrIndex) void {}
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
        \\const Inner = struct { pub fn deinit(_: *Inner) void {} };
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
        \\const Inner = struct { pub fn deinit(_: *Inner) void {} };
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
