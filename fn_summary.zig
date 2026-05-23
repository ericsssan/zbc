//! Per-fn behavioral summary, inferred from the body (purely
//! syntactic).  Parallel API to the older annotations.Db — same
//! semantic ground, but no `/// @returns` doc-comment parsing.
//! The author overrides the tool's inferred belief via
//! `// zbc-disable-line:` suppressions, not by asserting alternative
//! semantics.
//!
//! Summary fields are deliberately COARSE.  Each one answers a
//! specific question a downstream consumer asks:
//!
//!   returns                — "does the call leak ownership to the caller?"
//!   takes_ownership_of     — "does the call invalidate one of its args?"
//!   is_noreturn            — "does the call terminate the basic block?"
//!   allocates              — "does the body call into an allocator?"
//!   deallocates            — "does the body call .free / .destroy / etc.?"
//!
//! Anything inference can't reach is `.unknown` / null / false.
//! Consumers MUST treat `.unknown` as "assume nothing" — same as
//! today's `lowering_gap` conservative fallback.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("lexer.zig");
const vocabulary = @import("vocabulary.zig");

/// Result-shape classification.
pub const Returns = union(enum) {
    /// No lifetime constraint — value-typed return, primitive, etc.
    plain,
    /// Caller receives a tracked heap allocation (the body has an
    /// alloc / create / dupe call whose result feeds the return).
    heap,
    /// Caller owns the value but it isn't a tracked heap id (returned
    /// from a wrapper / opaque source).  Distinct from `.heap` so
    /// consumers know NOT to mint a HeapId.
    owned,
    /// Return value borrows from the named parameter (0-indexed).
    /// Caller's lifetime is bound to the param's.
    borrowed_from: u32,
    /// Couldn't classify — conservative.
    unknown,
};

/// A `<param>.<field>` chain that a fn's body destroys.  Multiple
/// entries per fn possible — `fn deinit(self) { self.x.free(); self.y.close(); }`
/// emits two.  Same shape as the old `annotations.FieldFree`.
pub const FieldFree = struct {
    /// 0-indexed param whose `.<field>` is freed (0 = receiver).
    param: u32,
    /// Field name (slice into source — caller keeps tree alive).
    field: []const u8,
};

pub const FnSummary = struct {
    returns: Returns = .unknown,
    /// If non-null, the call site invalidates the value passed at
    /// this parameter index.  Mirrors `@takes ownership(<param>)` from
    /// the old annotation system.
    takes_ownership_of: ?u32 = null,
    /// Body returns via `unreachable` / calls `@panic` / signature
    /// says `noreturn`.
    is_noreturn: bool = false,
    /// Body invokes an alloc-class call somewhere.  Coarse — doesn't
    /// distinguish allocator identities.
    allocates: bool = false,
    /// Body invokes a free / destroy / cleanup call.  Coarse — same
    /// caveat as `allocates`.
    deallocates: bool = false,
    /// `<param>.<field>.<destroy_method>()` chains in the body — one
    /// entry per chain.  Lets call sites emit a `.field_heap_free`
    /// per chain.  Slice is owned by the FnSummaryCache arena.
    may_free_fields: []const FieldFree = &.{},
    /// Field names that a constructor allocates and stores into the
    /// returned struct literal — i.e. `return .{ .X = alloc(), ... }`.
    /// Lets call sites mint synthetic `field_assign(local, X,
    /// .heap_alloc)` so subsequent `local.X` reads see correct UAF
    /// state.  Slice is owned by the FnSummaryCache arena.
    result_heap_fields: []const []const u8 = &.{},
    /// Body contains `<x>.create(<containing-type>)` or
    /// `<x>.create(Self)` — i.e. allocates a heap instance of its
    /// own type.  Filled when the containing type is known; null
    /// when the fn is top-level (no containing type).
    heap_allocates_self: bool = false,
    /// Internal flag: true iff FileCache.summaryOfFn has fully
    /// populated this entry (cheap + deep inference).  Distinct
    /// from "no fields detected" — without this flag, fns with
    /// genuinely empty `may_free_fields` would be indistinguishable
    /// from never-resolved and would get re-inferred (wiping any
    /// R10 transitive updates).  Not part of the public contract;
    /// consumers should treat the summary as resolved when they
    /// retrieve it via FileCache.
    _resolved: bool = false,
};

/// Infer a summary for `body`.  Conservative: when unclear, returns
/// `.unknown` / null / false — never guesses.  `proto` carries the
/// param list so `borrowed_from` can resolve to a param index.
///
/// Body-only inference: only fills fields that can be determined
/// from the proto + body alone.  `heap_allocates_self` requires the
/// containing type's NAME (a contextual lookup) and `may_free_fields`
/// / `result_heap_fields` need allocations to land somewhere stable —
/// caller may want `inferFromBodyAlloc` for those.
pub fn inferFromBody(
    tree: *const Ast,
    proto: Ast.full.FnProto,
    body: Ast.Node.Index,
) FnSummary {
    var out: FnSummary = .{};
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    // ── is_noreturn from the return-type signature ─────────────
    if (proto.ast.return_type.unwrap()) |rt| {
        const rt_first = tree.firstToken(rt);
        if (tags[rt_first] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(rt_first), "noreturn"))
        {
            out.is_noreturn = true;
        }
    }

    // ── Body-wide effects (allocates / deallocates) ────────────
    // Scan for `.<method>(` shapes where method is alloc / free / etc.
    // Skips nested fns so a helper-fn-decl inside the body doesn't
    // leak its own classification upward.
    var t = first;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        const method = tree.tokenSlice(t + 1);
        if (vocabulary.lookupMethod(method)) |vs| {
            if (vs.allocates) out.allocates = true;
            if (vs.deallocates) out.deallocates = true;
        }
    }

    // ── returns: scan the FIRST `return <expr>` shape ──────────
    // Body inference is conservative — we only classify when the
    // shape is unambiguous.  Multi-arm returns (different shapes per
    // arm) collapse to `.unknown` rather than guessing.
    if (firstReturnExpr(tree, first, last)) |re| {
        out.returns = classifyReturnExpr(tree, proto, re.first, re.last, out.allocates);
    }

    // Direct takes_ownership_of inference (R8b-style: .free(<param>)
    // / .destroy(<param>) only).  See inferDirectTakes for the
    // conservative rationale around <param>.deinit() being excluded.
    out.takes_ownership_of = inferDirectTakes(tree, proto, body);

    return out;
}

/// Token range of a `return <expr>;` body, if the body has one at
/// brace-depth 0 (relative to the fn body).  Skips nested fns.
fn firstReturnExpr(
    tree: *const Ast,
    body_first: lexer.TokenIndex,
    body_last: lexer.TokenIndex,
) ?struct { first: lexer.TokenIndex, last: lexer.TokenIndex } {
    const tags = tree.tokens.items(.tag);
    var t = body_first;
    while (t <= body_last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, body_last);
            continue;
        }
        if (tags[t] != .keyword_return) continue;
        if (t + 1 > body_last) return null;
        // `return;` (no value) — not a value return.
        if (tags[t + 1] == .semicolon) return null;
        const sc = lexer.findStmtSemicolon(tags, t + 1, body_last) orelse return null;
        if (sc == t + 1) return null;
        return .{ .first = t + 1, .last = sc - 1 };
    }
    return null;
}

/// Classify a `return <expr>` token range against the param list.
fn classifyReturnExpr(
    tree: *const Ast,
    proto: Ast.full.FnProto,
    first: lexer.TokenIndex,
    last: lexer.TokenIndex,
    body_allocates: bool,
) Returns {
    const tags = tree.tokens.items(.tag);
    if (first > last) return .unknown;

    // `return try <expr>` — strip the `try` and re-classify.
    if (tags[first] == .keyword_try and first + 1 <= last) {
        return classifyReturnExpr(tree, proto, first + 1, last, body_allocates);
    }

    // Bare `return undefined;` — `.unknown` rather than misclassify.
    // `undefined` is tokenized as an identifier with that text.
    if (first == last and tags[first] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(first), "undefined")) return .unknown;

    // `return <chain>.<allocMethod>(...)` — if the chain ends in an
    // alloc-class call, the result is a fresh heap allocation.
    // Checked BEFORE the param-borrow check so `return gpa.alloc(...)`
    // classifies as .heap, not .borrowed_from(gpa).
    if (returnIsAllocCall(tree, first, last)) return .heap;

    // `return <param>` / `return <param>.<field>` /
    // `return <param>.<method>(...)` — borrowed_from(param).
    if (tags[first] == .identifier) {
        const head = tree.tokenSlice(first);
        if (paramIndex(tree, proto, head)) |idx| {
            return .{ .borrowed_from = idx };
        }
    }

    // Body has an alloc and the return is some shape we can't pin
    // down — conservative `.owned` (caller owns, no tracked id).
    // Only emit when the body genuinely allocates, otherwise stay
    // `.unknown` so callers don't assume ownership transfer.
    if (body_allocates) return .owned;

    return .unknown;
}

fn returnIsAllocCall(
    tree: *const Ast,
    first: lexer.TokenIndex,
    last: lexer.TokenIndex,
) bool {
    const tags = tree.tokens.items(.tag);
    // Walk the chain `<id>(.<id>)*\(`, identify the LAST method ident
    // before the first `(`, and look it up in the vocabulary.
    var t = first;
    var last_method: ?lexer.TokenIndex = null;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .identifier => last_method = t,
            .period => {},
            .l_paren => break,
            else => return false,
        }
    }
    const m = last_method orelse return false;
    if (vocabulary.lookupMethod(tree.tokenSlice(m))) |vs| {
        return vs.allocates;
    }
    return false;
}

fn paramIndex(tree: *const Ast, proto: Ast.full.FnProto, name: []const u8) ?u32 {
    var idx: u32 = 0;
    var it = proto.iterate(tree);
    while (it.next()) |p| : (idx += 1) {
        const name_tok = p.name_token orelse continue;
        if (std.mem.eql(u8, tree.tokenSlice(name_tok), name)) return idx;
    }
    return null;
}

/// Scan `body` for direct ownership-transfer patterns and return
/// the index of the first param the fn takes (if any).
///
/// Matches `.free(<param>)` / `.destroy(<param>)` — the param is
/// passed as the explicit arg to an allocator-vocabulary free.
/// Mirrors annotations.zig R8b.
///
/// Deliberately does NOT match `<param>.deinit()` / `.close()` /
/// other receiver-cleanup forms.  Those signals are ambiguous: a
/// fn body can call `self.deinit(); self.entries = ...;` as a
/// reset-and-resurrect pattern where self isn't actually consumed.
/// Without dataflow tracking we can't tell the difference, so we
/// stay conservative — annotations.zig's same restriction.
///
/// Returns the FIRST match.  When multiple params are consumed the
/// summary only records one; consumers that need fuller fidelity
/// should consult `may_free_fields` for the field-typed cases.
pub fn inferDirectTakes(
    tree: *const Ast,
    proto: Ast.full.FnProto,
    body: Ast.Node.Index,
) ?u32 {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    var t = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            continue;
        }
        // `.free(<param>)` / `.destroy(<param>)`.  The arg is the
        // consumed value (not the receiver).  Reject mid-chain match
        // where the arg has its own field access (`.free(this.field)`
        // doesn't consume this).
        if (tags[t] == .period and tags[t + 1] == .identifier and
            tags[t + 2] == .l_paren and tags[t + 3] == .identifier)
        {
            const method = tree.tokenSlice(t + 1);
            const is_free = std.mem.eql(u8, method, "free") or
                std.mem.eql(u8, method, "destroy");
            if (!is_free) continue;
            // Guard: arg followed by `.` is a field access on the
            // arg — the param itself isn't being freed.
            if (t + 4 <= last and tags[t + 4] == .period) continue;
            const arg = tree.tokenSlice(t + 3);
            if (paramIndex(tree, proto, arg)) |pi| return pi;
        }
    }
    return null;
}

// ── Deep inference (allocates) ────────────────────────────

/// Scan `body` for `<param>.<field>.<destroy_method>(...)` chains.
/// Returns one entry per chain.  Caller owns the returned slice;
/// pass an arena allocator so per-fn deinit is cheap.
pub fn inferMayFreeFields(
    arena: std.mem.Allocator,
    tree: *const Ast,
    proto: Ast.full.FnProto,
    body: Ast.Node.Index,
) ![]const FieldFree {
    var out: std.ArrayListUnmanaged(FieldFree) = .empty;
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    var t = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            continue;
        }
        // Match `<id>.<id>.<id>(` shape.
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        if (tags[t + 5] != .l_paren) continue;
        const recv = tree.tokenSlice(t);
        const idx = paramIndex(tree, proto, recv) orelse continue;
        const method = tree.tokenSlice(t + 4);
        if (vocabulary.lookupMethod(method)) |vs| {
            if (!vs.deallocates) continue;
            try out.append(arena, .{
                .param = idx,
                .field = tree.tokenSlice(t + 2),
            });
        }
    }
    return out.toOwnedSlice(arena);
}

/// True iff the body contains `<x>.create(<type_name>)` or
/// `<x>.create(Self)`.  Returns false when `type_name` is null
/// (top-level fns have no containing type).
pub fn inferHeapAllocatesSelf(
    tree: *const Ast,
    body: Ast.Node.Index,
    type_name: ?[]const u8,
) bool {
    const tn = type_name orelse return false;
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    var t = first;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 1), "create")) continue;
        if (tags[t + 2] != .l_paren) continue;
        // Walk the call's arg list (single arg expected, possibly
        // namespaced like `ns.Type`) and check the LAST identifier
        // against `tn` / `Self`.
        var k = t + 3;
        var last_ident: ?Ast.TokenIndex = null;
        while (k <= last) : (k += 1) {
            if (tags[k] == .r_paren or tags[k] == .comma) break;
            if (tags[k] == .identifier) last_ident = k;
        }
        if (last_ident) |li| {
            const text = tree.tokenSlice(li);
            if (std.mem.eql(u8, text, tn)) return true;
            if (std.mem.eql(u8, text, "Self")) return true;
        }
    }
    return false;
}

/// If `body` is `{ return <struct_literal>; }` and any field's
/// initializer text contains an alloc call (`.alloc(`, `.create(`,
/// `.dupe(`, etc.), return the list of those field names.  Empty
/// for non-constructor bodies.  Caller owns the returned slice.
pub fn inferResultHeapFields(
    arena: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
) ![]const []const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    // Text-based approach matching the original annotations.zig
    // pipeline: find a `return ... { .X = ... }` struct-literal
    // shape, then text-match each field's RHS against the alloc-call
    // vocabulary.  Per-token introspection of a struct literal AST
    // node would be more precise but this is good enough for the
    // common constructor shape and matches the existing pipeline's
    // conservatism.
    const source = tree.source;
    const tags = tree.tokens.items(.tag);
    const starts = tree.tokens.items(.start);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    // Find `return` at depth 0 of the body, then look for `.{` or
    // `<Type>{` following it.
    var t = first;
    var ret_at: ?Ast.TokenIndex = null;
    while (t <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] == .keyword_return) {
            ret_at = t;
            break;
        }
    }
    const ra = ret_at orelse return &.{};
    // Find the `{` after the return that opens a struct literal.
    var k = ra + 1;
    while (k <= last and tags[k] != .l_brace and tags[k] != .semicolon) : (k += 1) {}
    if (k > last or tags[k] != .l_brace) return &.{};
    const lb = k;
    const rb = lexer.matchBrace(tags, lb, last) orelse return &.{};
    // Walk the literal's body looking for `.<name> = <rhs>,` pairs.
    var i: lexer.TokenIndex = lb + 1;
    while (i < rb) : (i += 1) {
        if (tags[i] != .period) continue;
        if (i + 2 > rb) break;
        if (tags[i + 1] != .identifier) continue;
        if (tags[i + 2] != .equal) continue;
        const fname = tree.tokenSlice(i + 1);
        // Find end of this field's RHS: the comma at depth 0
        // (relative to where we are) or `}`.
        var depth: u32 = 0;
        var j: lexer.TokenIndex = i + 3;
        while (j <= rb) : (j += 1) {
            switch (tags[j]) {
                .l_paren, .l_brace, .l_bracket => depth += 1,
                .r_paren, .r_brace, .r_bracket => {
                    if (depth == 0) break;
                    depth -= 1;
                },
                .comma => if (depth == 0) break,
                else => {},
            }
        }
        const rhs_first = i + 3;
        const rhs_last = if (j > rb) rb - 1 else j - 1;
        if (rhs_first > rhs_last) {
            i = j;
            continue;
        }
        const rhs_text = source[starts[rhs_first] .. starts[rhs_last] + tree.tokenSlice(rhs_last).len];
        if (rhsTextLooksAlloc(rhs_text)) {
            try out.append(arena, fname);
        }
        i = j;
    }
    return out.toOwnedSlice(arena);
}

/// True iff `text` contains a substring matching the alloc-pattern
/// vocabulary.  Conservative text match (same shape the old
/// annotations.zig pipeline used).
fn rhsTextLooksAlloc(text: []const u8) bool {
    const patterns = [_][]const u8{
        ".alloc(", ".allocSentinel(", ".allocAdvanced(",
        ".create(", ".dupe(", ".dupeZ(",
        ".allocPrint(", ".allocPrintZ(",
        ".toOwnedSlice(",
    };
    for (patterns) |p| {
        if (std.mem.indexOf(u8, text, p) != null) return true;
    }
    return false;
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn parse(src: [:0]const u8) !Ast {
    return try Ast.parse(testing.allocator, src, .zig);
}

/// Find the first fn_decl in `tree` and infer its summary.  The
/// `proto_buf` parameter MUST outlive the returned summary because
/// fnProtoOne/Simple store params into it — a stack-local buffer
/// would dangle by the time the caller uses the summary.
fn inferFirstFn(tree: *const Ast, proto_buf: *[1]Ast.Node.Index) FnSummary {
    var idx: u32 = 1;
    while (idx < tree.nodes.len) : (idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        const proto = lexer.fnProto(tree, proto_buf, node).?;
        const body = lexer.bodyOf(tree, node).?;
        return inferFromBody(tree, proto, body);
    }
    unreachable;
}

test "infer: noreturn return type sets is_noreturn" {
    var tree = try parse("fn die() noreturn { @panic(\"\"); }");
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(s.is_noreturn);
}

test "infer: body with .alloc() sets allocates" {
    var tree = try parse(
        \\fn f(gpa: std.mem.Allocator) ![]u8 {
        \\    return try gpa.alloc(u8, 16);
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(s.allocates);
    try testing.expect(s.returns == .heap);
}

test "infer: body with .free() sets deallocates" {
    var tree = try parse(
        \\fn f(gpa: std.mem.Allocator, p: []u8) void {
        \\    gpa.free(p);
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(s.deallocates);
}

test "infer: return self.x classifies as borrowed_from(self)" {
    var tree = try parse(
        \\fn text(self: *Foo) []const u8 {
        \\    return self.buf;
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(s.returns == .borrowed_from);
    try testing.expectEqual(@as(u32, 0), s.returns.borrowed_from);
}

test "infer: return try ctx.method() classifies via ctx param" {
    var tree = try parse(
        \\fn wrap(ctx: *Foo) ![]u8 {
        \\    return try ctx.makeBuf();
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(s.returns == .borrowed_from);
    try testing.expectEqual(@as(u32, 0), s.returns.borrowed_from);
}

test "infer: no return statement leaves returns as unknown" {
    var tree = try parse(
        \\fn nothing() void {}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(s.returns == .unknown);
}

test "infer: bare return undefined stays unknown (per design)" {
    var tree = try parse(
        \\fn placeholder() u32 {
        \\    return undefined;
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(s.returns == .unknown);
}

test "infer: nested fns don't leak effects to outer" {
    var tree = try parse(
        \\fn outer() void {
        \\    const inner = struct {
        \\        fn deep(gpa: std.mem.Allocator) ![]u8 {
        \\            return try gpa.alloc(u8, 1);
        \\        }
        \\    };
        \\    _ = inner;
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const s = inferFirstFn(&tree, &buf);
    try testing.expect(!s.allocates);
    try testing.expect(s.returns == .unknown);
}

fn firstFnProtoAndBody(
    tree: *const Ast,
    proto_buf: *[1]Ast.Node.Index,
) struct { Ast.full.FnProto, Ast.Node.Index } {
    var idx: u32 = 1;
    while (idx < tree.nodes.len) : (idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        return .{ lexer.fnProto(tree, proto_buf, node).?, lexer.bodyOf(tree, node).? };
    }
    unreachable;
}

test "inferDirectTakes: gpa.destroy(<param>) returns param index" {
    var tree = try parse(
        \\fn cleanup(gpa: std.mem.Allocator, p: *Foo) void {
        \\    gpa.destroy(p);
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    // inferDirectTakes is callable on its own even though it isn't
    // currently wired into inferFromBody (see the note there).
    try testing.expectEqual(@as(?u32, 1), inferDirectTakes(&tree, pb[0], pb[1]));
}

test "inferDirectTakes: gpa.free(<param>) returns param index" {
    var tree = try parse(
        \\fn drop(gpa: std.mem.Allocator, buf: []u8) void {
        \\    gpa.free(buf);
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    try testing.expectEqual(@as(?u32, 1), inferDirectTakes(&tree, pb[0], pb[1]));
}

test "inferDirectTakes: no .free/.destroy returns null" {
    var tree = try parse(
        \\fn touch(self: *Foo) void {
        \\    _ = self;
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    try testing.expect(inferDirectTakes(&tree, pb[0], pb[1]) == null);
}

test "inferDirectTakes: <param>.deinit() does NOT match (reset-and-resurrect risk)" {
    var tree = try parse(
        \\fn cleanup(self: *Foo) void {
        \\    self.deinit();
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    try testing.expect(inferDirectTakes(&tree, pb[0], pb[1]) == null);
}

test "inferMayFreeFields: detects <param>.<field>.<deallocMethod>()" {
    var tree = try parse(
        \\fn cleanup(self: *Foo, other: *Bar) void {
        \\    self.x.deinit();
        \\    other.y.close();
        \\    self.z.deref();
        \\}
    );
    defer tree.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    const ff = try inferMayFreeFields(arena.allocator(), &tree, pb[0], pb[1]);
    try testing.expectEqual(@as(usize, 3), ff.len);
    try testing.expectEqual(@as(u32, 0), ff[0].param);
    try testing.expectEqualStrings("x", ff[0].field);
    try testing.expectEqual(@as(u32, 1), ff[1].param);
    try testing.expectEqualStrings("y", ff[1].field);
    try testing.expectEqual(@as(u32, 0), ff[2].param);
    try testing.expectEqualStrings("z", ff[2].field);
}

test "inferMayFreeFields: ignores non-deallocating methods" {
    var tree = try parse(
        \\fn touch(self: *Foo) void {
        \\    self.x.append(1);
        \\    self.y.process();
        \\}
    );
    defer tree.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    const ff = try inferMayFreeFields(arena.allocator(), &tree, pb[0], pb[1]);
    try testing.expectEqual(@as(usize, 0), ff.len);
}

test "inferHeapAllocatesSelf: <x>.create(<TypeName>) hits" {
    var tree = try parse(
        \\fn factory(gpa: std.mem.Allocator) !*Foo {
        \\    return try gpa.create(Foo);
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    try testing.expect(inferHeapAllocatesSelf(&tree, pb[1], "Foo"));
    try testing.expect(!inferHeapAllocatesSelf(&tree, pb[1], "Bar"));
    try testing.expect(!inferHeapAllocatesSelf(&tree, pb[1], null));
}

test "inferHeapAllocatesSelf: <x>.create(Self) hits" {
    var tree = try parse(
        \\fn factory(gpa: std.mem.Allocator) !*Foo {
        \\    return try gpa.create(Self);
        \\}
    );
    defer tree.deinit(testing.allocator);
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    try testing.expect(inferHeapAllocatesSelf(&tree, pb[1], "AnyType"));
}

test "inferResultHeapFields: collects alloc-RHS fields from struct-literal return" {
    var tree = try parse(
        \\fn init(gpa: std.mem.Allocator, src: []const u8) !Foo {
        \\    return .{
        \\        .bytes = try gpa.alloc(u8, 16),
        \\        .name = try gpa.dupe(u8, src),
        \\        .count = 0,
        \\    };
        \\}
    );
    defer tree.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    const rhf = try inferResultHeapFields(arena.allocator(), &tree, pb[1]);
    try testing.expectEqual(@as(usize, 2), rhf.len);
    try testing.expectEqualStrings("bytes", rhf[0]);
    try testing.expectEqualStrings("name", rhf[1]);
}

test "inferResultHeapFields: non-constructor body yields empty" {
    var tree = try parse(
        \\fn make() Foo { return .{}; }
    );
    defer tree.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [1]Ast.Node.Index = undefined;
    const pb = firstFnProtoAndBody(&tree, &buf);
    const rhf = try inferResultHeapFields(arena.allocator(), &tree, pb[1]);
    try testing.expectEqual(@as(usize, 0), rhf.len);
}
