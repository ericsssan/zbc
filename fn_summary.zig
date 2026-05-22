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
};

/// Infer a summary for `body`.  Conservative: when unclear, returns
/// `.unknown` / null / false — never guesses.  `proto` carries the
/// param list so `borrowed_from` can resolve to a param index.
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
