//! Scope-aware iteration primitives.
//!
//! Three patterns recurred across every precision-tightened
//! pattern detector:
//!   1. "Find a use of <name> in the binding's enclosing scope"
//!      — bounded by the enclosing `}`, allowing nested blocks
//!      inside the scope but stopping when we'd cross out of it.
//!      (Sibling scopes shouldn't trigger via shadowed names.)
//!   2. "Find a call to <recv>.<method>(...) at the SAME lexical
//!      block depth as a binding" — skip nested blocks (catch/if/
//!      loop bodies might not execute) and skip defer/errdefer
//!      (deferred, not inline).
//!   3. "Walk the body collecting matches, skipping nested fns."
//!
//! These three are encoded as three orthogonal iterators below.

const std = @import("std");
const Ast = std.zig.Ast;
const lexer = @import("lexer.zig");

const TokenIndex = lexer.TokenIndex;
const TokenTag = lexer.TokenTag;

/// Find the first identifier whose text equals `name` in the
/// binding's enclosing scope.  Walks forward from `start`; allows
/// the use to be inside nested blocks within the binding's scope
/// (`try map.put(...); for (...) p.* += 1;`).  Stops at the
/// enclosing scope's closing `}` — same-name identifiers in
/// sibling scopes (shadowed loop captures, etc.) don't match.
pub fn findIdentUseInEnclosingScope(
    tree: *const Ast,
    start: TokenIndex,
    last: TokenIndex,
    name: []const u8,
) ?TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var depth: u32 = 0;
    var t: TokenIndex = start;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => if (depth == 0) return null else {
                depth -= 1;
            },
            .identifier => if (std.mem.eql(u8, tree.tokenSlice(t), name)) return t,
            else => {},
        }
    }
    return null;
}

/// Find the first `<recv>.<method>(` call at the SAME lexical
/// block depth as `start`, where `method` passes `methodPred`.
/// Skips nested `{...}` blocks entirely (deeper-scope mutates
/// don't always execute) and `defer`/`errdefer` statements
/// (deferred, not inline).  Stops at the enclosing scope's `}`.
pub fn findReceiverCallSameDepth(
    tree: *const Ast,
    start: TokenIndex,
    last: TokenIndex,
    recv: []const u8,
    methodPred: *const fn ([]const u8) bool,
) ?TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: TokenIndex = start;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = lexer.matchBrace(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] == .r_brace) return null;
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = lexer.skipDeferStmt(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), recv)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        if (methodPred(tree.tokenSlice(t + 2))) return t + 2;
    }
    return null;
}

/// Iterator state for walking a fn body — handles skipping nested
/// fns and (optionally) defer/errdefer statements.  Caller manually
/// advances; this just provides the "skip these" helpers.
///
/// Usage:
/// ```zig
/// var walk = BodyWalk.init(tags, first, last);
/// while (walk.t + N <= last) : (walk.t += 1) {
///     if (walk.atNestedFn()) { walk.skipNestedFn(); continue; }
///     if (walk.atDeferKeyword()) { walk.skipDeferStmt(); continue; }
///     // ... rule logic ...
/// }
/// ```
pub const BodyWalk = struct {
    tags: []const TokenTag,
    last: TokenIndex,
    t: TokenIndex,

    pub fn init(tags: []const TokenTag, first: TokenIndex, last: TokenIndex) BodyWalk {
        return .{ .tags = tags, .last = last, .t = first };
    }

    pub fn atNestedFn(self: BodyWalk) bool {
        return self.tags[self.t] == .keyword_fn;
    }

    /// Advance past a nested fn (proto + body).  Caller should
    /// `continue` after.
    pub fn skipNestedFn(self: *BodyWalk) void {
        self.t = lexer.skipNestedFn(self.tags, self.t, self.last);
    }

    pub fn atDeferKeyword(self: BodyWalk) bool {
        return self.tags[self.t] == .keyword_defer or self.tags[self.t] == .keyword_errdefer;
    }

    /// Advance past a defer/errdefer statement (inline or block).
    /// Caller should `continue` after.
    pub fn skipDeferStmt(self: *BodyWalk) void {
        if (lexer.skipDeferStmt(self.tags, self.t, self.last)) |end| {
            self.t = end;
        } else {
            self.t = self.last;
        }
    }
};

// ── Tests ──────────────────────────────────────────────────

test "findIdentUseInEnclosingScope stops at enclosing }" {
    const src: [:0]const u8 =
        \\fn f() void {
        \\    { const entry = 1; _ = entry; }
        \\    for (0..1) |entry| { _ = entry; }
        \\}
    ;
    var tree = try Ast.parse(std.testing.allocator, src, .zig);
    defer tree.deinit(std.testing.allocator);
    const tags = tree.tokens.items(.tag);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    // Find first `const entry = 1;` binding token.
    var t: TokenIndex = 0;
    while (t <= last) : (t += 1) {
        if (tags[t] == .keyword_const) break;
    }
    // Skip `const`, find `entry` (the bound name).
    t += 1;
    // After the binding's `;`, scan for `entry` use.
    var sc: TokenIndex = t;
    while (sc <= last and tags[sc] != .semicolon) : (sc += 1) {}
    // Use within the same `{...}` block must be found; the
    // `entry` in the sibling `for` block must NOT match.
    const use = findIdentUseInEnclosingScope(&tree, sc + 1, last, "entry").?;
    // The use should be the `_ = entry;` IN THE SAME BLOCK
    // (before the inner `}`), not the for-loop one.
    // Verify by checking the token is followed by `;` then `}`.
    try std.testing.expectEqual(TokenTag.semicolon, tags[use + 1]);
    try std.testing.expectEqual(TokenTag.r_brace, tags[use + 2]);
}
