//! Declarative token-pattern matcher.
//!
//! Rules describe SHAPES instead of writing bespoke token-walk
//! loops.  A Pattern is a sequence of Atoms; matching it against
//! a token position returns a Match (with captures) or null.
//!
//! Combine with scope-aware finders (findInSameScope /
//! findInEnclosingScope) to express the "bind X here, find use
//! of X later" pattern that nearly every rule needs.
//!
//! Example — `const X = try <openMethod>(...)` then later `X.close()`:
//!
//!     const open_call = comptime &[_]Atom{
//!         .{ .tok = .keyword_const },
//!         .{ .capture = 0 },              // X
//!         .{ .tok = .equal },
//!         .{ .opt = &[_]Atom{ .{ .tok = .keyword_try } } },
//!         .{ .tok = .identifier },        // receiver (e.g. dir)
//!         .{ .tok = .period },
//!         .{ .pred = isOpenerMethod },
//!         .paren_args,
//!     };
//!     const close_call = comptime &[_]Atom{
//!         .{ .ref = 0 },                  // X
//!         .{ .tok = .period },
//!         .{ .text = "close" },
//!         .paren_args,
//!     };
//!
//!     for (try findAll(gpa, tree, open_call, body_first, body_last)) |bind| {
//!         const close = findInSameScope(tree, close_call, bind.end + 1, body_last, &bind) orelse continue;
//!         // ...
//!     }

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("lexer.zig");

pub const TokenIndex = Ast.TokenIndex;
pub const TokenTag = lexer.TokenTag;

pub const MAX_CAPTURES: u8 = 8;

/// One atomic match step.
pub const Atom = union(enum) {
    /// Consume one token whose tag equals this.  No text check.
    tok: TokenTag,
    /// Consume one identifier whose text equals this.
    text: []const u8,
    /// Consume one identifier whose text passes this predicate.
    pred: *const fn ([]const u8) bool,
    /// Consume one identifier; record its position in captures[slot].
    capture: u8,
    /// Consume one identifier whose text equals tokenSlice(captures[slot]).
    ref: u8,
    /// Consume one .builtin token whose text equals this (e.g. "@memset").
    builtin: []const u8,
    /// Try to match the nested sequence; if any atom fails, rewind to
    /// before this opt and continue with the next atom.
    opt: []const Atom,
    /// Consume a balanced `(...)`: opens with `(`, skips to matching
    /// `)`, advances past `)`.  Used for "ignore the call args".
    paren_args,
    /// Consume a balanced `[...]`.
    bracket_args,
    /// Consume a balanced `{...}`.
    brace_args,
};

/// Result of matching a Pattern at a position.
pub const Match = struct {
    /// First token of the match (the position passed to matchAt).
    start: TokenIndex,
    /// Last token of the match (inclusive).
    end: TokenIndex,
    /// captures[slot] is the token index of an identifier captured
    /// by `.capture = slot`; null if that slot wasn't filled.
    captures: [MAX_CAPTURES]?TokenIndex = .{null} ** MAX_CAPTURES,

    /// Convenience: text of capture slot N.
    pub fn captureText(self: Match, tree: *const Ast, slot: u8) ?[]const u8 {
        const tok = self.captures[slot] orelse return null;
        return tree.tokenSlice(tok);
    }
};

/// Try to match `atoms` starting at `pos`.  Returns a Match or null.
/// Captures from `inherited`, if non-null, are pre-loaded so `.ref`
/// atoms can reference previously-bound names.
pub fn matchAt(
    tree: *const Ast,
    atoms: []const Atom,
    pos: TokenIndex,
    last: TokenIndex,
    inherited: ?*const Match,
) ?Match {
    var m: Match = .{ .start = pos, .end = pos };
    if (inherited) |i| m.captures = i.captures;
    var t: TokenIndex = pos;
    if (matchSlice(tree, atoms, &t, last, &m.captures)) {
        if (t == pos) return null; // matched zero tokens — reject
        m.end = t - 1;
        return m;
    }
    return null;
}

/// Internal: try to match `atoms` against `t`, advancing `t` on
/// success and writing into `captures`.  Returns false on any atom
/// failure (t is left in an undefined state — caller doesn't reuse).
fn matchSlice(
    tree: *const Ast,
    atoms: []const Atom,
    t: *TokenIndex,
    last: TokenIndex,
    captures: *[MAX_CAPTURES]?TokenIndex,
) bool {
    const tags = tree.tokens.items(.tag);
    for (atoms) |a| {
        if (t.* > last) {
            // Allow opt to absorb end-of-range; other atoms fail.
            switch (a) {
                .opt => {}, // handled below — opt over end is a no-op
                else => return false,
            }
        }
        switch (a) {
            .tok => |want| {
                if (t.* > last or tags[t.*] != want) return false;
                t.* += 1;
            },
            .text => |want| {
                if (t.* > last or tags[t.*] != .identifier) return false;
                if (!std.mem.eql(u8, tree.tokenSlice(t.*), want)) return false;
                t.* += 1;
            },
            .pred => |p| {
                if (t.* > last or tags[t.*] != .identifier) return false;
                if (!p(tree.tokenSlice(t.*))) return false;
                t.* += 1;
            },
            .capture => |slot| {
                if (slot >= MAX_CAPTURES) return false;
                if (t.* > last or tags[t.*] != .identifier) return false;
                captures[slot] = t.*;
                t.* += 1;
            },
            .ref => |slot| {
                if (slot >= MAX_CAPTURES) return false;
                const want_tok = captures[slot] orelse return false;
                if (t.* > last or tags[t.*] != .identifier) return false;
                if (!std.mem.eql(u8, tree.tokenSlice(t.*), tree.tokenSlice(want_tok))) return false;
                t.* += 1;
            },
            .builtin => |want| {
                if (t.* > last or tags[t.*] != .builtin) return false;
                if (!std.mem.eql(u8, tree.tokenSlice(t.*), want)) return false;
                t.* += 1;
            },
            .opt => |sub| {
                // Try to match nested; on failure, restore t and continue.
                const save = t.*;
                const save_caps = captures.*;
                if (!matchSlice(tree, sub, t, last, captures)) {
                    t.* = save;
                    captures.* = save_caps;
                }
            },
            .paren_args => {
                if (t.* > last or tags[t.*] != .l_paren) return false;
                const close = lexer.matchParen(tags, t.*, last) orelse return false;
                t.* = close + 1;
            },
            .bracket_args => {
                if (t.* > last or tags[t.*] != .l_bracket) return false;
                const close = lexer.matchBracket(tags, t.*, last) orelse return false;
                t.* = close + 1;
            },
            .brace_args => {
                if (t.* > last or tags[t.*] != .l_brace) return false;
                const close = lexer.matchBrace(tags, t.*, last) orelse return false;
                t.* = close + 1;
            },
        }
    }
    return true;
}

/// Find ALL non-overlapping matches of `atoms` in `[start, last]`.
/// After each match, scanning resumes at `match.end + 1`.  Does
/// NOT skip nested fns — pass a body range or use `findAllInBody`
/// when you need to confine to one fn's body.
pub fn findAll(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
) ![]Match {
    var out: std.ArrayListUnmanaged(Match) = .empty;
    var t: TokenIndex = start;
    while (t <= last) {
        if (matchAt(tree, atoms, t, last, null)) |m| {
            try out.append(gpa, m);
            t = m.end + 1;
            continue;
        }
        t += 1;
    }
    return out.toOwnedSlice(gpa);
}

/// Find ALL non-overlapping matches of `atoms` in `[start, last]`,
/// SKIPPING nested fn declarations entirely.  Use this when scanning
/// inside a fn body so that inner fn contents aren't double-matched.
/// Does NOT skip defer/errdefer statements — use
/// findAllInBodySkippingDefer if you want both.
pub fn findAllInBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
) ![]Match {
    var out: std.ArrayListUnmanaged(Match) = .empty;
    const tags = tree.tokens.items(.tag);
    var t: TokenIndex = start;
    while (t <= last) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            t = if (t < last) t + 1 else last + 1;
            continue;
        }
        if (matchAt(tree, atoms, t, last, null)) |m| {
            try out.append(gpa, m);
            t = m.end + 1;
            continue;
        }
        t += 1;
    }
    return out.toOwnedSlice(gpa);
}

/// Find ALL non-overlapping matches of `atoms` in `[start, last]`,
/// SKIPPING both nested fn declarations AND defer/errdefer
/// statements.  Use when matches inside deferred code shouldn't
/// count toward the rule (because they fire at a different point
/// in the fn's lifetime).
pub fn findAllInBodySkippingDefer(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
) ![]Match {
    var out: std.ArrayListUnmanaged(Match) = .empty;
    const tags = tree.tokens.items(.tag);
    var t: TokenIndex = start;
    while (t <= last) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            t = if (t < last) t + 1 else last + 1;
            continue;
        }
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            const end = lexer.skipDeferStmt(tags, t, last) orelse {
                t = last + 1;
                continue;
            };
            t = end + 1;
            continue;
        }
        if (matchAt(tree, atoms, t, last, null)) |m| {
            try out.append(gpa, m);
            t = m.end + 1;
            continue;
        }
        t += 1;
    }
    return out.toOwnedSlice(gpa);
}

/// Find FIRST match of `atoms` at the SAME LEXICAL BLOCK DEPTH as
/// `start`.  Skips nested `{...}` blocks entirely (their contents
/// are deeper-scope) and `defer`/`errdefer` statements (deferred,
/// not inline).  Stops at the enclosing scope's `}`.
///
/// `bound` (if non-null) provides captures that `.ref` atoms can
/// resolve against — for "find X.close() where X was the binding".
pub fn findInSameScope(
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
    bound: ?*const Match,
) ?Match {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: TokenIndex = start;
    while (t <= last) {
        if (tags[t] == .l_brace) {
            t = (lexer.matchBrace(tags, t, last) orelse return null) + 1;
            continue;
        }
        if (tags[t] == .r_brace) return null;
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = (lexer.skipDeferStmt(tags, t, last) orelse return null) + 1;
            continue;
        }
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            t = if (t < last) t + 1 else last + 1;
            continue;
        }
        if (matchAt(tree, atoms, t, last, bound)) |m| return m;
        t += 1;
    }
    return null;
}

/// Find FIRST match of `atoms` within the ENCLOSING `{...}` scope
/// of `start`.  Allows nested blocks inside the scope (descends
/// into them).  Stops at the enclosing scope's `}`.
///
/// Use this for "find any USE of X anywhere in the rest of the
/// enclosing scope" — vs findInSameScope which restricts to same
/// block depth.
pub fn findInEnclosingScope(
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
    bound: ?*const Match,
) ?Match {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var depth: i32 = 0;
    var t: TokenIndex = start;
    while (t <= last) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => {
                if (depth == 0) return null;
                depth -= 1;
            },
            else => {},
        }
        if (matchAt(tree, atoms, t, last, bound)) |m| return m;
        t += 1;
    }
    return null;
}

/// True iff `atoms` matches at position `start` AND consumes the
/// range exactly through `last`.  Useful for "is the RHS of this
/// binding EXACTLY this shape (no trailing chain)?"
pub fn matchExact(
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
    bound: ?*const Match,
) ?Match {
    const m = matchAt(tree, atoms, start, last, bound) orelse return null;
    if (m.end != last) return null;
    return m;
}

/// True iff `atoms` matches at position `start` (don't care if the
/// match consumes the whole range — there can be trailing tokens).
pub fn matchPrefix(
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
    bound: ?*const Match,
) ?Match {
    return matchAt(tree, atoms, start, last, bound);
}

/// True iff `atoms` matches ANYWHERE in `[start, last]` at SAME
/// block depth as start (with same skipping rules as
/// findInSameScope).  Used for "is there a defer/errdefer doing X
/// somewhere in this scope".
pub fn anyMatchInSameScope(
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
    bound: ?*const Match,
) bool {
    return findInSameScope(tree, atoms, start, last, bound) != null;
}

/// True iff `atoms` matches anywhere in `[start, last]`, INCLUDING
/// inside defer/errdefer (which findInSameScope skips).  Used for
/// "is there ANY .release() in this fn body, even guarded by defer".
pub fn anyMatchAnywhere(
    tree: *const Ast,
    atoms: []const Atom,
    start: TokenIndex,
    last: TokenIndex,
    bound: ?*const Match,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > last) return false;
    var t: TokenIndex = start;
    while (t <= last) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            t = if (t < last) t + 1 else last + 1;
            continue;
        }
        if (matchAt(tree, atoms, t, last, bound)) |_| return true;
        t += 1;
    }
    return false;
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn parseTokens(src: [:0]const u8) !Ast {
    return try Ast.parse(testing.allocator, src, .zig);
}

fn findIdent(tree: *const Ast, name: []const u8) TokenIndex {
    const tags = tree.tokens.items(.tag);
    var i: TokenIndex = 0;
    while (i < tree.tokens.len) : (i += 1) {
        if (tags[i] == .identifier and std.mem.eql(u8, tree.tokenSlice(i), name)) return i;
    }
    unreachable;
}

test "matchAt: simple tag sequence" {
    var tree = try parseTokens("fn f() void { const x = 1; }");
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const atoms = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .tok = .identifier },
        .{ .tok = .equal },
        .{ .tok = .number_literal },
    };
    const x_pos = findIdent(&tree, "x");
    const m = matchAt(&tree, atoms, x_pos - 1, last, null).?;
    try testing.expectEqual(@as(TokenIndex, x_pos - 1), m.start);
    try testing.expectEqual(@as(TokenIndex, x_pos + 2), m.end);
}

test "matchAt: capture and ref" {
    var tree = try parseTokens("fn f() void { const x = y; const z = x; }");
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    // Pattern: `const $0 = ...`
    const bind = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .capture = 0 },
        .{ .tok = .equal },
    };
    const x_pos = findIdent(&tree, "x");
    const b = matchAt(&tree, bind, x_pos - 1, last, null).?;
    try testing.expectEqualStrings("x", b.captureText(&tree, 0).?);

    // Pattern: `$0` (ref) — find a use of x.
    const use = &[_]Atom{.{ .ref = 0 }};
    const use_m = findInEnclosingScope(&tree, use, b.end + 1, last, &b).?;
    try testing.expectEqualStrings("x", tree.tokenSlice(use_m.start));
}

test "matchAt: predicate" {
    var tree = try parseTokens("fn f() void { dir.openFile(); }");
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const isOpener = struct {
        fn p(name: []const u8) bool {
            return std.mem.eql(u8, name, "openFile") or std.mem.eql(u8, name, "createFile");
        }
    }.p;
    const atoms = &[_]Atom{
        .{ .tok = .identifier },
        .{ .tok = .period },
        .{ .pred = isOpener },
        .paren_args,
    };
    const dir_pos = findIdent(&tree, "dir");
    const m = matchAt(&tree, atoms, dir_pos, last, null).?;
    try testing.expectEqual(@as(TokenIndex, dir_pos), m.start);
}

test "matchAt: opt" {
    var tree = try parseTokens("fn f() void { const x = try foo(); const y = bar(); }");
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    // Pattern: `const $0 = [try] <ident>()`
    const atoms = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .capture = 0 },
        .{ .tok = .equal },
        .{ .opt = &[_]Atom{.{ .tok = .keyword_try }} },
        .{ .tok = .identifier },
        .paren_args,
    };
    const matches = try findAll(testing.allocator, &tree, atoms, 0, last);
    defer testing.allocator.free(matches);
    try testing.expectEqual(@as(usize, 2), matches.len);
    try testing.expectEqualStrings("x", matches[0].captureText(&tree, 0).?);
    try testing.expectEqualStrings("y", matches[1].captureText(&tree, 0).?);
}

test "matchAt: builtin" {
    var tree = try parseTokens("fn f() void { @memset(buf, 0); }");
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const atoms = &[_]Atom{
        .{ .builtin = "@memset" },
        .paren_args,
    };
    const matches = try findAll(testing.allocator, &tree, atoms, 0, last);
    defer testing.allocator.free(matches);
    try testing.expectEqual(@as(usize, 1), matches.len);
}

test "matchAt: paren_args skips balanced parens" {
    var tree = try parseTokens("fn f() void { foo(bar(1, 2), 3); }");
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const atoms = &[_]Atom{
        .{ .text = "foo" },
        .paren_args,
        .{ .tok = .semicolon },
    };
    const matches = try findAll(testing.allocator, &tree, atoms, 0, last);
    defer testing.allocator.free(matches);
    try testing.expectEqual(@as(usize, 1), matches.len);
}

test "findInSameScope: skips nested blocks" {
    var tree = try parseTokens(
        \\fn f() void {
        \\    const x = open();
        \\    { x.close(); }
        \\}
    );
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const bind = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .capture = 0 },
        .{ .tok = .equal },
        .{ .text = "open" },
        .paren_args,
    };
    const close = &[_]Atom{
        .{ .ref = 0 },
        .{ .tok = .period },
        .{ .text = "close" },
        .paren_args,
    };
    const matches = try findAll(testing.allocator, &tree, bind, 0, last);
    defer testing.allocator.free(matches);
    const b = matches[0];
    // The close is in a nested block — same-scope find should miss it.
    const found = findInSameScope(&tree, close, b.end + 1, last, &b);
    try testing.expect(found == null);
}

test "findInSameScope: skips defer" {
    var tree = try parseTokens(
        \\fn f() void {
        \\    const x = open();
        \\    defer x.close();
        \\}
    );
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const bind = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .capture = 0 },
        .{ .tok = .equal },
        .{ .text = "open" },
        .paren_args,
    };
    const close = &[_]Atom{
        .{ .ref = 0 },
        .{ .tok = .period },
        .{ .text = "close" },
        .paren_args,
    };
    const matches = try findAll(testing.allocator, &tree, bind, 0, last);
    defer testing.allocator.free(matches);
    const b = matches[0];
    const found = findInSameScope(&tree, close, b.end + 1, last, &b);
    try testing.expect(found == null);
}

test "findInSameScope: inline close hits" {
    var tree = try parseTokens(
        \\fn f() void {
        \\    const x = open();
        \\    x.close();
        \\}
    );
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const bind = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .capture = 0 },
        .{ .tok = .equal },
        .{ .text = "open" },
        .paren_args,
    };
    const close = &[_]Atom{
        .{ .ref = 0 },
        .{ .tok = .period },
        .{ .text = "close" },
        .paren_args,
    };
    const matches = try findAll(testing.allocator, &tree, bind, 0, last);
    defer testing.allocator.free(matches);
    const b = matches[0];
    const found = findInSameScope(&tree, close, b.end + 1, last, &b);
    try testing.expect(found != null);
}

test "findInEnclosingScope: descends into nested blocks" {
    var tree = try parseTokens(
        \\fn f() void {
        \\    const x = open();
        \\    { _ = x; }
        \\}
    );
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const bind = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .capture = 0 },
        .{ .tok = .equal },
        .{ .text = "open" },
        .paren_args,
    };
    const matches = try findAll(testing.allocator, &tree, bind, 0, last);
    defer testing.allocator.free(matches);
    const b = matches[0];
    const use = &[_]Atom{.{ .ref = 0 }};
    const found = findInEnclosingScope(&tree, use, b.end + 1, last, &b);
    try testing.expect(found != null);
}

test "findInEnclosingScope: stops at scope close" {
    var tree = try parseTokens(
        \\fn f() void {
        \\    { const x = open(); }
        \\    _ = x;
        \\}
    );
    defer tree.deinit(testing.allocator);
    const last: TokenIndex = @intCast(tree.tokens.len - 1);
    const bind = &[_]Atom{
        .{ .tok = .keyword_const },
        .{ .capture = 0 },
        .{ .tok = .equal },
        .{ .text = "open" },
        .paren_args,
    };
    const matches = try findAll(testing.allocator, &tree, bind, 0, last);
    defer testing.allocator.free(matches);
    const b = matches[0];
    const use = &[_]Atom{.{ .ref = 0 }};
    const found = findInEnclosingScope(&tree, use, b.end + 1, last, &b);
    // The use of `x` in the sibling scope shouldn't be reachable
    // from inside the brace block where x was bound.
    try testing.expect(found == null);
}
