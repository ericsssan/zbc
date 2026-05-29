//! Detects `.next().?` — a forced unwrap of an iterator's optional result.
//!
//! Standard Zig iterators return `?T`: `null` signals exhaustion.  Calling
//! `.next().?` asserts at runtime that the iterator has a remaining element.
//! When the iterator is already exhausted (e.g. the caller passed fewer items
//! than the code expects), this panics in debug/safe builds and invokes UB in
//! ReleaseFast.
//!
//! The safe idiom is `iter.next() orelse <handle-end>` or the `while`-loop
//! form `while (iter.next()) |val| { … }`.
//!
//! Real-world shapes:
//!   oven-sh/bun#27415 — `seq` builtin called `.next().?` after consuming all
//!     flags; when only flags were provided (no numeric args) the iterator was
//!     already empty → panic.
//!   oven-sh/bun#27316 — `cmds_array.next().?` on a JS-supplied argument list;
//!     empty array caused unconditional panic.
//!
//! Detection (Tier 1, token walk):
//!   6-token pattern:
//!     t+0: period   t+1: identifier("next")   t+2: l_paren
//!     t+3: r_paren  t+4: period               t+5: question_mark
//!   Fire at the `identifier("next")` token (t+1).
//!
//!   Suppression: findings inside a `test { … }` declaration body are
//!   suppressed.  Test code force-unwraps iterators over hard-coded, known
//!   inputs as a deliberate assertion; a panic there is a test failure, not a
//!   production crash.  This rule targets production input-handling code where
//!   the iterator may be empty at runtime.  (Token-level `keyword_test`
//!   brace-matching — see `collectTestRanges`.)

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "forced-unwrap-iterator-next";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .forced_unwrap_iterator_next)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var test_ranges: std.ArrayListUnmanaged(Range) = .empty;
    defer test_ranges.deinit(gpa);
    try collectTestRanges(gpa, tags, &test_ranges);

    var t: Ast.TokenIndex = 0;
    while (t + 5 <= last_tok) : (t += 1) {
        // Pattern: . next ( ) . ?
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 1), "next")) continue;
        if (tags[t + 2] != .l_paren) continue;
        if (tags[t + 3] != .r_paren) continue;
        if (tags[t + 4] != .period) continue;
        if (tags[t + 5] != .question_mark) continue;

        if (isInTestRange(test_ranges.items, t + 1)) continue;

        try report(gpa, problems, tree, t + 1);
    }
}

/// Token span of a `test { … }` declaration, from the `keyword_test` token
/// through its body's closing `r_brace` (inclusive).
const Range = struct { start: Ast.TokenIndex, end: Ast.TokenIndex };

/// Collects the token range of every `test` declaration in the file (top-level
/// or container-nested).  Zig grammar:
///   `KEYWORD_test (STRINGLITERAL / IDENTIFIER)? Block`
/// so the first `l_brace` after `keyword_test` opens the body; we brace-match
/// from there to find the closing `r_brace`.  Ranges are pairwise disjoint
/// (tests cannot nest), so a linear containment check suffices.
fn collectTestRanges(
    gpa: std.mem.Allocator,
    tags: []const std.zig.Token.Tag,
    out: *std.ArrayListUnmanaged(Range),
) !void {
    const n: u32 = @intCast(tags.len);
    var i: Ast.TokenIndex = 0;
    while (i < n) : (i += 1) {
        if (tags[i] != .keyword_test) continue;

        // Find the body's opening `l_brace` (skipping an optional name token).
        var j = i + 1;
        while (j < n and tags[j] != .l_brace) : (j += 1) {
            // Defensive: a well-formed test header has no `;`/`}` before `{`.
            if (tags[j] == .semicolon or tags[j] == .r_brace) break;
        }
        if (j >= n or tags[j] != .l_brace) continue;

        // Brace-match forward from the opening brace.
        var depth: u32 = 0;
        var k = j;
        while (k < n) : (k += 1) {
            if (tags[k] == .l_brace) {
                depth += 1;
            } else if (tags[k] == .r_brace) {
                depth -= 1;
                if (depth == 0) break;
            }
        }
        if (k >= n) break; // unbalanced — only possible on a malformed tree

        try out.append(gpa, .{ .start = i, .end = k });
        i = k; // resume past this test body
    }
}

/// True when `tok` falls within any collected `test { … }` range.
fn isInTestRange(ranges: []const Range, tok: Ast.TokenIndex) bool {
    for (ranges) |r| {
        if (tok >= r.start and tok <= r.end) return true;
    }
    return false;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    next_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`.next().?` force-unwraps the iterator result — if the iterator is exhausted, this panics (debug/safe) or invokes undefined behaviour (ReleaseFast); use `.next() orelse <handler>` or the `while (iter.next()) |val|` loop form instead",
        .{},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, next_tok),
        .end = Pos.fromTokenEnd(tree, next_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "forced-unwrap-iterator-next: basic fires" {
    try testing.expectFires(check, R,
        \\fn readFirst(iter: anytype) u32 {
        \\    return iter.next().?;
        \\}
        \\
    );
}

test "forced-unwrap-iterator-next: orelse does not fire" {
    try testing.expectNoFire(check,
        \\fn readFirst(iter: anytype) ?u32 {
        \\    return iter.next() orelse null;
        \\}
        \\
    );
}

test "forced-unwrap-iterator-next: while loop does not fire" {
    try testing.expectNoFire(check,
        \\fn processAll(iter: anytype) void {
        \\    while (iter.next()) |val| {
        \\        _ = val;
        \\    }
        \\}
        \\
    );
}

test "forced-unwrap-iterator-next: next with arg does not fire" {
    try testing.expectNoFire(check,
        \\fn readFirst(iter: anytype) u32 {
        \\    return iter.next(1);
        \\}
        \\
    );
}

// ── Test-block suppression ──────────────────────────────────

test "forced-unwrap-iterator-next: suppressed inside named test block" {
    try testing.expectNoFire(check,
        \\test "iterates" {
        \\    var it = makeIter();
        \\    const first = it.next().?;
        \\    _ = first;
        \\}
        \\
    );
}

test "forced-unwrap-iterator-next: suppressed inside anonymous test block" {
    try testing.expectNoFire(check,
        \\test {
        \\    var it = makeIter();
        \\    _ = it.next().?;
        \\}
        \\
    );
}

test "forced-unwrap-iterator-next: suppressed inside nested braces of a test" {
    try testing.expectNoFire(check,
        \\test "nested" {
        \\    {
        \\        var it = makeIter();
        \\        _ = it.next().?;
        \\    }
        \\}
        \\
    );
}

test "forced-unwrap-iterator-next: still fires in fn after a test block" {
    try testing.expectFires(check, R,
        \\test "setup" {
        \\    var it = makeIter();
        \\    _ = it.next().?;
        \\}
        \\fn parse(iter: anytype) u32 {
        \\    return iter.next().?;
        \\}
        \\
    );
}

test "forced-unwrap-iterator-next: still fires in fn before a test block" {
    try testing.expectFires(check, R,
        \\fn parse(iter: anytype) u32 {
        \\    return iter.next().?;
        \\}
        \\test "after" {
        \\    var it = makeIter();
        \\    _ = it.next().?;
        \\}
        \\
    );
}
