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
//!   Suppression: none — `.next().?` is never safe on user-supplied input.

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

        try report(gpa, problems, tree, t + 1);
    }
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
