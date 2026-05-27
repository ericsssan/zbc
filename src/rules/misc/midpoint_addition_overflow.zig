//! Detects `(a + b) / 2` — the classic binary-search midpoint overflow.
//! If `a` and `b` are both at their maximum values, `a + b` overflows the
//! integer type before the division, producing a wrong or wrapped midpoint.
//! The correct form is `a + (b - a) / 2` (or `left + (right - left) / 2`).
//!
//! Real-world instances:
//!   - ziglang/zig#20029 (std.sort.upperBound): `mid = (right + left) / 2` — overflow
//!     for bounds near `maxInt(usize)`.  Fix: `left + (right - left) / 2`.
//!   - ziglang/zig#18718 (std.sort.lowerBound / equalRange): same pattern.
//!
//! Detection (Tier 1, flat token walk):
//!   Pattern: `( identifier + identifier ) / 2`  — 7 tokens.
//!   Fire at the `(` token.
//!   Also catches `( identifier + identifier ) / 2` when the literal is `number_literal("2")`.
//!   Does NOT fire for `(a + b) / other_var` (not a division by 2) or
//!   `(a + b) / 2` inside a `comptime` expression (compiler catches overflow).

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "midpoint-addition-overflow";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .midpoint_addition_overflow)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    if (tree.tokens.len < 7) return;
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 6 <= last_tok) : (t += 1) {
        // Pattern: ( identifier + identifier ) / 2
        if (tags[t] != .l_paren) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .plus) continue;
        if (tags[t + 3] != .identifier) continue;
        if (tags[t + 4] != .r_paren) continue;
        if (tags[t + 5] != .slash) continue;
        if (tags[t + 6] != .number_literal) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 6), "2")) continue;

        const a = tree.tokenSlice(t + 1);
        const b = tree.tokenSlice(t + 3);
        try report(gpa, problems, tree, t, a, b);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    lparen_tok: Ast.TokenIndex,
    a: []const u8,
    b: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`({s} + {s}) / 2` overflows when `{s} + {s}` exceeds the integer type's maximum; use `{s} + ({s} - {s}) / 2` to compute the midpoint without overflow",
        .{ a, b, a, b, a, b, a },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, lparen_tok),
        .end = Pos.fromTokenEnd(tree, lparen_tok + 6),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "midpoint-addition-overflow: fires on (left + right) / 2" {
    try testing.expectFires(check, R,
        \\fn midpoint(left: usize, right: usize) usize {
        \\    return (left + right) / 2;
        \\}
        \\
    );
}

test "midpoint-addition-overflow: fires on binary search pattern" {
    try testing.expectFires(check, R,
        \\fn binarySearch(items: []const u32, target: u32) ?usize {
        \\    var left: usize = 0;
        \\    var right: usize = items.len;
        \\    while (left < right) {
        \\        const mid = (left + right) / 2;
        \\        if (items[mid] == target) return mid;
        \\        if (items[mid] < target) left = mid + 1 else right = mid;
        \\    }
        \\    return null;
        \\}
        \\
    );
}

test "midpoint-addition-overflow: correct form does not fire" {
    try testing.expectNoFire(check,
        \\fn midpoint(left: usize, right: usize) usize {
        \\    return left + (right - left) / 2;
        \\}
        \\
    );
}

test "midpoint-addition-overflow: division by non-2 does not fire" {
    try testing.expectNoFire(check,
        \\fn third(a: usize, b: usize) usize {
        \\    return (a + b) / 3;
        \\}
        \\
    );
}

test "midpoint-addition-overflow: variable divisor does not fire" {
    try testing.expectNoFire(check,
        \\fn avg(a: usize, b: usize, n: usize) usize {
        \\    return (a + b) / n;
        \\}
        \\
    );
}
