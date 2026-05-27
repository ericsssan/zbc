//! Detects `@as(f32, @floatFromInt(expr))` — narrowing an integer to f32.
//!
//! `f32` represents integers exactly only up to 2²⁴ (16,777,216).  For
//! integers larger than that, `@floatFromInt` silently rounds to the
//! nearest representable f32 value.  When the resulting f32 is used in
//! bounds checks, size arithmetic, or offset calculations, the rounding
//! invalidates the check — a value of 33,554,433 rounds to 33,554,432,
//! passing a guard that should have caught it.
//!
//! The correct type is `f64`, which represents integers exactly up to 2⁵³.
//! For cases where f32 is genuinely needed (e.g., GPU vertex buffers),
//! a saturating clamp should precede the cast.
//!
//! Real-world shape: oven-sh/bun#30134 (CSS parser: bounds checks on typed
//! array offsets used `@as(f32, @floatFromInt(...))`, silently rounding
//! large values and bypassing OOB guards).
//!
//! Detection (Tier 1, token walk):
//!   6-token pattern:
//!     t+0: builtin("@as")   t+1: l_paren   t+2: identifier("f32")
//!     t+3: comma            t+4: builtin("@floatFromInt")   t+5: l_paren
//!   Fire at the `@as` builtin token.
//!   Suppression: none (using f32 for integer promotion is almost always
//!   a precision bug in bounds-checking or arithmetic code).

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const tokens = @import("../../ast/tokens.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "f32-narrowing-int-to-float";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .f32_narrowing_int_to_float)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 5 <= last_tok) : (t += 1) {
        // Pattern: @as ( f32 , @floatFromInt (
        if (tags[t] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "@as")) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), "f32")) continue;
        if (tags[t + 3] != .comma) continue;
        if (tags[t + 4] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 4), "@floatFromInt")) continue;
        if (tags[t + 5] != .l_paren) continue;

        try report(gpa, problems, tree, t);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    as_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@as(f32, @floatFromInt(…))` narrows an integer to f32, which only represents integers exactly up to 2²⁴ (16,777,216); larger values are silently rounded, defeating bounds checks and size arithmetic; use `@as(f64, @floatFromInt(…))` for correctness, or clamp first if f32 is genuinely required",
        .{},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, as_tok),
        .end = Pos.fromTokenEnd(tree, as_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "f32-narrowing-int-to-float: basic pattern fires" {
    try testing.expectFires(check, R,
        \\fn checkBounds(offset: usize) f32 {
        \\    return @as(f32, @floatFromInt(offset));
        \\}
        \\
    );
}

test "f32-narrowing-int-to-float: f64 does not fire" {
    try testing.expectNoFire(check,
        \\fn checkBounds(offset: usize, len: usize) bool {
        \\    return @as(f64, @floatFromInt(offset)) < @as(f64, @floatFromInt(len));
        \\}
        \\
    );
}

test "f32-narrowing-int-to-float: non-floatFromInt does not fire" {
    try testing.expectNoFire(check,
        \\fn convert(x: f64) f32 {
        \\    return @as(f32, @floatCast(x));
        \\}
        \\
    );
}
