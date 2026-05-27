//! Detects `@intCast(-VAR)` — casting a negated runtime integer without
//! guarding against the minimum-value overflow.  If `VAR` is a signed integer
//! and holds `minInt(T)`, the negation wraps in ReleaseFast (silently produces
//! the wrong value) and panics in Debug/ReleaseSafe.  The correct form is
//! `@abs(VAR)` for the common "take the magnitude" pattern, or an explicit
//! range check before negating.
//!
//! Real-world instance:
//!   - ziglang/zig#23318 (fmtDurationSigned): `@as(u64, @intCast(-ns))` where
//!     `ns: i64` — if `ns == minInt(i64)`, negation overflows.  Fix: `@abs(ns)`.
//!
//! Detection (Tier 1, flat token walk):
//!   Pattern: `@intCast ( - identifier )` — 5 tokens.
//!   Fire at the `@intCast` builtin token.
//!   Does not fire for `@intCast(-1)` (integer literal — comptime-checked).

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "intcast-of-negated-signed";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .intcast_of_negated_signed)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    if (tree.tokens.len < 5) return;
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 4 <= last_tok) : (t += 1) {
        // Pattern: @intCast ( - identifier )
        if (tags[t] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "@intCast")) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .minus) continue;
        if (tags[t + 3] != .identifier) continue;
        if (tags[t + 4] != .r_paren) continue;

        try report(gpa, problems, tree, t);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    intcast_tok: Ast.TokenIndex,
) !void {
    const name = tree.tokenSlice(intcast_tok + 3);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@intCast(-{s})` — if `{s}` is a signed integer at its minimum value, `-{s}` overflows before the cast; use `@abs({s})` to safely get the magnitude, or guard with a range check",
        .{ name, name, name, name },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, intcast_tok),
        .end = Pos.fromTokenEnd(tree, intcast_tok + 4),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "intcast-of-negated-signed: fires on @intCast(-var)" {
    try testing.expectFires(check, R,
        \\fn formatDuration(ns: i64) u64 {
        \\    return @as(u64, @intCast(-ns));
        \\}
        \\
    );
}

test "intcast-of-negated-signed: fires on direct @intCast(-x)" {
    try testing.expectFires(check, R,
        \\fn negate(x: i32) u32 {
        \\    return @intCast(-x);
        \\}
        \\
    );
}

test "intcast-of-negated-signed: integer literal does not fire" {
    try testing.expectNoFire(check,
        \\fn negative() i32 {
        \\    return @intCast(-1);
        \\}
        \\
    );
}

test "intcast-of-negated-signed: intCast without negation does not fire" {
    try testing.expectNoFire(check,
        \\fn cast(x: i64) u32 {
        \\    return @intCast(x);
        \\}
        \\
    );
}

test "intcast-of-negated-signed: @abs is the correct form, does not fire" {
    try testing.expectNoFire(check,
        \\fn magnitude(x: i64) u64 {
        \\    return @abs(x);
        \\}
        \\
    );
}
