//! Detects `x < A and x > B` — a range validation that uses `and` instead
//! of `or`, making the guard permanently dead.
//!
//! No value can be simultaneously less than A and greater than B (when A ≤ B),
//! so the `if` body is unreachable.  The correct out-of-range check is
//! `x < A or x > B`.  Note: `x > A and x < B` is the valid *in-range* check
//! and is NOT flagged by this rule.
//!
//! Real-world shape: oven-sh/bun#25905 (S3 credentials validation)
//!   Three adjacent copy-paste occurrences in `s3/credentials.zig`:
//!     pageSize < MIN and pageSize > MAX
//!     partSize < MIN and partSize > MAX
//!     retry   < 0   and retry   > 255
//!   All silently never threw the intended RangeError.
//!
//! Detection (Tier 1, token walk):
//!   Anchor on `identifier(X) angle_bracket_left` (t, t+1).
//!   Scan forward up to 20 tokens for `keyword_and`.
//!   After `keyword_and`, check `identifier(X) angle_bracket_right` appears
//!   at positions +1 and +2 relative to `keyword_and`.
//!   Fire at the `identifier(X)` anchor token.
//!
//!   Suppression: the reversed form `x > A and x < B` (valid in-range check)
//!   is NOT flagged — only the `< … and … >` order fires.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "impossible-range-and";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .impossible_range_and)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 3 <= last_tok) : (t += 1) {
        // Anchor: identifier(X) < ...
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .angle_bracket_left) continue;

        const x_name = tree.tokenSlice(t);

        // Scan forward (capped) for `and`.
        const scan_end = @min(last_tok, t + 20);
        var u: Ast.TokenIndex = t + 2;
        while (u + 2 <= scan_end) : (u += 1) {
            if (tags[u] != .keyword_and) continue;
            // After `and`: identifier(X) > ...
            if (tags[u + 1] != .identifier) continue;
            if (!std.mem.eql(u8, tree.tokenSlice(u + 1), x_name)) continue;
            if (tags[u + 2] != .angle_bracket_right) continue;

            try report(gpa, problems, tree, t, x_name);
            break;
        }
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    anchor_tok: Ast.TokenIndex,
    x_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s} < … and {s} > …` is an impossible range: no value can be simultaneously less than the lower bound and greater than the upper bound — the guard is permanently dead; use `or` instead of `and` for an out-of-range check",
        .{ x_name, x_name },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, anchor_tok),
        .end = Pos.fromTokenEnd(tree, anchor_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "impossible-range-and: simple literal fires" {
    try testing.expectFires(check, R,
        \\fn validate(retry: i64) bool {
        \\    return retry < 0 and retry > 255;
        \\}
        \\
    );
}

test "impossible-range-and: qualified constant fires" {
    try testing.expectFires(check, R,
        \\fn validate(pageSize: i64) bool {
        \\    return pageSize < Options.MIN and pageSize > Options.MAX;
        \\}
        \\
    );
}

test "impossible-range-and: or form does not fire" {
    try testing.expectNoFire(check,
        \\fn validate(retry: i64) bool {
        \\    return retry < 0 or retry > 255;
        \\}
        \\
    );
}

test "impossible-range-and: valid in-range check does not fire" {
    try testing.expectNoFire(check,
        \\fn inRange(x: i64) bool {
        \\    return x > 0 and x < 100;
        \\}
        \\
    );
}

test "impossible-range-and: different variables do not fire" {
    try testing.expectNoFire(check,
        \\fn check(a: i64, b: i64) bool {
        \\    return a < 0 and b > 255;
        \\}
        \\
    );
}
