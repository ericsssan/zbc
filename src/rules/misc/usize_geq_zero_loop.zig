//! Detects `while (i >= 0)` and `while (i >= 0 and ...)` conditions where
//! `i` appears to be a loop variable that could be `usize`.  Since `usize`
//! is unsigned, `i >= 0` is always `true`; the loop never terminates via
//! this guard and the subsequent `i -= 1` underflows (panic in Debug,
//! wraparound in ReleaseFast).
//!
//! Real-world instances:
//!   - oven-sh/bun#11491 (glob.zig): `while (i >= 0 and pattern[i] == '\\') : (i -= 1)`
//!   - oven-sh/bun#24561 (hosted_git_info.zig): `pi - 1` access where `pi: usize`
//!     could be 0 due to a missing `> 0` guard.
//!
//! Detection (Tier 1, token walk):
//!   Pattern: `keyword_while l_paren identifier angle_bracket_right_equal number_literal["0"]`
//!   (5 tokens).  Fire at the `>=` operator.
//!   Suppression: none — `usize >= 0` is always a latent bug regardless of
//!   surrounding context.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const tokens = @import("../../ast/tokens.zig");
const testing = @import("../../testing.zig");

const skipNestedFn = tokens.skipNestedFn;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "usize-geq-zero-loop";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .usize_geq_zero_loop)) return;
    _ = cache;
    try tokens.forEachFnBody(gpa, tree, problems, checkBody);
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    if (first + 4 > last) return;

    var t: Ast.TokenIndex = first;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }

        // Pattern: `while ( identifier >= 0`
        //   t+0: keyword_while
        //   t+1: l_paren
        //   t+2: identifier
        //   t+3: angle_bracket_right_equal  (>=)
        //   t+4: number_literal  with text "0"
        if (tags[t] != .keyword_while) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .angle_bracket_right_equal) continue;
        if (tags[t + 4] != .number_literal) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 4), "0")) continue;

        try report(gpa, problems, tree, t + 3, tree.tokenSlice(t + 2));
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    geq_tok: Ast.TokenIndex,
    var_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`while ({s} >= 0)` — if `{s}` is `usize` or any other unsigned type, this condition is always `true` (unsigned values are always ≥ 0), so the loop never exits through this guard and `{s} -= 1` wraps to `maxInt(usize)` (panic in Debug, silent wrap in ReleaseFast); use `while ({s} > 0)` or restructure to avoid underflow",
        .{ var_name, var_name, var_name, var_name },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, geq_tok),
        .end = Pos.fromTokenEnd(tree, geq_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "usize-geq-zero-loop: basic while fires" {
    try testing.expectFires(check, R,
        \\fn scan(s: []const u8) void {
        \\    var i: usize = s.len - 1;
        \\    while (i >= 0) : (i -= 1) {
        \\        _ = s[i];
        \\    }
        \\}
        \\
    );
}

test "usize-geq-zero-loop: while with and condition fires" {
    try testing.expectFires(check, R,
        \\fn scan(s: []const u8) void {
        \\    var i: usize = s.len - 1;
        \\    while (i >= 0 and s[i] != 0) : (i -= 1) {}
        \\}
        \\
    );
}

test "usize-geq-zero-loop: while (i > 0) does not fire" {
    try testing.expectNoFire(check,
        \\fn scan(s: []const u8) void {
        \\    var i: usize = s.len;
        \\    while (i > 0) {
        \\        i -= 1;
        \\        _ = s[i];
        \\    }
        \\}
        \\
    );
}

test "usize-geq-zero-loop: while (i >= 1) does not fire" {
    try testing.expectNoFire(check,
        \\fn scan(s: []const u8, n: usize) void {
        \\    var i: usize = n;
        \\    while (i >= 1) : (i -= 1) {
        \\        _ = s[i - 1];
        \\    }
        \\}
        \\
    );
}

test "usize-geq-zero-loop: for loop does not fire" {
    try testing.expectNoFire(check,
        \\fn scan(s: []const u8) void {
        \\    for (s) |c| {
        \\        _ = c;
        \\    }
        \\}
        \\
    );
}
