//! Detects array subscript expressions of the form `buf[idx - 1]` where the
//! `idx - 1` subtraction is not guarded against `idx == 0`.  When `idx` is
//! `usize` and equals zero, `idx - 1` wraps to `maxInt(usize)` —
//! an OOB trap in Debug/Safe and a silent arbitrary-memory read in
//! ReleaseFast.
//!
//! Real-world instances:
//!   - oven-sh/bun#24561 (hosted_git_info.zig): `npa_str[pi - 1]` where `pi`
//!     optional payload could be 0; fix added `pi == 0 or` guard.
//!   - oven-sh/bun#28487 (braces.zig): `self.items[self.current - 1]` when
//!     `self.current` could be 0; fix added `if (self.current > 0)` guard.
//!   - ziglang/zig#26057 (ArgIteratorWasi): `self.args[self.args.len - 1]`
//!     panics when `self.args.len == 0`; `0 - 1` wraps to `maxInt(usize)`.
//!
//! Detection (Tier 1, token walk):
//!   Form A: `[ identifier - 1 ]`                          (5 tokens)
//!   Form B: `[ identifier . identifier - 1 ]`             (7 tokens)
//!   Form C: `[ identifier . identifier . len - 1 ]`       (9 tokens)
//!   Fire at the `l_bracket` token.
//!   Suppression: none at the token level — any `buf[x - 1]` without a
//!   statically visible guard is suspect.

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
const R = "index-minus-one-without-zero-guard";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .index_minus_one_without_zero_guard)) return;
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

        if (tags[t] != .l_bracket) continue;

        // Form A: `[ identifier - 1 ]`
        //   t+0: l_bracket
        //   t+1: identifier
        //   t+2: minus
        //   t+3: number_literal "1"
        //   t+4: r_bracket
        if (tags[t + 1] == .identifier and
            tags[t + 2] == .minus and
            tags[t + 3] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(t + 3), "1") and
            tags[t + 4] == .r_bracket)
        {
            const idx_name = tree.tokenSlice(t + 1);
            try report(gpa, problems, tree, t, idx_name);
            continue;
        }

        // Form B: `[ identifier . identifier - 1 ]`
        //   t+0: l_bracket
        //   t+1: identifier
        //   t+2: period
        //   t+3: identifier
        //   t+4: minus
        //   t+5: number_literal "1"
        //   t+6: r_bracket
        if (t + 6 <= last and
            tags[t + 1] == .identifier and
            tags[t + 2] == .period and
            tags[t + 3] == .identifier and
            tags[t + 4] == .minus and
            tags[t + 5] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(t + 5), "1") and
            tags[t + 6] == .r_bracket)
        {
            const idx_name = tree.tokenSlice(t + 3);
            try report(gpa, problems, tree, t, idx_name);
            continue;
        }

        // Form C: `[ identifier . identifier . len - 1 ]`
        //   t+0: l_bracket
        //   t+1: identifier (recv)
        //   t+2: period
        //   t+3: identifier (field)
        //   t+4: period
        //   t+5: identifier "len"
        //   t+6: minus
        //   t+7: number_literal "1"
        //   t+8: r_bracket
        if (t + 8 <= last and
            tags[t + 1] == .identifier and
            tags[t + 2] == .period and
            tags[t + 3] == .identifier and
            tags[t + 4] == .period and
            tags[t + 5] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t + 5), "len") and
            tags[t + 6] == .minus and
            tags[t + 7] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(t + 7), "1") and
            tags[t + 8] == .r_bracket)
        {
            const idx_name = tree.tokenSlice(t + 3);
            try reportC(gpa, problems, tree, t,
                tree.tokenSlice(t + 1), idx_name);
            continue;
        }
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    lb_tok: Ast.TokenIndex,
    idx_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`[{s} - 1]` — if `{s}` is `usize` (or any unsigned type) and equals `0`, the subtraction wraps to `maxInt(usize)`, producing an OOB panic (Debug/Safe) or silent arbitrary-memory read (ReleaseFast); add a `{s} > 0` (or `{s} != 0`) guard before this expression",
        .{ idx_name, idx_name, idx_name, idx_name },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, lb_tok),
        .end = Pos.fromTokenEnd(tree, lb_tok + 4),
        .message = msg,
    });
}

fn reportC(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    lb_tok: Ast.TokenIndex,
    recv: []const u8,
    field: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`[{s}.{s}.len - 1]` — if `{s}.{s}.len` is `0`, the subtraction wraps to `maxInt(usize)`, producing an OOB panic (Debug/Safe) or silent arbitrary-memory read (ReleaseFast); add a `{s}.{s}.len > 0` guard before this expression",
        .{ recv, field, recv, field, recv, field },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, lb_tok),
        .end = Pos.fromTokenEnd(tree, lb_tok + 8),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: basic fires" {
    try testing.expectFires(check, R,
        \\fn prev(items: []const u8, idx: usize) u8 {
        \\    return items[idx - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: field minus one fires" {
    try testing.expectFires(check, R,
        \\const Self = struct { current: usize, items: []const u8 };
        \\fn prev(self: Self) u8 {
        \\    return self.items[self.current - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: idx - 2 does not fire" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, idx: usize) u8 {
        \\    return items[idx - 2];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: idx + 1 does not fire" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, idx: usize) u8 {
        \\    return items[idx + 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: plain index does not fire" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, idx: usize) u8 {
        \\    return items[idx];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: recv.field.len - 1 fires (Form C)" {
    try testing.expectFires(check, R,
        \\const Self = struct { args: []const u8 };
        \\fn deinit(self: *Self) void {
        \\    _ = self.args[self.args.len - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: recv.field.len - 2 does not fire" {
    try testing.expectNoFire(check,
        \\const Self = struct { args: []const u8 };
        \\fn f(self: *Self) void {
        \\    _ = self.args[self.args.len - 2];
        \\}
        \\
    );
}
