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
//!
//! Suppression (five checks, all applied):
//!
//!   1. Same-expression `and`-guard (window 15): `GUARD_IDENT (> | !=) 0
//!      keyword_and` immediately before the array identifier.
//!      Covers `x > 0 and buf[x - 1]`.
//!
//!   2. If-body guard (window 25): `keyword_if ( GUARD_IDENT (> | !=) 0 )` with
//!      no `;` between the condition `)` and `[`.  Covers
//!      `if (x > 0) assert(arr[x - 1])`.
//!
//!   3. Assert guard (window 30): `assert ( GUARD_IDENT (> | !=) 0 )` anywhere
//!      in the preceding tokens (semicolons allowed — the assert may be on a
//!      prior line).  Covers `assert(len > 0); arr[len - 1]`.
//!
//!   4. Early-return guard (window 45): `keyword_if ( GUARD_IDENT == 0 )
//!      keyword_return` (return within 3 tokens of condition close).
//!      Covers `if (len == 0) return err; arr[len - 1]`.
//!
//!   5. Comptime context (window 5): `keyword_comptime` within 5 tokens of `[`.
//!      A comptime subscript is bounds-checked at compile time.
//!      Covers `comptime assert(fmt[fmt.len - 1] == '\n')`.

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

        // Subscript inside a `comptime` expression is evaluated at compile
        // time; any OOB would be a compile error, not a runtime panic.
        if (hasComptimeContext(tags, t)) continue;

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
            if (hasAndGuard(tags, tree, t, &.{idx_name})) continue;
            if (hasIfBodyGuard(tags, tree, t, &.{idx_name})) continue;
            if (hasAssertGuard(tags, tree, t, &.{idx_name})) continue;
            if (hasEarlyReturnGuard(tags, tree, t, &.{idx_name})) continue;
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
            const outer_name = tree.tokenSlice(t + 1);
            const idx_name = tree.tokenSlice(t + 3);
            if (hasAndGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (hasIfBodyGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (hasAssertGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (hasEarlyReturnGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
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
            const recv_name = tree.tokenSlice(t + 1);
            const field_name = tree.tokenSlice(t + 3);
            if (hasAndGuard(tags, tree, t, &.{ recv_name, field_name, "len" })) continue;
            if (hasIfBodyGuard(tags, tree, t, &.{ recv_name, field_name, "len" })) continue;
            if (hasAssertGuard(tags, tree, t, &.{ recv_name, field_name, "len" })) continue;
            if (hasEarlyReturnGuard(tags, tree, t, &.{ recv_name, field_name, "len" })) continue;
            try reportC(gpa, problems, tree, t, recv_name, field_name);
            continue;
        }
    }
}

/// True when `keyword_comptime` appears within 5 tokens before `[`.
/// A subscript evaluated at compile time cannot cause a runtime OOB panic.
fn hasComptimeContext(tags: []const std.zig.Token.Tag, t: Ast.TokenIndex) bool {
    const window: u32 = 5;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] == .keyword_comptime) return true;
    }
    return false;
}

/// Returns true when a same-expression `and`-guard for one of `guard_names` is
/// present in the 15 tokens immediately before the `[` at position `t`.
///
/// Matched token pattern (reading backward from `t`):
///   ... GUARD_IDENT (> | !=) 0 keyword_and ARRAY_IDENT [t]
///
/// GUARD_IDENT must match one of `guard_names`.  Covers `x > 0 and buf[x - 1]`
/// and `prefix.len > 0 and arr[prefix.len - 1]` (guard_names includes both
/// "prefix" and "len" for Form B).
fn hasAndGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 5) return false;
    const window: u32 = 15;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .keyword_and) continue;
        if (k < 3) continue;
        if (tags[k - 1] != .number_literal) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k - 1), "0")) continue;
        if (tags[k - 2] != .angle_bracket_right and tags[k - 2] != .bang_equal) continue;
        if (tags[k - 3] != .identifier) continue;
        const guard_id = tree.tokenSlice(k - 3);
        for (guard_names) |gn| {
            if (std.mem.eql(u8, guard_id, gn)) return true;
        }
    }
    return false;
}

/// Returns true when the subscript at `t` is inside an `if`-body whose
/// condition is a simple zero-guard on one of `guard_names`.
///
/// Looks backward within 25 tokens for `keyword_if`, then checks two
/// condition shapes (both require no `;` between condition-close and `[`
/// — ensuring the subscript is in the body, not a later statement):
///
///   Simple  (5 tok): `( GUARD_IDENT (> | !=) 0 )`
///   Dotted  (7 tok): `( OUTER . INNER (> | !=) 0 )`
///
/// In both shapes the matched identifier must be in `guard_names`.
/// `or`-conditions are intentionally not matched — `if (x > 0 or cond)`
/// does not guarantee `x > 0`.
fn hasIfBodyGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 7) return false;
    const window: u32 = 25;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .keyword_if) continue;

        // Simple form: `keyword_if ( GUARD_IDENT cmp 0 )` — 6 tokens total,
        // condition closes at k+5.
        if (k + 5 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            (tags[k + 3] == .angle_bracket_right or tags[k + 3] == .bang_equal) and
            tags[k + 4] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 4), "0") and
            tags[k + 5] == .r_paren)
        {
            const guard_id = tree.tokenSlice(k + 2);
            var matched = false;
            for (guard_names) |gn| {
                if (std.mem.eql(u8, guard_id, gn)) { matched = true; break; }
            }
            if (matched and !hasSemicolon(tags, k + 6, t)) return true;
        }

        // Dotted form: `keyword_if ( OUTER . INNER cmp 0 )` — 8 tokens total,
        // condition closes at k+7.
        if (k + 7 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            tags[k + 3] == .period and
            tags[k + 4] == .identifier and
            (tags[k + 5] == .angle_bracket_right or tags[k + 5] == .bang_equal) and
            tags[k + 6] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 6), "0") and
            tags[k + 7] == .r_paren)
        {
            const outer_id = tree.tokenSlice(k + 2);
            const inner_id = tree.tokenSlice(k + 4);
            var matched = false;
            for (guard_names) |gn| {
                if (std.mem.eql(u8, outer_id, gn) or std.mem.eql(u8, inner_id, gn)) {
                    matched = true;
                    break;
                }
            }
            if (matched and !hasSemicolon(tags, k + 8, t)) return true;
        }
    }
    return false;
}

/// Returns true when an `assert`-guard within 30 tokens before `[` protects
/// one of `guard_names`.
///
/// Matched patterns (semicolons between assert and `[` are allowed — the
/// assert is often a separate statement on the prior line):
///   Simple: `assert ( GUARD_IDENT (> | !=) 0 )`
///   Dotted: `assert ( OUTER . INNER (> | !=) 0 )`
fn hasAssertGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 6) return false;
    const window: u32 = 30;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k), "assert")) continue;

        // Simple: `assert ( GUARD_IDENT (> | !=) 0 )`
        if (k + 5 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            (tags[k + 3] == .angle_bracket_right or tags[k + 3] == .bang_equal) and
            tags[k + 4] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 4), "0") and
            tags[k + 5] == .r_paren)
        {
            const guard_id = tree.tokenSlice(k + 2);
            for (guard_names) |gn| {
                if (std.mem.eql(u8, guard_id, gn)) return true;
            }
        }

        // Dotted: `assert ( OUTER . INNER (> | !=) 0 )`
        if (k + 7 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            tags[k + 3] == .period and
            tags[k + 4] == .identifier and
            (tags[k + 5] == .angle_bracket_right or tags[k + 5] == .bang_equal) and
            tags[k + 6] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 6), "0") and
            tags[k + 7] == .r_paren)
        {
            const outer_id = tree.tokenSlice(k + 2);
            const inner_id = tree.tokenSlice(k + 4);
            for (guard_names) |gn| {
                if (std.mem.eql(u8, outer_id, gn) or std.mem.eql(u8, inner_id, gn)) return true;
            }
        }
    }
    return false;
}

/// Returns true when an early-return guard `if (GUARD == 0) return …`
/// precedes the subscript at `t` within 45 tokens.
///
/// The guard ensures execution only reaches `[` when GUARD != 0.
/// Semicolons between the return statement and `[` are allowed.
///
/// Matched patterns:
///   Simple: `if ( GUARD_IDENT == 0 ) keyword_return`  (return within 3 tok of `)`)
///   Dotted: `if ( OUTER . INNER == 0 ) keyword_return`
fn hasEarlyReturnGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 8) return false;
    const window: u32 = 45;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .keyword_if) continue;

        // Simple: `if ( GUARD_IDENT == 0 ) keyword_return`
        //   condition closes at k+5; return must appear within 3 tokens of it.
        if (k + 6 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            tags[k + 3] == .equal_equal and
            tags[k + 4] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 4), "0") and
            tags[k + 5] == .r_paren)
        {
            if (hasReturnWithin(tags, k + 6, k + 9, t)) {
                const guard_id = tree.tokenSlice(k + 2);
                for (guard_names) |gn| {
                    if (std.mem.eql(u8, guard_id, gn)) return true;
                }
            }
        }

        // Dotted: `if ( OUTER . INNER == 0 ) keyword_return`
        //   condition closes at k+7; return within 3 tokens.
        if (k + 8 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            tags[k + 3] == .period and
            tags[k + 4] == .identifier and
            tags[k + 5] == .equal_equal and
            tags[k + 6] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 6), "0") and
            tags[k + 7] == .r_paren)
        {
            if (hasReturnWithin(tags, k + 8, k + 11, t)) {
                const outer_id = tree.tokenSlice(k + 2);
                const inner_id = tree.tokenSlice(k + 4);
                for (guard_names) |gn| {
                    if (std.mem.eql(u8, outer_id, gn) or std.mem.eql(u8, inner_id, gn)) return true;
                }
            }
        }
    }
    return false;
}

/// True if `keyword_return` appears in [from, min(to, bound)) .
fn hasReturnWithin(tags: []const std.zig.Token.Tag, from: Ast.TokenIndex, to: Ast.TokenIndex, bound: Ast.TokenIndex) bool {
    const end = @min(to, bound);
    var i = from;
    while (i < end) : (i += 1) {
        if (tags[i] == .keyword_return) return true;
    }
    return false;
}

/// True if any token in [from, to) is a semicolon.
fn hasSemicolon(tags: []const std.zig.Token.Tag, from: Ast.TokenIndex, to: Ast.TokenIndex) bool {
    var i = from;
    while (i < to) : (i += 1) {
        if (tags[i] == .semicolon) return true;
    }
    return false;
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

test "index-minus-one-without-zero-guard: Form A suppressed by and-guard" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) u8 {
        \\    return if (x > 0 and buf[x - 1] == 0) 1 else 0;
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A suppressed by != 0 and-guard" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) u8 {
        \\    return if (x != 0 and buf[x - 1] == 0) 1 else 0;
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A fires when guard uses different ident" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, x: usize, y: usize) u8 {
        \\    return if (y > 0 and buf[x - 1] == 0) 1 else 0;
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by and-guard on outer ident" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, s: anytype) bool {
        \\    return s.len > 0 and items[s.len - 1] == 0;
        \\}
        \\
    );
}

// ── If-body guard tests ────────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: Form A suppressed by if-body guard (simple)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) void {
        \\    if (x > 0) assert(buf[x - 1] == 0);
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A suppressed by if-body guard (!= 0)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) void {
        \\    if (x != 0) doSomething(buf[x - 1]);
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A fires when guard uses different ident (if-body)" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, x: usize, y: usize) void {
        \\    if (y > 0) _ = buf[x - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A fires when if guard is followed by semicolon" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, x: usize) void {
        \\    if (x > 0) doSomething();
        \\    _ = buf[x - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by if-body guard (dotted)" {
    try testing.expectNoFire(check,
        \\fn f(arr: []const u8, s: anytype) void {
        \\    if (s.len > 0) assert(arr[s.len - 1] == 0);
        \\}
        \\
    );
}

// ── Assert guard tests ─────────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: Form A suppressed by assert guard (simple)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) u8 {
        \\    assert(n > 0);
        \\    return buf[n - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by assert guard (dotted)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, s: anytype) u8 {
        \\    assert(s.len > 0);
        \\    return buf[s.len - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: assert guard with != 0 suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) u8 {
        \\    assert(n != 0);
        \\    return buf[n - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: assert guard on different ident still fires" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, n: usize, m: usize) u8 {
        \\    assert(m > 0);
        \\    return buf[n - 1];
        \\}
        \\
    );
}

// ── Early-return guard tests ───────────────────────────────────────────────

test "index-minus-one-without-zero-guard: Form A suppressed by early-return guard" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) !u8 {
        \\    if (n == 0) return error.Empty;
        \\    return buf[n - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by early-return guard (dotted)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, s: anytype) !u8 {
        \\    if (s.len == 0) return error.Empty;
        \\    return buf[s.len - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: early-return guard on different ident still fires" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, n: usize, m: usize) !u8 {
        \\    if (m == 0) return error.Empty;
        \\    return buf[n - 1];
        \\}
        \\
    );
}

// ── Comptime context tests ─────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: comptime assert suppressed" {
    try testing.expectNoFire(check,
        \\fn f(comptime fmt: []const u8) void {
        \\    comptime assert(fmt[fmt.len - 1] == '\n');
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: runtime access still fires" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, n: usize) u8 {
        \\    return buf[n - 1];
        \\}
        \\
    );
}
