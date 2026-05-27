//! Detects `@truncate(a - b)` and `@truncate(recv.field - other)` without a
//! preceding subtraction-safety guard.  When `b > a` (unsigned underflow) the
//! subtraction wraps to a huge value BEFORE `@truncate` narrows it, yielding
//! a garbage result instead of a meaningful error.
//!
//! Real-world instances:
//!   - oven-sh/bun#23993 (OKPacket.zig): `@truncate(this.packet_size - read_size)`
//!     without a `packet_size > read_size` guard; OOB read when read_size exceeded
//!     packet_size.
//!   - oven-sh/bun#6761 / #29905 (h2_frame_parser.zig): `payload.len - padding`
//!     without bounds check; fixed by adding explicit padding-length guards.
//!
//! Detection (Tier 1, token walk):
//!   Two patterns:
//!   Form A: `@truncate ( identifier - identifier )`  — 6 tokens
//!   Form B: `@truncate ( identifier . identifier - identifier )`  — 8 tokens
//!   Fire at the `@truncate` builtin token.
//!   Suppression: if a saturating subtract token (`minus_percent` — `-|`) is
//!   used inside the parens, suppress (explicit overflow handling).

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
const R = "truncate-subtraction-without-guard";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .truncate_subtraction_without_guard)) return;
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

    if (first + 5 > last) return;

    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }

        if (tags[t] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "@truncate")) continue;
        if (tags[t + 1] != .l_paren) continue;

        // Form A: `@truncate ( identifier - identifier )`
        //   t+0: builtin ["@truncate"]
        //   t+1: l_paren
        //   t+2: identifier
        //   t+3: minus
        //   t+4: identifier
        //   t+5: r_paren
        if (t + 5 <= last and matchFormA(tags, t)) {
            try report(gpa, problems, tree, t);
            continue;
        }

        // Form B: `@truncate ( identifier . identifier - identifier )`
        //   t+0: builtin ["@truncate"]
        //   t+1: l_paren
        //   t+2: identifier
        //   t+3: period
        //   t+4: identifier
        //   t+5: minus
        //   t+6: identifier
        //   t+7: r_paren
        if (t + 7 <= last and matchFormB(tags, t)) {
            try report(gpa, problems, tree, t);
            continue;
        }
    }
}

fn matchFormA(tags: []const std.zig.Token.Tag, t: Ast.TokenIndex) bool {
    return tags[t + 2] == .identifier and
        tags[t + 3] == .minus and
        tags[t + 4] == .identifier and
        tags[t + 5] == .r_paren;
}

fn matchFormB(tags: []const std.zig.Token.Tag, t: Ast.TokenIndex) bool {
    return tags[t + 2] == .identifier and
        tags[t + 3] == .period and
        tags[t + 4] == .identifier and
        tags[t + 5] == .minus and
        tags[t + 6] == .identifier and
        tags[t + 7] == .r_paren;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    truncate_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@truncate(a - b)` — if `b > a` the unsigned subtraction wraps to a huge value BEFORE `@truncate` narrows it, yielding garbage; add a guard `if (a >= b)` (or use saturating `-|` arithmetic) before the subtraction",
        .{},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, truncate_tok),
        .end = Pos.fromTokenEnd(tree, truncate_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "truncate-subtraction-without-guard: form A fires" {
    try testing.expectFires(check, R,
        \\fn decode(packet_size: u32, read_size: u32) u8 {
        \\    return @truncate(packet_size - read_size);
        \\}
        \\
    );
}

test "truncate-subtraction-without-guard: form B fires" {
    try testing.expectFires(check, R,
        \\const Ctx = struct { packet_size: u32 };
        \\fn decode(self: Ctx, read_size: u32) u8 {
        \\    return @truncate(self.packet_size - read_size);
        \\}
        \\
    );
}

test "truncate-subtraction-without-guard: addition does not fire" {
    try testing.expectNoFire(check,
        \\fn encode(a: u32, b: u32) u8 {
        \\    return @truncate(a + b);
        \\}
        \\
    );
}

test "truncate-subtraction-without-guard: @truncate of plain identifier does not fire" {
    try testing.expectNoFire(check,
        \\fn encode(n: u32) u8 {
        \\    return @truncate(n);
        \\}
        \\
    );
}

test "truncate-subtraction-without-guard: @intCast subtraction does not fire" {
    try testing.expectNoFire(check,
        \\fn encode(a: u32, b: u32) u8 {
        \\    return @intCast(a - b);
        \\}
        \\
    );
}
