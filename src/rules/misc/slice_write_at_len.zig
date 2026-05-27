//! Detects `buf[buf.len] = value` and `obj.field[obj.field.len] = value` —
//! a write exactly one past the end of a slice or ArrayList field.
//! Valid Zig slice indices are 0..len-1; writing at index `len` is
//! out-of-bounds, panics in Debug/ReleaseSafe, and is undefined behaviour
//! in ReleaseFast.
//!
//! Real-world instance:
//!   - oven-sh/bun#29982 (toUTF16Alloc): `output.items[output.items.len] = 0`
//!     wrote a null-terminator sentinel one past the last valid index of the
//!     ArrayList buffer.  Fix: `try output.append(gpa, 0)`.
//!
//! Detection (Tier 1, flat token walk):
//!   Form A: `IDENT [ IDENT . len ] =`                      (7 tokens)
//!   Form B: `IDENT . FIELD [ IDENT . FIELD . len ] =`      (11 tokens)
//!   Both forms fire only when `=` (assignment) immediately follows `]`,
//!   distinguishing writes from reads.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "slice-write-at-len";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .slice_write_at_len)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    if (tree.tokens.len < 7) return;
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 6 <= last_tok) : (t += 1) {
        // Form A: IDENT [ IDENT . len ] =
        if (tags[t] == .identifier and
            tags[t + 1] == .l_bracket and
            tags[t + 2] == .identifier and
            tags[t + 3] == .period and
            tags[t + 4] == .identifier and
            tags[t + 5] == .r_bracket and
            tags[t + 6] == .equal and
            std.mem.eql(u8, tree.tokenSlice(t), tree.tokenSlice(t + 2)) and
            std.mem.eql(u8, tree.tokenSlice(t + 4), "len"))
        {
            try reportA(gpa, problems, tree, t);
            continue;
        }

        // Form B: IDENT . FIELD [ IDENT . FIELD . len ] =
        if (t + 10 <= last_tok and
            tags[t] == .identifier and
            tags[t + 1] == .period and
            tags[t + 2] == .identifier and
            tags[t + 3] == .l_bracket and
            tags[t + 4] == .identifier and
            tags[t + 5] == .period and
            tags[t + 6] == .identifier and
            tags[t + 7] == .period and
            tags[t + 8] == .identifier and
            tags[t + 9] == .r_bracket and
            tags[t + 10] == .equal and
            std.mem.eql(u8, tree.tokenSlice(t), tree.tokenSlice(t + 4)) and
            std.mem.eql(u8, tree.tokenSlice(t + 2), tree.tokenSlice(t + 6)) and
            std.mem.eql(u8, tree.tokenSlice(t + 8), "len"))
        {
            try reportB(gpa, problems, tree, t);
            continue;
        }
    }
}

fn reportA(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    base_tok: Ast.TokenIndex,
) !void {
    const base = tree.tokenSlice(base_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}[{s}.len] = ...` writes one past the end of the slice — valid Zig indices are 0..len-1; index `len` is out-of-bounds and will panic in Debug/ReleaseSafe",
        .{ base, base },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, base_tok),
        .end = Pos.fromTokenEnd(tree, base_tok + 5),
        .message = msg,
    });
}

fn reportB(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    base_tok: Ast.TokenIndex,
) !void {
    const base = tree.tokenSlice(base_tok);
    const field = tree.tokenSlice(base_tok + 2);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}.{s}[{s}.{s}.len] = ...` writes one past the end of the slice — valid Zig indices are 0..len-1; index `len` is out-of-bounds and will panic in Debug/ReleaseSafe",
        .{ base, field, base, field },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, base_tok),
        .end = Pos.fromTokenEnd(tree, base_tok + 9),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "slice-write-at-len: fires on buf[buf.len] = value (Form A)" {
    try testing.expectFires(check, R,
        \\fn addSentinel(buf: []u8) void {
        \\    buf[buf.len] = 0;
        \\}
        \\
    );
}

test "slice-write-at-len: fires on output.items[output.items.len] = value (Form B)" {
    try testing.expectFires(check, R,
        \\fn appendNull(output: *std.ArrayListUnmanaged(u16)) void {
        \\    output.items[output.items.len] = 0;
        \\}
        \\
    );
}

test "slice-write-at-len: buf[buf.len - 1] = value does not fire" {
    try testing.expectNoFire(check,
        \\fn writeLast(buf: []u8) void {
        \\    buf[buf.len - 1] = 0;
        \\}
        \\
    );
}

test "slice-write-at-len: read at buf[buf.len] does not fire" {
    try testing.expectNoFire(check,
        \\fn readSentinel(buf: [:0]const u8) u8 {
        \\    return buf[buf.len];
        \\}
        \\
    );
}

test "slice-write-at-len: different bases do not fire" {
    try testing.expectNoFire(check,
        \\fn write(dst: []u8, src: []const u8) void {
        \\    dst[src.len] = 0;
        \\}
        \\
    );
}

test "slice-write-at-len: different fields do not fire (Form B)" {
    try testing.expectNoFire(check,
        \\fn write(a: *S, b: *S) void {
        \\    a.items[b.items.len] = 0;
        \\}
        \\
    );
}
