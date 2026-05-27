//! Detects calls to `joinAbsStringBuf(` — this unchecked variant does not
//! detect buffer overflow and silently writes past the end of fixed-size
//! stack or threadlocal buffers when the normalized path exceeds the buffer
//! size.  The safe alternative `joinAbsStringBufChecked` falls back to a
//! heap allocation when the buffer would overflow.
//!
//! Real-world instance:
//!   - oven-sh/bun#28585 (pathToFileURL): `joinAbsStringBuf` was called with
//!     a fixed 4096-byte threadlocal `join_buf`.  Long relative paths (> 4 KB)
//!     caused `normalizeStringGenericTZ` to `@memcpy` past the end of the
//!     buffer, corrupting adjacent threadlocal state.
//!     Fix: switched to `joinAbsStringBufChecked` which returns a heap-
//!     allocated fallback string on overflow.
//!
//! Detection (Tier 1, flat token walk):
//!   Pattern: `identifier("joinAbsStringBuf") l_paren` — 2 tokens.
//!   Fire at the `joinAbsStringBuf` identifier.
//!   Calls to `joinAbsStringBufChecked` do NOT fire.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "joinabsstringbuf-without-checked-variant";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .joinabsstringbuf_without_checked_variant)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 1 <= last_tok) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const name = tree.tokenSlice(t);
        // Fire only on the plain (unchecked) variant; "Checked" suffix is safe.
        if (!std.mem.eql(u8, name, "joinAbsStringBuf")) continue;
        if (tags[t + 1] != .l_paren) continue;

        try report(gpa, problems, tree, t);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`joinAbsStringBuf(...)` — this unchecked variant does not detect buffer overflow; use `joinAbsStringBufChecked(...)` which returns a heap-allocated fallback string when the normalized path exceeds the fixed buffer size",
        .{},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, tok),
        .end = Pos.fromTokenEnd(tree, tok + 1),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "joinabsstringbuf-without-checked-variant: fires" {
    try testing.expectFires(check, R,
        \\fn makeUrl(buf: []u8, parts: []const []const u8) []const u8 {
        \\    return joinAbsStringBuf(buf, parts, .auto);
        \\}
        \\
    );
}

test "joinabsstringbuf-without-checked-variant: checked variant does not fire" {
    try testing.expectNoFire(check,
        \\fn makeUrl(buf: []u8, parts: []const []const u8, alloc: std.mem.Allocator) bun.String {
        \\    return joinAbsStringBufChecked(buf, parts, .auto, alloc);
        \\}
        \\
    );
}

test "joinabsstringbuf-without-checked-variant: similar name without l_paren does not fire" {
    try testing.expectNoFire(check,
        \\const fn_ptr = joinAbsStringBuf;
        \\fn use(buf: []u8, parts: []const []const u8) []const u8 {
        \\    return fn_ptr(buf, parts, .auto);
        \\}
        \\
    );
}
