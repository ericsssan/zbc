//! Detects `.getEntry(key).?` — forced optional unwrap on the result of
//! `HashMap.getEntry`.  `getEntry(key)` returns `?Entry`; when the key is
//! absent the result is null and the forced `.?` panics.  The safe form is
//! `if (map.getEntry(key)) |entry| { … }` or guard with `orelse return`.
//!
//! Real-world instance:
//!   - oven-sh/bun#14606 (H2 stream handling): `this.streams.getEntry(stream_id).?.value_ptr`
//!     was called after a callback dispatch that may have removed the stream id from the
//!     map; the forced `.?` panicked at runtime.
//!     Fix: added `orelse return` guard before the unwrap.
//!
//! Detection (Tier 1, paren-balanced forward scan):
//!   Pattern: `identifier("getEntry") l_paren … r_paren period question_mark`
//!   For each `getEntry(`, paren-balance-skips the argument list to its
//!   closing `)`, then fires if the very next two tokens are `.?`
//!   (`.period` + `.question_mark`).

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "hashmap-getentry-forced-unwrap";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .hashmap_getentry_forced_unwrap)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 2 <= last_tok) : (t += 1) {
        // Find `getEntry(`
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "getEntry")) continue;
        if (tags[t + 1] != .l_paren) continue;

        // Paren-balance-skip the argument list.
        var i = t + 1;
        var depth: u32 = 1;
        i += 1;
        while (i <= last_tok and depth > 0) : (i += 1) {
            if (tags[i] == .l_paren) depth += 1 else if (tags[i] == .r_paren) depth -= 1;
        }
        // `i` is now the token immediately after the closing `)`.

        // Fire if `.?` follows immediately.
        if (i + 1 > last_tok) continue;
        if (tags[i] != .period) continue;
        if (tags[i + 1] != .question_mark) continue;

        try report(gpa, problems, tree, t, i + 1);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    getentry_tok: Ast.TokenIndex,
    question_mark_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`.getEntry(key).?` — `HashMap.getEntry` returns `?Entry`; the forced `.?` panics when the key is absent; use `if (map.getEntry(key)) |entry| {{ … }}` or guard with `orelse return`",
        .{},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, getentry_tok),
        .end = Pos.fromTokenEnd(tree, question_mark_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "hashmap-getentry-forced-unwrap: fires on .getEntry().?" {
    try testing.expectFires(check, R,
        \\fn getStream(streams: *StreamMap, id: u32) *Stream {
        \\    return streams.getEntry(id).?.value_ptr;
        \\}
        \\
    );
}

test "hashmap-getentry-forced-unwrap: safe orelse return does not fire" {
    try testing.expectNoFire(check,
        \\fn getStream(streams: *StreamMap, id: u32) ?*Stream {
        \\    const entry = streams.getEntry(id) orelse return null;
        \\    return entry.value_ptr;
        \\}
        \\
    );
}

test "hashmap-getentry-forced-unwrap: if guard does not fire" {
    try testing.expectNoFire(check,
        \\fn handleStream(streams: *StreamMap, id: u32) void {
        \\    if (streams.getEntry(id)) |entry| {
        \\        _ = entry.value_ptr;
        \\    }
        \\}
        \\
    );
}

test "hashmap-getentry-forced-unwrap: getEntry without .? does not fire" {
    try testing.expectNoFire(check,
        \\fn getStream(streams: *StreamMap, id: u32) ??*Stream {
        \\    const entry = streams.getEntry(id);
        \\    return if (entry) |e| e.value_ptr else null;
        \\}
        \\
    );
}
