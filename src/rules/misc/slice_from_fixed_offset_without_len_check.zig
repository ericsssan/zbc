//! Detects slicing from a non-zero constant offset into a slice/array whose
//! length is not checked before the slice expression:
//!
//!   const tail = line[6..];   // BUG: crashes / OOB if line.len < 6
//!
//! In Zig, `buf[N..]` where `buf.len < N` is a safety-checked out-of-bounds
//! error (trapping in Debug/ReleaseSafe, undefined behaviour in ReleaseFast).
//! When `buf` comes from user or network input the length is unconstrained.
//!
//! Fix: check `buf.len` before slicing:
//!   if (buf.len < 6) return error.TruncatedInput;
//!   const tail = buf[6..];
//!
//! Real-world shape: oven-sh/bun#31227 (patch/lib.rs Zig-mirror pattern —
//! `line[b"--- a/".len()..] ` panics on a truncated `--- a/` header line),
//! oven-sh/bun#31264 (eql_case_insensitive_ascii OOB when input shorter than
//! the keyword literal).
//!
//! Detection (Tier 1, per-fn body token walk):
//!   1. Scan for `identifier l_bracket number_literal(N) ellipsis2 r_bracket`
//!      where N > 0 (i.e., `buf[N..]`).
//!   2. The number_literal must represent a value > 0 (skip `buf[0..]`).
//!   3. Suppression: if `identifier(buf) period identifier(len)` appears
//!      anywhere in the fn body before the slice token, the programmer is
//!      already consulting `.len` on that buffer — do not fire.
//!   4. Suppression: if the preceding token before `identifier(buf)` is
//!      `period` (chain: `self.buf[N..]`) — the receiver has more context;
//!      skip to reduce noise on deeply-chained field accesses.
//!   5. Fire at the `l_bracket` token of the unsafe slice.

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
const R = "slice-from-fixed-offset-without-len-check";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .slice_from_fixed_offset_without_len_check)) return;
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

    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        // Skip nested fn bodies.
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }

        // Pattern: `identifier l_bracket number_literal ellipsis2 r_bracket`
        //   t+0: identifier (the buffer/slice variable)
        //   t+1: l_bracket
        //   t+2: number_literal (the offset N)
        //   t+3: ellipsis2 (..)
        //   t+4: r_bracket  (we check t+4 <= last)
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .l_bracket) continue;
        if (tags[t + 2] != .number_literal) continue;
        if (tags[t + 3] != .ellipsis2) continue;
        if (t + 4 > last) continue;
        if (tags[t + 4] != .r_bracket) continue;

        const offset_str = tree.tokenSlice(t + 2);

        // Skip `buf[0..]` — always safe.
        if (std.mem.eql(u8, offset_str, "0")) continue;

        const buf_name = tree.tokenSlice(t);

        // Suppression: skip if the identifier is a chained field access
        // (`self.buf[N..]`). The receiver provides more context and static
        // analysis becomes very imprecise without type info (Tier 4).
        if (t > first and tags[t - 1] == .period) continue;

        // Suppression: if `buf_name.len` appears in the fn body BEFORE
        // this slice, the programmer already consults the length.
        if (lenCheckedBefore(tree, tags, first, t, buf_name)) continue;

        // Fire at the l_bracket of the unsafe slice.
        try report(gpa, problems, tree, t + 1, buf_name, offset_str);
    }
}

/// Returns true iff `identifier(name) period identifier(len)` appears
/// in the range `[start, end)` — i.e. `name.len` is accessed before the slice.
fn lenCheckedBefore(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    name: []const u8,
) bool {
    if (start >= end) return false;
    var t: Ast.TokenIndex = start;
    // end is exclusive: we scan [start, end-1].
    while (t + 2 < end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), name)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), "len")) continue;
        return true;
    }
    return false;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    lb_tok: Ast.TokenIndex,
    buf_name: []const u8,
    offset: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}[{s}..]` slices from a fixed offset without a prior `{s}.len >= {s}` check — crashes (Debug/Safe) or UB (ReleaseFast) when the slice is shorter than {s} bytes; add `if ({s}.len < {s}) return error.TruncatedInput;` before this slice",
        .{ buf_name, offset, buf_name, offset, offset, buf_name, offset },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, lb_tok),
        .end = Pos.fromTokenEnd(tree, lb_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "slice-from-fixed-offset-without-len-check: basic pattern fires" {
    try testing.expectFires(check, R,
        \\fn parse(line: []const u8) []const u8 {
        \\    return line[6..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: larger offset fires" {
    try testing.expectFires(check, R,
        \\fn parse(header: []const u8) []const u8 {
        \\    return header[10..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: zero offset does not fire" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8) []const u8 {
        \\    return buf[0..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: len check before slice suppresses" {
    try testing.expectNoFire(check,
        \\fn parse(line: []const u8) ![]const u8 {
        \\    if (line.len < 6) return error.TruncatedInput;
        \\    return line[6..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: chained field access does not fire" {
    try testing.expectNoFire(check,
        \\const S = struct {
        \\    buf: []const u8,
        \\    pub fn tail(self: S) []const u8 {
        \\        return self.buf[4..];
        \\    }
        \\};
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: len consulted anywhere before suppresses" {
    try testing.expectNoFire(check,
        \\fn f(data: []const u8) []const u8 {
        \\    const n = data.len;
        \\    _ = n;
        \\    return data[4..];
        \\}
        \\
    );
}
