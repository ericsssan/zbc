//! Detects struct literal field copies of the form `.field = recv.field`
//! where the field name suggests a refcounted or owned type and no
//! ref-acquire method (clone/dupeRef/ref/retain/…) is called on the
//! source in the nearby tokens.
//!
//! Real-world shapes:
//!   oven-sh/bun#30955 — `Blob.name` bitwise-copied without calling
//!   `.dupeRef()`; both the source and the copy call `name.deinit()` →
//!   double-decrement → SIGFPE.
//!   oven-sh/bun#30991 — WTF string ref copied without `ref()`.
//!   oven-sh/bun#30882 — specifier field copied without `dupe_ref()`.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Scan for the struct literal field-init pattern:
//!        t+0: `.period`
//!        t+1: `.identifier`  (dest_field)
//!        t+2: `.equal`
//!        t+3: `.identifier`  (source_recv)
//!        t+4: `.period`
//!        t+5: `.identifier`  (source_field, same text as dest_field)
//!      AND `dest_field == source_field`.
//!   2. The field name must contain a substring associated with
//!      refcounted / owned types:
//!        "name", "str", "string", "ref", "handle", "buf", "data", "content".
//!   3. In the window [t-10, t) there must be NO call to a ref-acquire
//!      method (`isRefAcquireName`) on `source_recv.source_field`
//!      — i.e. no `source_recv . source_field . <acquire> (` pattern.
//!   4. Fire at t+1 (the dest_field identifier).

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const tokens = @import("../../ast/tokens.zig");
const method_names = @import("../../model/method_names.zig");
const testing = @import("../../testing.zig");

const skipFnDecl = tokens.skipFnDecl;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "ref-counted-copy-without-dupe";

/// Field name substrings that suggest the field holds a refcounted
/// or heap-owned value.
const refcounted_substrings = [_][]const u8{
    "name", "str", "string", "ref", "handle", "buf", "data", "content",
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .ref_counted_copy_without_dupe)) return;
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
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipFnDecl(tags, t, last);
            continue;
        }

        // Pattern: `. dest_field = source_recv . source_field`
        //   t+0: period
        //   t+1: identifier  (dest_field)
        //   t+2: equal
        //   t+3: identifier  (source_recv)
        //   t+4: period
        //   t+5: identifier  (source_field)
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .equal) continue;
        if (tags[t + 3] != .identifier) continue;
        if (tags[t + 4] != .period) continue;
        if (tags[t + 5] != .identifier) continue;

        const dest_field = tree.tokenSlice(t + 1);
        const source_recv = tree.tokenSlice(t + 3);
        const source_field = tree.tokenSlice(t + 5);

        // Both sides must name the same field.
        if (!std.mem.eql(u8, dest_field, source_field)) continue;

        // Field name must suggest a refcounted / owned type.
        if (!isRefcountedFieldName(dest_field)) continue;

        // Suppress when the RHS is `source_recv.source_field.<acquire>(`:
        //   t+4: period, t+5: source_field, t+6: period, t+7: <method>, t+8: l_paren
        if (t + 8 <= last and
            tags[t + 6] == .period and
            tags[t + 7] == .identifier and
            tags[t + 8] == .l_paren and
            method_names.isRefAcquireName(tree.tokenSlice(t + 7))) continue;

        // Also check that no ref-acquire is called on source_recv.source_field
        // in the 10 tokens preceding t (backward-scan for manual pre-clone).
        const window_start = t -| 10;
        if (hasRefAcquireCall(tree, tags, window_start, t -| 1, source_recv, source_field)) continue;

        try report(gpa, problems, tree, t + 1, dest_field, source_recv);
    }
}

/// True iff any underscore-delimited word component of `name` exactly matches
/// one of the refcounted substrings.  Whole-word matching prevents short
/// substrings like "ref" from firing on compound names like "react_fast_refresh",
/// or "name" from firing on "rename".
///
/// Also suppressed when the last component is all-digits (e.g. `user_data_64`,
/// `user_data_32`) — a numeric suffix strongly implies an integer type.
fn isRefcountedFieldName(name: []const u8) bool {
    // If the final underscore-component is purely numeric, the field almost
    // certainly holds an integer, not a refcounted pointer.
    if (std.mem.lastIndexOfScalar(u8, name, '_')) |last_us| {
        const suffix = name[last_us + 1 ..];
        if (suffix.len > 0) {
            var all_digits = true;
            for (suffix) |c| {
                if (!std.ascii.isDigit(c)) { all_digits = false; break; }
            }
            if (all_digits) return false;
        }
    }
    var it = std.mem.splitScalar(u8, name, '_');
    while (it.next()) |word| {
        for (refcounted_substrings) |sub| {
            if (std.mem.eql(u8, word, sub)) return true;
        }
    }
    return false;
}

/// True iff the token range [start, end] contains:
///   `source_recv . source_field . <acquire_method> (`
fn hasRefAcquireCall(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    source_recv: []const u8,
    source_field: []const u8,
) bool {
    if (start > end) return false;
    // Need at least 5 tokens: recv . field . method (
    if (end < start + 4) return false;
    var t: Ast.TokenIndex = start;
    while (t + 4 <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), source_recv)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), source_field)) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        const method = tree.tokenSlice(t + 4);
        if (method_names.isRefAcquireName(method)) return true;
    }
    return false;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    field_tok: Ast.TokenIndex,
    field: []const u8,
    recv: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "field `.{s}` is copied from `{s}.{s}` without calling `clone()`/`dupeRef()`/`ref()` — if `{s}` is refcounted, both the source and the copy will decrement the refcount on cleanup, potentially causing a double-free or SIGFPE; call `{s}.{s}.clone()` or the appropriate ref-acquire method",
        .{ field, recv, field, field, recv, field },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, field_tok),
        .end = Pos.fromTokenEnd(tree, field_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "ref-counted-copy-without-dupe: .name = other.name fires" {
    try testing.expectFires(check, R,
        \\fn copy(source: anytype) void {
        \\    const result = .{
        \\        .name = source.name,
        \\    };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .handle = other.handle fires" {
    try testing.expectFires(check, R,
        \\fn copy(other: anytype) void {
        \\    const result = .{
        \\        .handle = other.handle,
        \\    };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .name = source.name.clone() does not fire" {
    try testing.expectNoFire(check,
        \\fn copy(source: anytype) void {
        \\    const result = .{
        \\        .name = source.name.clone(),
        \\    };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .count = other.count does not fire" {
    try testing.expectNoFire(check,
        \\fn copy(other: anytype) void {
        \\    const result = .{
        \\        .count = other.count,
        \\    };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .id = other.id does not fire" {
    try testing.expectNoFire(check,
        \\fn copy(other: anytype) void {
        \\    const result = .{
        \\        .id = other.id,
        \\    };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .str = other.str fires" {
    try testing.expectFires(check, R,
        \\fn copy(other: anytype) void {
        \\    const result = .{
        \\        .str = other.str,
        \\    };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .name = source.name.dupeRef() does not fire" {
    try testing.expectNoFire(check,
        \\fn copy(source: anytype) void {
        \\    const result = .{
        \\        .name = source.name.dupeRef(),
        \\    };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .rename = other.rename does not fire (whole-word)" {
    try testing.expectNoFire(check,
        \\fn copy(other: anytype) void {
        \\    const result = .{ .rename = other.rename };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .metadata = other.metadata does not fire (whole-word)" {
    try testing.expectNoFire(check,
        \\fn copy(other: anytype) void {
        \\    const result = .{ .metadata = other.metadata };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .react_fast_refresh = other.react_fast_refresh does not fire" {
    try testing.expectNoFire(check,
        \\fn copy(other: anytype) void {
        \\    const result = .{ .react_fast_refresh = other.react_fast_refresh };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .user_data = other.user_data fires (data is whole word)" {
    try testing.expectFires(check, R,
        \\fn copy(other: anytype) void {
        \\    const result = .{ .user_data = other.user_data };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .user_data_64 = other.user_data_64 does not fire (numeric suffix)" {
    try testing.expectNoFire(check,
        \\fn copy(other: anytype) void {
        \\    const result = .{ .user_data_64 = other.user_data_64 };
        \\    _ = result;
        \\}
        \\
    );
}

test "ref-counted-copy-without-dupe: .user_data_128 = other.user_data_128 does not fire (numeric suffix)" {
    try testing.expectNoFire(check,
        \\fn copy(other: anytype) void {
        \\    const result = .{ .user_data_128 = other.user_data_128 };
        \\    _ = result;
        \\}
        \\
    );
}
