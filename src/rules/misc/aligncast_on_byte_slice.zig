//! Detects `@alignCast(expr.ptr)` — asserting alignment on a raw byte pointer
//! derived from a `[]const u8` or `[]u8` slice.  The alignment of `.ptr` from a
//! byte slice is determined by the allocator, not the element type; for network
//! buffers, file content, or serialised binary data the pointer can land at any
//! byte offset.  The runtime alignment check in `@alignCast` panics in Safe
//! builds when the offset is not a multiple of the target alignment.
//!
//! Real-world instances (all Zig):
//!   - oven-sh/bun#27082 (Postgres binary arrays): `@ptrCast(@alignCast(@constCast(bytes.ptr)))`
//!     on network-received data; panicked non-deterministically on odd-offset packets.
//!   - oven-sh/bun#27281 (sourcemap deserialisation): `@ptrCast(@alignCast(raw.ptr))`
//!     on a memory-mapped file; panicked on unaligned mmap regions.
//!   - oven-sh/bun#27384 (tagged-pointer sockets): `@alignCast(data.ptr)` producing an
//!     assumed-4-byte-aligned pointer into a tagged-pointer arena.
//!   - oven-sh/bun#27290 (HTTP response parsing): `@alignCast(@constCast(bytes.ptr))`.
//!     Fix in all cases: use `std.mem.readInt` / `@memcpy` into a local aligned struct.
//!
//! Detection (Tier 1, flat token walk):
//!   Form A: `@alignCast ( identifier . identifier("ptr") )` — 6 tokens
//!   Form B: `@alignCast ( @constCast ( identifier . identifier("ptr") ) )` — 9 tokens
//!   Fire at the `@alignCast` builtin token.
//!   `@alignCast(align1_ptr)` on explicitly `align(1)` pointers (common in readInt
//!   helpers) would also fire — acceptable since those should use `align(1)` casts
//!   without `@alignCast`, which is the safe idiom.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "aligncast-on-byte-slice";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .aligncast_on_byte_slice)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 5 <= last_tok) : (t += 1) {
        if (tags[t] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "@alignCast")) continue;
        if (tags[t + 1] != .l_paren) continue;

        // Form A: @alignCast ( identifier . identifier("ptr") )
        if (tags[t + 2] == .identifier and
            tags[t + 3] == .period and
            tags[t + 4] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t + 4), "ptr") and
            tags[t + 5] == .r_paren)
        {
            // Suppress when the receiver was declared with an explicit alignment
            // annotation (`recv: []align(N) u8`) or via `alignedAlloc` — in those
            // cases the alignment is guaranteed by construction and the @alignCast
            // assertion is always safe.
            if (!receiverHasUnknownAlignment(tree, tags, t, tree.tokenSlice(t + 2)))
                continue;
            try report(gpa, problems, tree, t, t + 5);
            continue;
        }

        // Form B: @alignCast ( @constCast ( identifier . identifier("ptr") ) )
        if (t + 8 <= last_tok and
            tags[t + 2] == .builtin and
            std.mem.eql(u8, tree.tokenSlice(t + 2), "@constCast") and
            tags[t + 3] == .l_paren and
            tags[t + 4] == .identifier and
            tags[t + 5] == .period and
            tags[t + 6] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t + 6), "ptr") and
            tags[t + 7] == .r_paren and
            tags[t + 8] == .r_paren)
        {
            if (!receiverHasUnknownAlignment(tree, tags, t, tree.tokenSlice(t + 4)))
                continue;
            try report(gpa, problems, tree, t, t + 8);
            continue;
        }
    }
}

/// Returns true (fire) when the receiver's alignment is UNKNOWN (the common
/// unsafe case), false (suppress) when the receiver is explicitly aligned:
///   - Parameter with `align(N)` type annotation: `recv: []align(N) u8`
///   - Local variable from `alignedAlloc(...)` or similar
/// Scans backward 300 tokens, finds the first non-field-access declaration
/// of `recv_name`, then checks the 20 tokens after it for `keyword_align`
/// or an identifier containing "alignedalloc" (case-insensitive).
fn receiverHasUnknownAlignment(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    anchor: Ast.TokenIndex,
    recv_name: []const u8,
) bool {
    const back: Ast.TokenIndex = 300;
    const start: Ast.TokenIndex = if (anchor >= back) anchor - back else 0;

    var k = start;
    while (k < anchor) : (k += 1) {
        if (tags[k] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k), recv_name)) continue;
        if (k > 0 and tags[k - 1] == .period) continue; // field access, skip

        // Check 20 tokens after the receiver name for alignment signals.
        const check_end = @min(k + 20, anchor);
        var j = k + 1;
        while (j < check_end) : (j += 1) {
            if (tags[j] == .keyword_align) return false; // explicit alignment
            if (tags[j] == .identifier) {
                const s = tree.tokenSlice(j);
                if (std.ascii.indexOfIgnoreCase(s, "alignedalloc") != null or
                    std.ascii.indexOfIgnoreCase(s, "alignalloc") != null)
                    return false; // alignedAlloc call in RHS
            }
        }
    }
    return true; // no alignment guarantee found → unknown alignment
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    start_tok: Ast.TokenIndex,
    end_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@alignCast(expr.ptr)` — asserting alignment on a raw byte-slice pointer is unsafe; for network/file/serialised data the pointer offset is arbitrary and the runtime check panics when misaligned; use `std.mem.readInt` or copy into a local aligned struct with `@memcpy` instead",
        .{},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, start_tok),
        .end = Pos.fromTokenEnd(tree, end_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "aligncast-on-byte-slice: form A fires" {
    try testing.expectFires(check, R,
        \\fn parseHeader(bytes: []const u8) *Header {
        \\    return @alignCast(bytes.ptr);
        \\}
        \\
    );
}

test "aligncast-on-byte-slice: form B fires" {
    try testing.expectFires(check, R,
        \\fn parseHeader(bytes: []const u8) *Header {
        \\    return @alignCast(@constCast(bytes.ptr));
        \\}
        \\
    );
}

test "aligncast-on-byte-slice: alignCast on plain identifier does not fire" {
    try testing.expectNoFire(check,
        \\fn cast(p: *anyopaque) *Header {
        \\    return @alignCast(p);
        \\}
        \\
    );
}

test "aligncast-on-byte-slice: alignCast on field (non-ptr) does not fire" {
    try testing.expectNoFire(check,
        \\fn cast(s: SomeStruct) *Header {
        \\    return @alignCast(s.data);
        \\}
        \\
    );
}

test "aligncast-on-byte-slice: explicit align param suppressed" {
    try testing.expectNoFire(check,
        \\pub fn free(mem: []align(std.heap.page_size_min) u8) void {
        \\    windows.VirtualFree(@ptrCast(@alignCast(mem.ptr)), 0, windows.MEM_RELEASE);
        \\}
        \\
    );
}

test "aligncast-on-byte-slice: alignedAlloc receiver suppressed" {
    try testing.expectNoFire(check,
        \\fn makeHeader(alloc: Allocator) !*Header {
        \\    const buf = try alloc.alignedAlloc(u8, .of(Header), @sizeOf(Header));
        \\    const h: *Header = @ptrCast(@alignCast(buf.ptr));
        \\    return h;
        \\}
        \\
    );
}

test "aligncast-on-byte-slice: unaligned alloc still fires" {
    try testing.expectFires(check, R,
        \\fn makeHeader(alloc: Allocator) !*Header {
        \\    const buf = try alloc.alloc(u8, @sizeOf(Header));
        \\    return @alignCast(buf.ptr);
        \\}
        \\
    );
}
