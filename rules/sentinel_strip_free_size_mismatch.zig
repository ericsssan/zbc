//! Sentinel-strip-free-size-mismatch detector — `<alloc>.free(
//! <X>.ptr[0..<X>.len])` (or `<X>.ptr.?[0..<X>.len]`) hand-rolls
//! a `[]u8` slice from a many-item-pointer and slices it to
//! `<X>.len`.  If `<X>` is a sentinel-terminated slice
//! (`[:0]const u8` produced by `dupeZ`, `allocSentinel`, string
//! literals, etc.) the underlying allocation is `len + 1` bytes
//! — but the freed slice is only `len` bytes.  The allocator's
//! free-size check trips with `Allocation size N+1 does not
//! match free size N`.
//!
//! Even when there's no sentinel, the shape is redundant — you
//! should just pass `<X>` to `free` directly.  Either
//! interpretation is a bug.
//!
//! Real-world: ghostty-org/ghostty#8886
//! (`ghostty_string_free` in src/main_c.zig).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Find `.free(` calls preceded by `.` (allocator method).
//!   3. Match the single argument against the pattern
//!      `<X> . ptr (.?)? [ <expr> . . <X> . len ]`.
//!   4. Fire on the `.free` call.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");

const lexer = @import("../lexer.zig");
const query = @import("../query.zig");
const testing = @import("../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const Atom = query.Atom;

// `.free(<X>.ptr (.?)? [<lo>..<X>.len])` — the sentinel-strip shape.
// $0 captures X (the slice's binding name) so the trailing `<X>.len`
// is matched as the SAME identifier via ref.  The `<lo>` expression
// between `[` and `..` is captured via range slot 0 (skipped).
const sentinel_strip = &[_]Atom{
    .{ .tok = .period },
    .{ .text = "free" },
    .{ .tok = .l_paren },
    .{ .capture = 0 },
    .{ .tok = .period },
    .{ .text = "ptr" },
    .{ .opt = &[_]Atom{ .{ .tok = .period }, .{ .tok = .question_mark } } },
    .{ .tok = .l_bracket },
    .{ .capture_until = .{ .slot = 0, .stops = &.{.ellipsis2} } },
    .{ .tok = .ellipsis2 },
    .{ .ref = 0 },
    .{ .tok = .period },
    .{ .text = "len" },
    .{ .tok = .r_bracket },
    .{ .tok = .r_paren },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .sentinel_strip_free_size_mismatch)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkBody(gpa, tree, fn_entry.body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    const matches = try query.findAllInBody(gpa, tree, sentinel_strip, first, last);
    defer gpa.free(matches);
    for (matches) |m| {
        // Report at the `.free` method token (m.start is the leading `.`;
        // m.start + 1 is `free`).
        try report(gpa, problems, tree, m.start + 1);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    free_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`<alloc>.free(<X>.ptr[0..<X>.len])` hand-rolls a non-sentinel slice from a many-item-pointer.  If `<X>` is `[:0]const u8` or another sentinel-terminated slice, the underlying allocation is len+1 bytes — the allocator's free-size check trips.  Either pass `<X>` directly to `free`, or include the sentinel: `<alloc>.free(<X>.ptr.?[0..<X>.len :0])`",
        .{},
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "sentinel-strip-free-size-mismatch",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, free_tok),
        .end = Pos.fromTokenEnd(tree, free_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "sentinel-strip-free-size-mismatch: ghostty_string_free pattern fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Str = struct { ptr: ?[*]const u8, len: usize };
        \\pub fn ghostty_string_free(str: Str, alloc: std.mem.Allocator) void {
        \\    alloc.free(str.ptr.?[0..str.len]);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("sentinel-strip-free-size-mismatch", problems.items[0].rule_id);
}

test "sentinel-strip-free-size-mismatch: bare .ptr[0..len] variant also fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Str = struct { ptr: [*]u8, len: usize };
        \\pub fn release(str: Str, alloc: std.mem.Allocator) void {
        \\    alloc.free(str.ptr[0..str.len]);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "sentinel-strip-free-size-mismatch: alloc.free(slice) directly doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn release(slice: []u8, alloc: std.mem.Allocator) void {
        \\    alloc.free(slice);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "sentinel-strip-free-size-mismatch: alloc.free(slice[0..N]) doesn't fire (not .ptr-based)" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn release(slice: []u8, alloc: std.mem.Allocator) void {
        \\    alloc.free(slice[0..10]);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
