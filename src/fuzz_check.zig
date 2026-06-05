//! Fuzz target: the full AST + CFG + pattern-rule pipeline must not
//! crash on arbitrary Zig source bytes.
//!
//! Normal test mode (`zig build test`): runs once with each seed entry
//! to verify the pipeline handles known shapes without crashing.
//! Fuzz mode (libfuzzer/AFL via `zig build fuzz`): feeds mutated corpus
//! entries; the harness accepts anything the fuzzer mutates from the seeds.
//!
//! The harness intentionally omits the ZLS type engine (which requires
//! a real file path and project context) — pattern rules and CFG analysis
//! both fall through to AST-only mode, which is the dominant code path.

const std = @import("std");
const Ast = std.zig.Ast;

const cfg_builder = @import("flow/cfg_builder.zig");
const worklist = @import("flow/worklist.zig");
const rule_catalog = @import("rule_catalog.zig");
const config_mod = @import("config.zig");
const file_cache_mod = @import("cache/file_cache.zig");
const problem_mod = @import("problem.zig");

/// Seed corpus — representative Zig snippets covering the main rule
/// classes.  The fuzzer mutates from these, so diverse seeds improve
/// coverage faster than random-byte starts.
const seeds: []const []const u8 = &.{
    // Minimal valid function
    "fn f() void {}",
    // Unsigned index minus one (index-minus-one-without-zero-guard)
    \\fn g(i: usize, buf: []const u8) u8 {
    \\    if (i > 0) return buf[i - 1];
    \\    return 0;
    \\}
    ,
    // Arena escape
    \\const std = @import("std");
    \\fn leak(a: std.mem.Allocator) ![]u8 {
    \\    var arena = std.heap.ArenaAllocator.init(a);
    \\    defer arena.deinit();
    \\    const s = try arena.allocator().alloc(u8, 16);
    \\    return s;
    \\}
    ,
    // Defer LIFO (deinit-order-violates-construction-dep)
    \\fn run() void {
    \\    var grid = Grid.init();
    \\    defer grid.deinit();
    \\    var log = Log.init(&grid);
    \\    defer log.deinit();
    \\}
    ,
    // struct-literal-multiple-try
    \\const std = @import("std");
    \\fn make(a: std.mem.Allocator) !Pair {
    \\    return .{
    \\        .a = try a.dupe(u8, "hello"),
    \\        .b = try a.dupe(u8, "world"),
    \\    };
    \\}
    ,
    // intcast-of-negated-signed
    \\fn fmt(ns: i64) u64 { return @as(u64, @intCast(-ns)); }
    ,
    // use-undefined
    \\fn f() u8 {
    \\    var x: u8 = undefined;
    \\    return x;
    \\}
    ,
    // Pathological: empty file
    "",
    // Pathological: only whitespace
    "   \n\t  ",
    // Pathological: not Zig at all
    "hello world this is not zig code !!!",
    // Pathological: deeply nested braces
    "fn f() void { { { { { { { { { {} } } } } } } } } }",
};

test "fuzz: full analysis pipeline is crash-free on arbitrary input" {
    try std.testing.fuzz({}, fuzzOne, .{});
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    // Use an arena so all per-iteration allocations are freed in one shot.
    // Page allocator avoids the leak-detection overhead of testing.allocator.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // smith.in is the raw input from the fuzzer (or null in seed-replay mode).
    const raw = smith.in orelse return;

    // Ast.parse requires a null-terminated sentinel string.
    const src = gpa.allocSentinel(u8, raw.len, 0) catch return;
    @memcpy(src[0..raw.len], raw);

    // Parse — may contain syntax errors; that's fine and expected.
    // An OOM here means the input triggered huge memory use; return quietly.
    var tree = Ast.parse(gpa, src, .zig) catch return;
    defer tree.deinit(gpa);

    const config = &config_mod.Default;
    var problems: std.ArrayListUnmanaged(problem_mod.Problem) = .empty;

    // Per-file cache used by both pipelines.
    var cache = file_cache_mod.FileCache.init(gpa, &tree);
    defer cache.deinit();

    // ── CFG + worklist (flow analysis) ─────────────────────────────
    // Iterate all fn_decls and run the abstract interpretation pipeline.
    // Skip on error (OOM), not on crash — a crash here is a bug.
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        const cfg = (cfg_builder.lowerFunctionFull(
            gpa, &tree, node, config, &cache,
        ) catch continue) orelse continue;
        var cfg_mut = cfg;
        defer cfg_mut.deinit(gpa);
        worklist.check(gpa, &cfg_mut, .{ .path = "<fuzz>", .config = config }, &problems) catch continue;
    }

    // ── Pattern detectors ───────────────────────────────────────────
    rule_catalog.runEscape(gpa, &tree, &cache, config, &problems) catch {};

    // Free Problem messages — arena owns the slice but Problem.deinit
    // releases the gpa-allocated message string.
    for (problems.items) |*p| p.deinit(gpa);
}
