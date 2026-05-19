//! ez-borrow-check — Layer 1 lint runner.
//!
//! Walks the .zig files passed on the CLI, runs the Layer-1 annotation-
//! hygiene rules on each, prints problems in a grep-friendly format.
//!
//! Exits 0 if no problems, 1 if any rule reported.
//!
//! Usage:
//!   zig run tools/ez-borrow-check/main.zig -- src/parser/ast.zig src/linter/lint_context.zig

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("problem.zig");
const require_borrowed_from = @import("rules/require_borrowed_from.zig");
const require_node_index_origin = @import("rules/require_node_index_origin.zig");
const require_arena_kill_tag = @import("rules/require_arena_kill_tag.zig");

// Layer 2 — pulled in via test entry so its tests run when we
// `zig test main.zig`.  Not yet wired into the CLI default; can be
// invoked via `--escape-check` flag (week 5 will polish UX).
const _layer2_cfg = @import("cfg.zig");
const _layer2_abstract_state = @import("abstract_state.zig");
const _layer2_transfer = @import("transfer.zig");
const _layer2_analyzer = @import("analyzer.zig");

const Problem = problem_mod.Problem;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arg_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer arg_it.deinit();
    _ = arg_it.next(); // argv[0]
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    defer paths.deinit(gpa);
    while (arg_it.next()) |a| try paths.append(gpa, a);

    if (paths.items.len == 0) {
        std.debug.print("usage: ez-borrow-check <file.zig>...\n", .{});
        std.process.exit(2);
    }

    var any_problems = false;
    for (paths.items) |path| {
        const had = try checkFile(gpa, io, path);
        any_problems = any_problems or had;
    }

    std.process.exit(if (any_problems) @as(u8, 1) else 0);
}

fn checkFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !bool {
    const src_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        std.Io.Limit.limited(16 * 1024 * 1024),
    ) catch |err| {
        std.debug.print("ez-borrow-check: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return true;
    };
    defer gpa.free(src_bytes);

    // Ast.parse needs a null-terminated source.
    const src = try gpa.allocSentinel(u8, src_bytes.len, 0);
    defer gpa.free(src);
    @memcpy(src[0..src_bytes.len], src_bytes);

    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    defer {
        for (problems.items) |*p| p.deinit(gpa);
        problems.deinit(gpa);
    }

    try require_borrowed_from.check(gpa, &tree, .{}, &problems);
    try require_node_index_origin.check(gpa, &tree, .{}, &problems);
    try require_arena_kill_tag.check(gpa, &tree, .{}, &problems);

    if (problems.items.len == 0) return false;

    for (problems.items) |p| {
        std.debug.print("{s}:{}:{}: {s}: {s} [{s}]\n", .{
            path,
            p.start.line,
            p.start.column,
            switch (p.severity) {
                .@"error" => "error",
                .warning => "warning",
                .off => "off",
            },
            p.message,
            p.rule_id,
        });
    }
    return true;
}

test {
    // refAllDecls doesn't recurse; explicitly pull in submodules so
    // `zig test main.zig` runs every rule's + every layer's tests.
    _ = require_borrowed_from;
    _ = require_node_index_origin;
    _ = require_arena_kill_tag;
    _ = _layer2_cfg;
    _ = _layer2_abstract_state;
    _ = _layer2_transfer;
    _ = _layer2_analyzer;
    std.testing.refAllDecls(@This());
}
