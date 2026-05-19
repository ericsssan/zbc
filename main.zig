//! zbc CLI — thin shell over the lib.zig library API.
//! Walks the .zig files passed on argv, runs the requested analysis
//! mode, prints any Problems found in a grep-friendly format, and
//! exits 0 if all-clean / 1 if any problems.
//!
//! Modes:
//!   default     Layer-1 annotation hygiene (require_* rules)
//!   --escape    Layer-2 escape analysis with cross-file resolution
//!
//! Usage:
//!   zig run main.zig -- [--escape] <file.zig>...

const std = @import("std");
const lib = @import("lib.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arg_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer arg_it.deinit();
    _ = arg_it.next(); // argv[0]
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    defer paths.deinit(gpa);
    var escape_mode = false;
    while (arg_it.next()) |a| {
        if (std.mem.eql(u8, a, "--escape")) {
            escape_mode = true;
            continue;
        }
        try paths.append(gpa, a);
    }

    if (paths.items.len == 0) {
        std.debug.print("usage: zbc [--escape] <file.zig>...\n", .{});
        std.process.exit(2);
    }

    // Sweep-wide remote-resolver cache, only needed in escape mode.
    var cache_storage: ?lib.Cache = if (escape_mode) lib.Cache.init(gpa, io) else null;
    defer if (cache_storage) |*c| c.deinit();

    var any_problems = false;
    for (paths.items) |path| {
        const problems = if (escape_mode)
            lib.analyzeEscape(gpa, io, path, &cache_storage.?, &lib.DefaultConfig) catch |err| {
                std.debug.print("zbc: cannot analyze {s}: {s}\n", .{ path, @errorName(err) });
                any_problems = true;
                continue;
            }
        else
            lib.analyzeHygiene(gpa, io, path) catch |err| {
                std.debug.print("zbc: cannot analyze {s}: {s}\n", .{ path, @errorName(err) });
                any_problems = true;
                continue;
            };
        defer lib.freeProblems(gpa, problems);

        if (problems.len == 0) continue;
        any_problems = true;
        printProblems(path, problems);
    }

    std.process.exit(if (any_problems) @as(u8, 1) else 0);
}

fn printProblems(path: []const u8, problems: []const lib.Problem) void {
    for (problems) |p| {
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
}

test {
    _ = lib;
    std.testing.refAllDecls(@This());
}
