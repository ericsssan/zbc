//! zbc CLI — thin shell over the lib.zig library API.
//! Walks the .zig files passed on argv, runs the requested analysis
//! mode, prints any Problems found in a grep-friendly format, and
//! exits 0 if all-clean / 1 if any problems.
//!
//! Usage:
//!   zbc [options] <file.zig>...
//!
//! Options:
//!   --escape             Layer-2 escape analysis (default: Layer-1
//!                        annotation hygiene only).
//!   --enable=<list>      Comma-separated invariant names to enable
//!                        (e.g. --enable=ast_identity,arena_escape).
//!                        Default is all invariants.  Implies --escape.
//!   --disable=<list>     Comma-separated invariant names to disable.
//!                        Subtracted from the enabled set.
//!   --list-invariants    Print known invariant names and exit 0.
//!   -h / --help          Print usage and exit 0.

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
    var enabled: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer enabled.deinit(gpa);
    try enabled.appendSlice(gpa, &lib.all_invariants);
    var escape_mode = false;
    var enabled_explicit = false;

    while (arg_it.next()) |a| {
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            printUsage();
            std.process.exit(0);
        }
        if (std.mem.eql(u8, a, "--list-invariants")) {
            inline for (@typeInfo(lib.Invariant).@"enum".fields) |f| {
                std.debug.print("{s}\n", .{f.name});
            }
            std.process.exit(0);
        }
        if (std.mem.eql(u8, a, "--escape")) {
            escape_mode = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--enable=")) {
            if (!enabled_explicit) {
                enabled.clearRetainingCapacity();
                enabled_explicit = true;
            }
            escape_mode = true; // invariants only matter in escape mode
            try parseInvariantList(gpa, a["--enable=".len..], &enabled, .add);
            continue;
        }
        if (std.mem.startsWith(u8, a, "--disable=")) {
            try parseInvariantList(gpa, a["--disable=".len..], &enabled, .remove);
            continue;
        }
        if (std.mem.startsWith(u8, a, "--")) {
            std.debug.print("zbc: unknown flag: {s}\n", .{a});
            printUsage();
            std.process.exit(2);
        }
        try paths.append(gpa, a);
    }

    if (paths.items.len == 0) {
        printUsage();
        std.process.exit(2);
    }

    const config: lib.Config = .{ .enabled = enabled.items };

    var cache_storage: ?lib.Cache = if (escape_mode) lib.Cache.init(gpa, io) else null;
    defer if (cache_storage) |*c| c.deinit();

    var any_problems = false;
    for (paths.items) |path| {
        const problems = if (escape_mode)
            lib.analyzeEscape(gpa, io, path, &cache_storage.?, &config) catch |err| {
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

const Op = enum { add, remove };

fn parseInvariantList(
    gpa: std.mem.Allocator,
    csv: []const u8,
    list: *std.ArrayListUnmanaged(lib.Invariant),
    op: Op,
) !void {
    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |raw| {
        const name = std.mem.trim(u8, raw, " \t");
        if (name.len == 0) continue;
        const inv = lib.invariantFromName(name) orelse {
            std.debug.print("zbc: unknown invariant `{s}`; --list-invariants for valid names\n", .{name});
            std.process.exit(2);
        };
        switch (op) {
            .add => {
                if (!containsInvariant(list.items, inv)) try list.append(gpa, inv);
            },
            .remove => {
                var i: usize = 0;
                while (i < list.items.len) {
                    if (list.items[i] == inv) {
                        _ = list.orderedRemove(i);
                    } else i += 1;
                }
            },
        }
    }
}

fn containsInvariant(slice: []const lib.Invariant, inv: lib.Invariant) bool {
    for (slice) |e| if (e == inv) return true;
    return false;
}

fn printUsage() void {
    std.debug.print(
        \\usage: zbc [options] <file.zig>...
        \\
        \\options:
        \\  --escape              Run Layer-2 escape analysis (default: Layer-1 only).
        \\  --enable=a,b,c        Enable only these invariants (implies --escape).
        \\  --disable=a,b         Disable these invariants from the enabled set.
        \\  --list-invariants     Print known invariant names and exit.
        \\  -h, --help            Print this help.
        \\
    , .{});
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

// ── Tests ──────────────────────────────────────────────────

test "parseInvariantList: add single" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer list.deinit(gpa);
    try parseInvariantList(gpa, "ast_identity", &list, .add);
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(lib.Invariant.ast_identity, list.items[0]);
}

test "parseInvariantList: add multiple, dedupes" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer list.deinit(gpa);
    try parseInvariantList(gpa, "arena_escape,ast_mutation,arena_escape", &list, .add);
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
}

test "parseInvariantList: remove from a set" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer list.deinit(gpa);
    try list.appendSlice(gpa, &lib.all_invariants);
    try parseInvariantList(gpa, "thread_arena,pass_identity", &list, .remove);
    try std.testing.expectEqual(@as(usize, 3), list.items.len);
    try std.testing.expect(!containsInvariant(list.items, .thread_arena));
    try std.testing.expect(!containsInvariant(list.items, .pass_identity));
}

test "parseInvariantList: whitespace tolerated" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer list.deinit(gpa);
    try parseInvariantList(gpa, "  ast_identity ,  arena_escape  ", &list, .add);
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
}

test {
    _ = lib;
    std.testing.refAllDecls(@This());
}
