//! zbc CLI — thin shell over the lib.zig library API.
//! Walks the .zig files passed on argv, runs the requested analysis
//! mode, prints any Problems found in a grep-friendly format, and
//! exits 0 if all-clean / 1 if any problems.
//!
//! Usage:
//!   zbc [options] <file.zig>...
//!
//! Default mode is escape analysis — drop-in: run zbc on any Zig
//! source and signature-driven inference fills in the annotations
//! needed for invariant checks (see lib.zig for the rules).
//!
//! Options:
//!   --hygiene            Run Layer-1 annotation-presence rules
//!                        instead of escape analysis.
//!   --enable=<list>      Comma-separated invariant names to enable.
//!   --disable=<list>     Comma-separated invariant names to disable.
//!   --arena-init=<csv>   Source-text patterns that mint a fresh
//!                        arena (default: ArenaAllocator.init).
//!   --arena-kill=<csv>   Source-text patterns that kill the receiver
//!                        arena (default: .deinit().
//!   --format=text|json   Output format (default: text).
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
    var mode: Mode = .escape;
    var enabled_explicit = false;
    var format: Format = .text;

    var arena_init_patterns: []const []const u8 = lib.DefaultConfig.arena_init_patterns;
    var arena_kill_patterns: []const []const u8 = lib.DefaultConfig.arena_kill_patterns;
    var pattern_allocations: std.ArrayListUnmanaged([]const []const u8) = .empty;
    defer {
        for (pattern_allocations.items) |slice| gpa.free(slice);
        pattern_allocations.deinit(gpa);
    }

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
        if (std.mem.eql(u8, a, "--hygiene")) {
            mode = .hygiene;
            continue;
        }
        if (std.mem.eql(u8, a, "--escape")) {
            mode = .escape;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--enable=")) {
            if (!enabled_explicit) {
                enabled.clearRetainingCapacity();
                enabled_explicit = true;
            }
            try parseInvariantList(gpa, a["--enable=".len..], &enabled, .add);
            continue;
        }
        if (std.mem.startsWith(u8, a, "--disable=")) {
            try parseInvariantList(gpa, a["--disable=".len..], &enabled, .remove);
            continue;
        }
        if (std.mem.startsWith(u8, a, "--arena-init=")) {
            const slice = try splitCsv(gpa, a["--arena-init=".len..]);
            try pattern_allocations.append(gpa, slice);
            arena_init_patterns = slice;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--arena-kill=")) {
            const slice = try splitCsv(gpa, a["--arena-kill=".len..]);
            try pattern_allocations.append(gpa, slice);
            arena_kill_patterns = slice;
            continue;
        }
        if (std.mem.startsWith(u8, a, "--format=")) {
            const v = a["--format=".len..];
            if (std.mem.eql(u8, v, "text")) {
                format = .text;
            } else if (std.mem.eql(u8, v, "json")) {
                format = .json;
            } else {
                std.debug.print("zbc: unknown format `{s}` (expected text or json)\n", .{v});
                std.process.exit(2);
            }
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

    var expanded: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (expanded.items) |p| gpa.free(p);
        expanded.deinit(gpa);
    }
    for (paths.items) |p| {
        expandPath(gpa, io, p, &expanded) catch |err| {
            std.debug.print("zbc: cannot expand {s}: {s}\n", .{ p, @errorName(err) });
            std.process.exit(2);
        };
    }
    if (expanded.items.len == 0) {
        std.debug.print("zbc: no .zig files found in: {s}\n", .{paths.items[0]});
        std.process.exit(0);
    }

    const config: lib.Config = .{
        .arena_init_patterns = arena_init_patterns,
        .arena_kill_patterns = arena_kill_patterns,
        .enabled = enabled.items,
    };

    var shared_cache: ?lib.Cache = if (mode == .escape) lib.Cache.init(gpa, io) else null;
    defer if (shared_cache) |*c| c.deinit();

    const tasks = try gpa.alloc(Task, expanded.items.len);
    defer gpa.free(tasks);
    for (expanded.items, tasks) |path, *t| {
        t.* = .{
            .gpa = gpa,
            .io = io,
            .path = path,
            .mode = mode,
            .config = &config,
            .cache = if (shared_cache) |*c| c else null,
            .problems = &.{},
            .err = null,
        };
    }

    var group: std.Io.Group = .init;
    for (tasks) |*t| {
        group.concurrent(io, runOne, .{t}) catch
            group.async(io, runOne, .{t});
    }
    group.await(io) catch {};

    var all_problems: std.ArrayListUnmanaged(IndexedProblem) = .empty;
    defer all_problems.deinit(gpa);
    var any_problems = false;
    for (tasks) |*t| {
        if (t.err) |err| {
            std.debug.print("zbc: cannot analyze {s}: {s}\n", .{ t.path, @errorName(err) });
            any_problems = true;
            continue;
        }
        for (t.problems) |p| {
            try all_problems.append(gpa, .{ .path = t.path, .problem = p });
        }
    }
    defer for (tasks) |*t| if (t.problems.len > 0) gpa.free(t.problems);
    defer for (all_problems.items) |*ip| ip.problem.deinit(gpa);

    std.mem.sort(IndexedProblem, all_problems.items, {}, indexedProblemLess);

    if (all_problems.items.len > 0) any_problems = true;
    if (format == .json) {
        std.debug.print("[", .{});
        var first = true;
        for (all_problems.items) |ip| {
            printOneProblemJson(ip.path, ip.problem, &first);
        }
        std.debug.print("{s}]\n", .{if (first) "" else "\n"});
    } else {
        for (all_problems.items) |ip| {
            printOneProblemText(ip.path, ip.problem);
        }
    }
    std.process.exit(if (any_problems) @as(u8, 1) else 0);
}

fn splitCsv(gpa: std.mem.Allocator, csv: []const u8) ![]const []const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer out.deinit(gpa);
    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (trimmed.len == 0) continue;
        try out.append(gpa, trimmed);
    }
    return out.toOwnedSlice(gpa);
}

fn expandPath(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch {
        const duped = try gpa.dupe(u8, path);
        errdefer gpa.free(duped);
        try out.append(gpa, duped);
        return;
    };
    defer dir.close(io);

    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        if (std.mem.indexOf(u8, entry.path, "/.") != null) continue;
        if (std.mem.startsWith(u8, entry.path, ".")) continue;

        const full = try std.fs.path.join(gpa, &.{ path, entry.path });
        errdefer gpa.free(full);
        try out.append(gpa, full);
    }
}

const Mode = enum { escape, hygiene };
const Format = enum { text, json };
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
        \\Default mode is escape analysis — flags slices borrowed from a
        \\function-local arena that are returned past the arena's death.
        \\
        \\options:
        \\  --hygiene             Run annotation-presence rules instead.
        \\  --enable=a,b,c        Enable only these invariants.
        \\  --disable=a,b         Disable these invariants from the set.
        \\  --arena-init=A,B      Patterns that mint a fresh arena
        \\                        (default: ArenaAllocator.init).
        \\  --arena-kill=A,B      Patterns that kill the receiver arena
        \\                        (default: .deinit().
        \\  --format=text|json    Output format (default: text).
        \\  --list-invariants     Print known invariant names and exit.
        \\  -h, --help            Print this help.
        \\
    , .{});
}

const Task = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    mode: Mode,
    config: *const lib.Config,
    cache: ?*lib.Cache,
    problems: []lib.Problem,
    err: ?anyerror,
};

const IndexedProblem = struct {
    path: []const u8,
    problem: lib.Problem,
};

fn indexedProblemLess(_: void, a: IndexedProblem, b: IndexedProblem) bool {
    const path_cmp = std.mem.order(u8, a.path, b.path);
    if (path_cmp != .eq) return path_cmp == .lt;
    if (a.problem.start.line != b.problem.start.line)
        return a.problem.start.line < b.problem.start.line;
    return a.problem.start.column < b.problem.start.column;
}

fn runOne(t: *Task) std.Io.Cancelable!void {
    const problems = if (t.mode == .escape)
        lib.analyzeEscape(t.gpa, t.io, t.path, t.cache.?, t.config) catch |err| {
            t.err = err;
            return;
        }
    else
        lib.analyzeHygiene(t.gpa, t.io, t.path) catch |err| {
            t.err = err;
            return;
        };
    t.problems = problems;
}

fn printOneProblemText(path: []const u8, p: lib.Problem) void {
    std.debug.print("{s}:{}:{}: {s}: {s} [{s}]\n", .{
        path,
        p.start.line,
        p.start.column,
        severityName(p.severity),
        p.message,
        p.rule_id,
    });
}

fn printOneProblemJson(path: []const u8, p: lib.Problem, first: *bool) void {
    if (first.*) {
        std.debug.print("\n  ", .{});
        first.* = false;
    } else {
        std.debug.print(",\n  ", .{});
    }
    std.debug.print("{{\"path\":\"", .{});
    writeJsonEscaped(path);
    std.debug.print(
        "\",\"rule_id\":\"{s}\",\"severity\":\"{s}\"," ++
            "\"start\":{{\"line\":{},\"column\":{},\"byte\":{}}}," ++
            "\"end\":{{\"line\":{},\"column\":{},\"byte\":{}}}," ++
            "\"message\":\"",
        .{
            p.rule_id,
            severityName(p.severity),
            p.start.line, p.start.column, p.start.byte,
            p.end.line,   p.end.column,   p.end.byte,
        },
    );
    writeJsonEscaped(p.message);
    std.debug.print("\"}}", .{});
}

fn severityName(s: lib.Severity) []const u8 {
    return switch (s) {
        .@"error" => "error",
        .warning => "warning",
        .off => "off",
    };
}

fn writeJsonEscaped(s: []const u8) void {
    for (s) |c| {
        switch (c) {
            '"' => std.debug.print("\\\"", .{}),
            '\\' => std.debug.print("\\\\", .{}),
            '\n' => std.debug.print("\\n", .{}),
            '\r' => std.debug.print("\\r", .{}),
            '\t' => std.debug.print("\\t", .{}),
            0...0x08, 0x0b, 0x0c, 0x0e...0x1f => std.debug.print("\\u{x:0>4}", .{c}),
            else => std.debug.print("{c}", .{c}),
        }
    }
}

fn jsonEscapeToBuf(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer list.deinit(gpa);
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(gpa, "\\\""),
            '\\' => try list.appendSlice(gpa, "\\\\"),
            '\n' => try list.appendSlice(gpa, "\\n"),
            '\r' => try list.appendSlice(gpa, "\\r"),
            '\t' => try list.appendSlice(gpa, "\\t"),
            0...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                var buf: [6]u8 = undefined;
                const hex = try std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c});
                try list.appendSlice(gpa, hex);
            },
            else => try list.append(gpa, c),
        }
    }
    return list.toOwnedSlice(gpa);
}

// ── Tests ──────────────────────────────────────────────────

test "parseInvariantList: add single" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer list.deinit(gpa);
    try parseInvariantList(gpa, "arena_escape", &list, .add);
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(lib.Invariant.arena_escape, list.items[0]);
}

test "parseInvariantList: add dedupes" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer list.deinit(gpa);
    try parseInvariantList(gpa, "arena_escape,arena_escape", &list, .add);
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
}

test "parseInvariantList: remove from a set" {
    const gpa = std.testing.allocator;
    var list: std.ArrayListUnmanaged(lib.Invariant) = .empty;
    defer list.deinit(gpa);
    try list.appendSlice(gpa, &lib.all_invariants);
    try parseInvariantList(gpa, "arena_escape", &list, .remove);
    try std.testing.expect(!containsInvariant(list.items, .arena_escape));
}

test "splitCsv: basic comma-separated" {
    const gpa = std.testing.allocator;
    const out = try splitCsv(gpa, "a,b,c");
    defer gpa.free(out);
    try std.testing.expectEqual(@as(usize, 3), out.len);
    try std.testing.expectEqualStrings("a", out[0]);
    try std.testing.expectEqualStrings("c", out[2]);
}

test "splitCsv: trims whitespace, drops empties" {
    const gpa = std.testing.allocator;
    const out = try splitCsv(gpa, "  Foo.parse , , Bar.make ,");
    defer gpa.free(out);
    try std.testing.expectEqual(@as(usize, 2), out.len);
    try std.testing.expectEqualStrings("Foo.parse", out[0]);
    try std.testing.expectEqualStrings("Bar.make", out[1]);
}

test "jsonEscapeToBuf: passes ASCII through unchanged" {
    const gpa = std.testing.allocator;
    const s = try jsonEscapeToBuf(gpa, "hello, world (idx=42)");
    defer gpa.free(s);
    try std.testing.expectEqualStrings("hello, world (idx=42)", s);
}

test "jsonEscapeToBuf: escapes quote, backslash, common control chars" {
    const gpa = std.testing.allocator;
    const s = try jsonEscapeToBuf(gpa, "a\"b\\c\nd\te");
    defer gpa.free(s);
    try std.testing.expectEqualStrings("a\\\"b\\\\c\\nd\\te", s);
}

test "jsonEscapeToBuf: low control bytes become \\uXXXX" {
    const gpa = std.testing.allocator;
    const s = try jsonEscapeToBuf(gpa, &[_]u8{ 'x', 0x01, 'y', 0x1f, 'z' });
    defer gpa.free(s);
    try std.testing.expectEqualStrings("x\\u0001y\\u001fz", s);
}

test {
    _ = lib;
    std.testing.refAllDecls(@This());
}
