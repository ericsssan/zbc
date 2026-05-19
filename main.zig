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
//!                        instead of escape analysis.  Useful for
//!                        projects that want to enforce explicit
//!                        annotations everywhere.
//!   --enable=<list>      Comma-separated invariant names to enable
//!                        (e.g. --enable=ast_identity,arena_escape).
//!                        Default is all invariants.
//!   --disable=<list>     Comma-separated invariant names to disable.
//!                        Subtracted from the enabled set.
//!   --format=text|json   Output format (default: text).  JSON emits
//!                        a single array across all input files,
//!                        suitable for editor/CI tooling.
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
    // Default mode is escape analysis (drop-in adoption).  --hygiene
    // opts into the older Layer-1 annotation-presence rules.
    var mode: Mode = .escape;
    var enabled_explicit = false;
    var format: Format = .text;

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
            // Kept for backward compatibility — escape is now the
            // default.  Silent accept; document in --help comment.
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

    // Expand directory args into recursive .zig file lists.  Direct
    // file paths pass through unchanged.  This + the new escape
    // default + inference = `zbc src/` Just Works on any Zig codebase.
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

    const config: lib.Config = .{ .enabled = enabled.items };

    var cache_storage: ?lib.Cache = if (mode == .escape) lib.Cache.init(gpa, io) else null;
    defer if (cache_storage) |*c| c.deinit();

    var any_problems = false;
    var json_first = true;
    if (format == .json) std.debug.print("[", .{});

    for (expanded.items) |path| {
        const problems = if (mode == .escape)
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
        switch (format) {
            .text => printProblemsText(path, problems),
            .json => printProblemsJson(path, problems, &json_first),
        }
    }

    if (format == .json) std.debug.print("{s}]\n", .{if (json_first) "" else "\n"});
    std.process.exit(if (any_problems) @as(u8, 1) else 0);
}

/// If `path` is a regular file, append (dupe'd) to `out`.
/// If `path` is a directory, walk it recursively and append every
/// `.zig` file found.  Skips hidden entries (.zig-cache/, .git/, etc.).
/// Caller owns the duped paths in `out`.
fn expandPath(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        // .NotDir is what openDir returns when path is a file; the
        // exact name varies by zig version, so we catch anything
        // not-a-directory by re-trying as a file below.
        else => {
            // Not a directory — assume regular file, append as-is.
            const duped = try gpa.dupe(u8, path);
            errdefer gpa.free(duped);
            try out.append(gpa, duped);
            return;
        },
    };
    defer dir.close(io);

    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        // Skip anything under a hidden directory (.zig-cache, .git).
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
        \\Default mode is escape analysis — signature-driven inference
        \\fills in annotations needed for invariant checks, so most code
        \\just works without authors writing `///` annotations.
        \\
        \\options:
        \\  --hygiene             Run annotation-presence rules instead
        \\                        of escape analysis.  For projects that
        \\                        want to enforce explicit annotations.
        \\  --enable=a,b,c        Enable only these invariants.
        \\  --disable=a,b         Disable these invariants from the set.
        \\  --format=text|json    Output format (default: text).
        \\  --list-invariants     Print known invariant names and exit.
        \\  -h, --help            Print this help.
        \\
    , .{});
}

fn printProblemsText(path: []const u8, problems: []const lib.Problem) void {
    for (problems) |p| {
        std.debug.print("{s}:{}:{}: {s}: {s} [{s}]\n", .{
            path,
            p.start.line,
            p.start.column,
            severityName(p.severity),
            p.message,
            p.rule_id,
        });
    }
}

fn printProblemsJson(path: []const u8, problems: []const lib.Problem, first: *bool) void {
    for (problems) |p| {
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
}

fn severityName(s: lib.Severity) []const u8 {
    return switch (s) {
        .@"error" => "error",
        .warning => "warning",
        .off => "off",
    };
}

/// Write `s` to stderr with the minimum JSON-string escapes per RFC 8259:
/// quote, backslash, and control characters (< 0x20) become \uXXXX.
/// No Unicode validation — Zig source files are valid UTF-8 already,
/// and the user's diagnostic messages flow through unchanged.
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

/// Buffered mirror of writeJsonEscaped — used by tests and any
/// future library-mode JSON sink that wants the escaped string
/// in memory rather than streamed to stderr.
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
    try parseInvariantList(gpa, "ast_mutation,pass_identity", &list, .remove);
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expect(!containsInvariant(list.items, .ast_mutation));
    try std.testing.expect(!containsInvariant(list.items, .pass_identity));
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
    // 0x01 + 0x1f sit in the explicit \u-escape range; 0x09 is \t (above).
    const s = try jsonEscapeToBuf(gpa, &[_]u8{ 'x', 0x01, 'y', 0x1f, 'z' });
    defer gpa.free(s);
    try std.testing.expectEqualStrings("x\\u0001y\\u001fz", s);
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
