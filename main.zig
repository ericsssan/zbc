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

    // Project-tunable patterns (default mirrors lib.DefaultConfig).
    // Authors override via --ast-type / --ast-init / --arena-init /
    // --arena-kill / --thread-join when their codebase uses different
    // type names or constructor patterns.  Pattern lists are
    // comma-separated.  Allocated slice-of-slice freed at exit.
    var ast_type_name: []const u8 = lib.DefaultConfig.ast_type_name;
    var ast_init_patterns: []const []const u8 = lib.DefaultConfig.ast_init_patterns;
    var arena_init_patterns: []const []const u8 = lib.DefaultConfig.arena_init_patterns;
    var arena_kill_patterns: []const []const u8 = lib.DefaultConfig.arena_kill_patterns;
    var thread_join_patterns: []const []const u8 = lib.DefaultConfig.thread_join_patterns;
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
        if (std.mem.startsWith(u8, a, "--ast-type=")) {
            ast_type_name = a["--ast-type=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, a, "--ast-init=")) {
            const slice = try splitCsv(gpa, a["--ast-init=".len..]);
            try pattern_allocations.append(gpa, slice);
            ast_init_patterns = slice;
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
        if (std.mem.startsWith(u8, a, "--thread-join=")) {
            const slice = try splitCsv(gpa, a["--thread-join=".len..]);
            try pattern_allocations.append(gpa, slice);
            thread_join_patterns = slice;
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

    const config: lib.Config = .{
        .ast_type_name = ast_type_name,
        .ast_init_patterns = ast_init_patterns,
        .arena_init_patterns = arena_init_patterns,
        .arena_kill_patterns = arena_kill_patterns,
        .thread_join_patterns = thread_join_patterns,
        .enabled = enabled.items,
    };

    // Sweep-wide remote-resolver cache, shared across all workers.
    // Thread-safe (mutex + double-checked locking inside Cache); the
    // slow parse work runs OUTSIDE the lock so distinct files still
    // parallelize.  Cuts redundant reparses of common imports
    // (e.g. ast.zig imported from 30+ src/ files = parsed once
    // total instead of once per worker that touches it).
    var shared_cache: ?lib.Cache = if (mode == .escape) lib.Cache.init(gpa, io) else null;
    defer if (shared_cache) |*c| c.deinit();

    // Parallel fan-out: one Task per file, sharing the cache.
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

    // Group.concurrent vs Group.async: .concurrent forces a worker
    // thread for each task (up to concurrent_limit = unlimited by
    // default on Io.Threaded), giving real CPU parallelism.  .async
    // would let the scheduler decide and can serialize tasks when
    // the async_limit is small.  We want real parallelism here.
    // Fall back to .async if .concurrent isn't supported by the Io
    // backend (e.g. single-threaded testing envs).
    var group: std.Io.Group = .init;
    for (tasks) |*t| {
        group.concurrent(io, runOne, .{t}) catch
            group.async(io, runOne, .{t});
    }
    group.await(io) catch {};

    // Single-pass: collate problems, sort for deterministic output.
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

/// Split `csv` on commas, trim whitespace, drop empties.  Returns a
/// gpa-owned slice-of-slices where each element points into `csv`
/// (which lives for the process — argv strings are stable).  Caller
/// frees only the outer slice; inner slices aren't separately allocated.
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
        \\project-tunable patterns (defaults match the ez parser shape):
        \\  --ast-type=NAME       Identifier name treated as the Ast type
        \\                        (default: Ast).
        \\  --ast-init=A,B,C      Source-text patterns that mint a fresh
        \\                        Ast (default: Ast.parse).
        \\  --arena-init=A,B      Patterns that mint a fresh arena
        \\                        (default: ArenaAllocator.init).
        \\  --arena-kill=A,B      Patterns that kill the receiver arena
        \\                        (default: .deinit().
        \\  --thread-join=A,B     Patterns that join a worker thread
        \\                        (default: .join().
        \\
    , .{});
}

// ── Parallel-fanout types + helpers ────────────────────────

const Task = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    mode: Mode,
    config: *const lib.Config,
    /// Sweep-wide shared cache (null in hygiene mode where remote
    /// resolution isn't needed).  Thread-safe via internal mutex.
    cache: ?*lib.Cache,
    /// Outputs.  Owned by the task; collated after Group.await.
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

/// Worker body — analyzes one file against the sweep-wide Cache.
/// Errors stashed on the task so a bad file doesn't abort the sweep.
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
    try parseInvariantList(gpa, "thread_arena,pass_identity", &list, .remove);
    try std.testing.expectEqual(lib.all_invariants.len - 2, list.items.len);
    try std.testing.expect(!containsInvariant(list.items, .thread_arena));
    try std.testing.expect(!containsInvariant(list.items, .pass_identity));
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
