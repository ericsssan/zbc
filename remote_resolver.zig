//! Cross-file annotation resolver.  Given an import path (relative to
//! the current file's directory), opens the target file, parses it,
//! builds its annotation DB, and caches the result so subsequent
//! lookups within the same sweep don't re-read or re-parse.
//!
//! Lifetime model: a `Cache` owns every loaded RemoteFile (src_z,
//! tree, db).  Callers get a `*const RemoteFile` whose contents stay
//! valid until the cache is deinit'd.  Per-file-sweep scoping is the
//! default — promote to sweep-wide if profiling shows reparsing cost.
//!
//! Scope (phase 22):
//! - .zig file paths only.  Pure namespaces (`@import("std")`,
//!   `@import("builtin")`, `@import("root")`) and package-relative
//!   imports without `.zig` suffix → null (caller treats as opaque).
//! - One level deep.  An imported file's own `@import("...")` chain
//!   isn't followed — annotation lookup is performed against the
//!   immediate import target only.
//! - Read failures and parse failures both → null (the import either
//!   doesn't exist on disk or is malformed; conservative miss).

const std = @import("std");
const Ast = std.zig.Ast;

const annotations = @import("annotations.zig");
const imports_mod = @import("imports.zig");

pub const RemoteFile = struct {
    /// Borrowed view of the cache's key for this file.  Used by
    /// callers to resolve nested @imports relative to this file's
    /// directory (`std.fs.path.dirname(abs_path)`).  NOT freed by
    /// deinit — the cache owns the underlying allocation.
    abs_path: []const u8,
    src_z: [:0]u8,
    tree: Ast,
    db: annotations.Db,
    /// This file's own @import extractions, used to chase one extra
    /// level when callers see `lib.Submodule.method(...)`.
    imap: imports_mod.Map,

    pub fn deinit(self: *RemoteFile, gpa: std.mem.Allocator) void {
        self.imap.deinit(gpa);
        self.db.deinit(gpa);
        self.tree.deinit(gpa);
        gpa.free(self.src_z);
    }
};

pub const Cache = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Mutex protecting `files`.  The map check + insert are short;
    /// the slow part (file read + parse + DB build) runs OUTSIDE the
    /// lock so concurrent loads of DIFFERENT paths parallelize.
    /// Concurrent loads of the SAME path can race past the first
    /// `get` and both parse — the second to finish discards its
    /// duplicate via the re-check.  In practice this happens only at
    /// sweep startup before any cache entries exist.
    ///
    /// std.Io.Mutex (rather than std.Thread.Mutex, which doesn't
    /// exist on 0.17) — we already thread `io` through everywhere
    /// and use lockUncancelable since the critical sections never
    /// yield.
    mutex: std.Io.Mutex,
    /// abs-path → loaded file.  Keys are gpa-owned (heap-duped from
    /// std.fs.path.resolve output); values are heap-allocated boxes.
    files: std.StringHashMapUnmanaged(*RemoteFile),

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Cache {
        return .{ .gpa = gpa, .io = io, .mutex = .init, .files = .empty };
    }

    pub fn deinit(self: *Cache) void {
        var it = self.files.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.gpa);
            self.gpa.destroy(entry.value_ptr.*);
            self.gpa.free(entry.key_ptr.*);
        }
        self.files.deinit(self.gpa);
    }

    /// Resolve `import_path` (as written in source — may be relative)
    /// against `base_dir` (the directory of the file containing the
    /// `@import`).  Returns null when:
    ///   - The path isn't a `.zig` file (std/builtin/package names).
    ///   - The file can't be opened or read.
    ///   - The file can't be parsed.
    ///
    /// Thread-safe: the mutex guards map check and insert; the parse
    /// itself runs outside the lock so distinct files parse in
    /// parallel.  Same-file concurrent loads at sweep startup may
    /// duplicate the parse work; the second to finish discards the
    /// dup via re-check.
    pub fn loadOrLookup(
        self: *Cache,
        base_dir: []const u8,
        import_path: []const u8,
    ) !?*const RemoteFile {
        if (!std.mem.endsWith(u8, import_path, ".zig")) return null;

        // Resolve to a canonical absolute-ish path.  std.fs.path.resolve
        // joins + collapses .. segments but doesn't realpath() — fine
        // for cache keying within a single sweep.
        const abs = try std.fs.path.resolve(self.gpa, &.{ base_dir, import_path });
        errdefer self.gpa.free(abs);

        // Fast path: lock just long enough to check + return on hit.
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.files.get(abs)) |hit| {
                self.gpa.free(abs);
                return hit;
            }
        }

        const src_bytes = std.Io.Dir.cwd().readFileAlloc(
            self.io,
            abs,
            self.gpa,
            std.Io.Limit.limited(16 * 1024 * 1024),
        ) catch {
            // File missing / unreadable — cache the miss as null would
            // require Optional values; for now, just return null and
            // re-attempt next time (rare path).  Free abs first.
            self.gpa.free(abs);
            return null;
        };
        defer self.gpa.free(src_bytes);

        const src_z = self.gpa.allocSentinel(u8, src_bytes.len, 0) catch {
            self.gpa.free(abs);
            return null;
        };
        errdefer self.gpa.free(src_z);
        @memcpy(src_z[0..src_bytes.len], src_bytes);

        var tree = Ast.parse(self.gpa, src_z, .zig) catch {
            self.gpa.free(abs);
            self.gpa.free(src_z);
            return null;
        };
        errdefer tree.deinit(self.gpa);

        var db = annotations.build(self.gpa, &tree) catch {
            tree.deinit(self.gpa);
            self.gpa.free(src_z);
            self.gpa.free(abs);
            return null;
        };
        errdefer db.deinit(self.gpa);

        var imap = imports_mod.build(self.gpa, &tree) catch {
            db.deinit(self.gpa);
            tree.deinit(self.gpa);
            self.gpa.free(src_z);
            self.gpa.free(abs);
            return null;
        };
        errdefer imap.deinit(self.gpa);

        const box = try self.gpa.create(RemoteFile);
        box.* = .{
            .abs_path = abs,
            .src_z = src_z,
            .tree = tree,
            .db = db,
            .imap = imap,
        };

        // Re-check under lock: another worker may have inserted the
        // same path while we were parsing.  If so, discard our
        // duplicate and return the winner.
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.files.get(abs)) |hit| {
            box.deinit(self.gpa);
            self.gpa.destroy(box);
            self.gpa.free(abs);
            return hit;
        }
        try self.files.put(self.gpa, abs, box);
        return box;
    }
};

// ── Tests ──────────────────────────────────────────────────

test "loadOrLookup returns null for std-namespace imports" {
    const gpa = std.testing.allocator;
    var io_buf: std.Io.Threaded = .init(gpa, .{});
    defer io_buf.deinit();
    var cache = Cache.init(gpa, io_buf.io());
    defer cache.deinit();

    try std.testing.expectEqual(
        @as(?*const RemoteFile, null),
        try cache.loadOrLookup(".", "std"),
    );
    try std.testing.expectEqual(
        @as(?*const RemoteFile, null),
        try cache.loadOrLookup(".", "builtin"),
    );
}

test "loadOrLookup parses and caches a real .zig file (annotations DB built)" {
    const gpa = std.testing.allocator;
    var io_buf: std.Io.Threaded = .init(gpa, .{});
    defer io_buf.deinit();

    // Use std's own Ast.zig as a known-parseable real file — verifies
    // the resolver handles a multi-thousand-line tree without
    // crashing.  Its annotation DB will be empty (stdlib doesn't use
    // our @returns markers), which is fine — we just check we got
    // a non-null result and cache lookup is idempotent.
    var cache = Cache.init(gpa, io_buf.io());
    defer cache.deinit();

    const ast_dir = "/Users/ericsan/.local/share/zigup/master/files/lib/std/zig";
    const first = try cache.loadOrLookup(ast_dir, "Ast.zig") orelse return error.SkipZigTest;
    const second = try cache.loadOrLookup(ast_dir, "Ast.zig") orelse return error.SkipZigTest;
    try std.testing.expectEqual(first, second); // cache hit
}

test "loadOrLookup returns null for missing file" {
    const gpa = std.testing.allocator;
    var io_buf: std.Io.Threaded = .init(gpa, .{});
    defer io_buf.deinit();
    var cache = Cache.init(gpa, io_buf.io());
    defer cache.deinit();

    try std.testing.expectEqual(
        @as(?*const RemoteFile, null),
        try cache.loadOrLookup(".", "this_file_does_not_exist_anywhere.zig"),
    );
}
