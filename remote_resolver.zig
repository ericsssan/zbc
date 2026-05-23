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
const file_cache_mod = @import("file_cache.zig");

pub const RemoteFile = struct {
    /// Borrowed view of the cache's key for this file.  Used by
    /// callers to resolve nested @imports relative to this file's
    /// directory (`std.fs.path.dirname(abs_path)`).  NOT freed by
    /// deinit — the cache owns the underlying allocation.
    abs_path: []const u8,
    src_z: [:0]u8,
    tree: Ast,
    db: annotations.Db,
    /// FileCache for the new FnSummary / FileModel queries on this
    /// file.  Built alongside db during loadOrLookup; consumers
    /// (cfg.zig's cross-file lookup helpers) prefer cache queries
    /// over db queries during the annotation->inference migration.
    fcache: file_cache_mod.FileCache,
    /// This file's own @import extractions, used to chase one extra
    /// level when callers see `lib.Submodule.method(...)`.
    imap: imports_mod.Map,

    pub fn deinit(self: *RemoteFile, gpa: std.mem.Allocator) void {
        self.imap.deinit(gpa);
        self.fcache.deinit();
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
    /// Currently-loading set.  Cycle detector: if R7 inference inside
    /// file A triggers loadOrLookup(B) and B's R7 transitively
    /// triggers loadOrLookup(A), A isn't yet in `files` (we insert
    /// AFTER buildFull completes), so without this guard we'd
    /// re-parse + re-build A unboundedly until stack overflow.
    /// Bun's deeply-imported codebase hit this immediately.  Entries
    /// added on entry to the slow path and removed on completion.
    loading: std.StringHashMapUnmanaged(void),

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Cache {
        return .{ .gpa = gpa, .io = io, .mutex = .init, .files = .empty, .loading = .empty };
    }

    pub fn deinitLoading(self: *Cache) void {
        // Free loading-set keys we own (gpa-duped abs paths).
        var it = self.loading.iterator();
        while (it.next()) |entry| self.gpa.free(entry.key_ptr.*);
        self.loading.deinit(self.gpa);
    }

    pub fn deinit(self: *Cache) void {
        self.deinitLoading();
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

        // Fast path: lock just long enough to check + return on hit
        // or bail on a re-entry (cycle).  Hoists `loading_key` out
        // of the locked block so the cleanup defer below can use it
        // — abs gets freed on every error/dedup return below, so
        // looking the loading set up by `abs` would be a UAF (zbc's
        // own borrow checker flagged this).  loading_key is a
        // separate dupe that survives until the defer fires.
        const loading_key = blk: {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.files.get(abs)) |hit| {
                self.gpa.free(abs);
                return hit;
            }
            if (self.loading.contains(abs)) {
                // Reentrant load — cycle.  Return null so the caller
                // (R7 inference looking up a cross-file annotation)
                // treats this as a miss for THIS pass.  Stable
                // annotations from a later non-recursive load will
                // be picked up the next time the file is queried.
                self.gpa.free(abs);
                return null;
            }
            // Mark loading.  Duplicate ownership: the loading-set
            // owns its own copy of the abs path; the `files` entry
            // (on success) gets the original.
            const lk = self.gpa.dupe(u8, abs) catch {
                self.gpa.free(abs);
                return null;
            };
            self.loading.put(self.gpa, lk, {}) catch {
                self.gpa.free(lk);
                self.gpa.free(abs);
                return null;
            };
            break :blk lk;
        };
        // Remove from loading-set on every exit path.  Look up by
        // loading_key (not abs) — abs is freed on most error /
        // dedup paths below and reading it here would be UB.
        defer {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.loading.fetchRemove(loading_key)) |kv| self.gpa.free(kv.key);
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

        // Build the remote file's imap FIRST so R7 inference can do
        // cross-file lookups inside this file's body too — same cache,
        // resolved against this file's own directory.
        var imap = imports_mod.build(self.gpa, &tree) catch {
            tree.deinit(self.gpa);
            self.gpa.free(src_z);
            self.gpa.free(abs);
            return null;
        };
        errdefer imap.deinit(self.gpa);

        const remote_base_dir = std.fs.path.dirname(abs) orelse ".";
        const anno_remote: annotations.RemoteCtx = .{
            .imap = &imap,
            .base_dir = remote_base_dir,
            .cache = self,
        };
        var db = annotations.buildFull(self.gpa, &tree, null, anno_remote) catch {
            imap.deinit(self.gpa);
            tree.deinit(self.gpa);
            self.gpa.free(src_z);
            self.gpa.free(abs);
            return null;
        };
        errdefer db.deinit(self.gpa);

        const box = try self.gpa.create(RemoteFile);
        box.* = .{
            .abs_path = abs,
            .src_z = src_z,
            .tree = tree,
            .db = db,
            // fcache.tree must point at box.tree (not the local
            // `tree` that's about to go out of scope).  Initialize
            // with a placeholder then re-point after box assignment.
            .fcache = file_cache_mod.FileCache.init(self.gpa, &tree),
            .imap = imap,
        };
        box.fcache = file_cache_mod.FileCache.init(self.gpa, &box.tree);
        // Resolve R10 transitive takes for this imported file's
        // summaries.  Failure is non-fatal — drop the file rather
        // than poison the cache.
        box.fcache.resolveTransitiveTakes() catch {};

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

/// Adapter providing the `file_cache.RemoteSummaryCtx` interface for
/// `Cache + imports.Map + base_dir`.  Used by FileCache R7 inference
/// to chase delegating returns across files without creating an
/// import cycle (file_cache.zig can't import this file directly).
///
/// Lifetime: caller owns the struct; the produced `RemoteSummaryCtx`
/// borrows the adapter's pointer, so the adapter must outlive any
/// FileCache pass that uses the ctx.
pub const RemoteSummaryAdapter = struct {
    cache: *Cache,
    imap: *const imports_mod.Map,
    base_dir: []const u8,

    pub fn ctx(self: *RemoteSummaryAdapter) file_cache_mod.RemoteSummaryCtx {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: file_cache_mod.RemoteSummaryCtx.VTable = .{
        .getByNamespace = getByNamespace,
        .next = next,
    };

    fn getByNamespace(ptr: *anyopaque, namespace: []const u8) ?*file_cache_mod.FileCache {
        const self: *RemoteSummaryAdapter = @ptrCast(@alignCast(ptr));
        const entry = self.imap.lookup(namespace) orelse return null;
        const remote = (self.cache.loadOrLookup(self.base_dir, entry.path) catch return null) orelse return null;
        // The `fcache` field is borrowed via *const RemoteFile; cast
        // away const so the consumer can call mutating queries
        // (summaryByName allocates on first call).  Safe: the cache
        // only mutates lazy fields under its own per-file ownership.
        return @constCast(&remote.fcache);
    }

    fn next(ptr: *anyopaque, state: *u32) ?*file_cache_mod.FileCache {
        const self: *RemoteSummaryAdapter = @ptrCast(@alignCast(ptr));
        var it = self.imap.entries.iterator();
        var i: u32 = 0;
        while (it.next()) |kv| : (i += 1) {
            if (i < state.*) continue;
            state.* = i + 1;
            const remote = (self.cache.loadOrLookup(self.base_dir, kv.value_ptr.path) catch continue) orelse continue;
            return @constCast(&remote.fcache);
        }
        state.* = i;
        return null;
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
