//! Type resolution engine for zbc — repo-wide deep static analysis.
//!
//! Wraps the extracted type-resolution machinery (DocumentStore +
//! InternPool + Analyser) behind a zbc-shaped API.
//!
//! TypeContext  — long-lived per-thread state.  Holds DocumentStore +
//!                InternPool so stdlib files are parsed and typed once
//!                per thread.  In-place init required (self-referential
//!                pointers).  Never move after init.
//!
//! TypeResolver — per-file state.  Borrows a TypeContext; owns only
//!                the per-file arena and Analyser.

const std = @import("std");
const Ast = std.zig.Ast;

const DocumentStore = @import("document_store.zig");
const InternPool = @import("intern_pool.zig");
const Analyser = @import("analysis.zig");
const Uri = @import("uri.zig");
const DiagnosticsCollection = @import("diagnostics_collection.zig");

// ── Toolchain discovery ───────────────────────────────────────────────

const ToolchainPaths = struct {
    zig_exe: ?[]const u8 = null,
    zig_lib: ?[]const u8 = null,
    build_runner: ?[]const u8 = null,
    initialized: bool = false,
};

var global_toolchain: ToolchainPaths = .{};

/// Process-global cache — discovery runs once on first call.
/// Safe: called from TypeContext.init which is per-thread (no concurrent
/// calls to this function because workers are spawned AFTER the first
/// analyzeEscape call on the main thread has already populated the cache).
/// If concurrent init is ever needed, add an std.Io.Mutex guard.
pub fn discoverToolchain(io: std.Io, gpa: std.mem.Allocator) ToolchainPaths {
    if (global_toolchain.initialized) return global_toolchain;
    _ = gpa;
    const cache_gpa = std.heap.c_allocator;
    global_toolchain.zig_exe = findZigExe(cache_gpa, io, cache_gpa) catch null;
    global_toolchain.zig_lib = if (global_toolchain.zig_exe) |z|
        findZigLibDir(cache_gpa, io, cache_gpa, z) catch null
    else
        null;
    global_toolchain.build_runner = if (global_toolchain.zig_lib != null)
        findBuildRunner(cache_gpa, io) catch null
    else
        null;
    global_toolchain.initialized = true;
    return global_toolchain;
}

pub fn clearToolchainCacheForTesting() void {
    const cache_gpa = std.heap.c_allocator;
    if (global_toolchain.zig_exe) |p| cache_gpa.free(p);
    if (global_toolchain.zig_lib) |p| cache_gpa.free(p);
    if (global_toolchain.build_runner) |p| cache_gpa.free(p);
    global_toolchain = .{};
}

fn findZigExe(arena: std.mem.Allocator, io: std.Io, gpa: std.mem.Allocator) ![]const u8 {
    const raw = try runCapture(gpa, io, &.{ "/usr/bin/which", "zig" });
    defer gpa.free(raw);
    return try arena.dupe(u8, std.mem.trimEnd(u8, raw, &std.ascii.whitespace));
}

fn findZigLibDir(arena: std.mem.Allocator, io: std.Io, gpa: std.mem.Allocator, zig_exe: []const u8) ![]const u8 {
    const env_out = try runCapture(gpa, io, &.{ zig_exe, "env" });
    defer gpa.free(env_out);
    const needle = "\"lib_dir\":\"";
    const start = std.mem.indexOf(u8, env_out, needle) orelse return error.NotFound;
    const after = start + needle.len;
    const end = std.mem.indexOfScalarPos(u8, env_out, after, '"') orelse return error.NotFound;
    return try arena.dupe(u8, env_out[after..end]);
}

fn runCapture(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) ![]u8 {
    const result = std.process.run(gpa, io, .{ .argv = argv }) catch return error.NotFound;
    defer gpa.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            gpa.free(result.stdout);
            return error.NotFound;
        },
        else => {
            gpa.free(result.stdout);
            return error.NotFound;
        },
    }
    if (result.stdout.len == 0) {
        gpa.free(result.stdout);
        return error.NotFound;
    }
    return result.stdout;
}

fn findBuildRunner(arena: std.mem.Allocator, io: std.Io) ![]const u8 {
    const candidates = [_][]const u8{
        "zig-pkg/zls-0.17.0-dev-rmm5fhwjJgCaQB3fCtSi_8xBQvGJJqz9BBeQHjZK9jet/src/build_runner/build_runner.zig",
    };
    for (candidates) |path| {
        const handle = std.Io.Dir.cwd().openFile(io, path, .{}) catch continue;
        handle.close(io);
        return try arena.dupe(u8, path);
    }
    return error.NotFound;
}

// ── TypeContext ───────────────────────────────────────────────────────

/// Long-lived per-thread type-resolution state.  The DocumentStore
/// and InternPool persist across files processed by the same thread,
/// so stdlib is parsed and its types interned once per thread.
///
/// In-place init required: self-referential pointers
/// (store.config.environ_map → &self.environ_map,
///  store.diagnostics_collection → &self.diagnostics).
/// Never move after init.
pub const TypeContext = struct {
    gpa: std.mem.Allocator,
    ip: InternPool,
    diagnostics: DiagnosticsCollection,
    environ_map: std.process.Environ.Map,
    store: DocumentStore,

    pub fn init(self: *TypeContext, gpa: std.mem.Allocator, io: std.Io) !void {
        self.gpa = gpa;

        self.ip = try InternPool.init(io, gpa);
        errdefer self.ip.deinit(gpa);

        self.diagnostics = .{ .io = io, .allocator = gpa };
        self.environ_map = .init(std.testing.failing_allocator);

        const tc = discoverToolchain(io, gpa);
        const zig_lib: ?std.Build.Cache.Directory = if (tc.zig_lib) |p|
            .{ .path = p, .handle = .cwd() }
        else
            null;

        self.store = .{
            .io = io,
            .allocator = gpa,
            .config = .{
                .environ_map = &self.environ_map,
                .zig_exe_path = tc.zig_exe,
                .zig_lib_dir = zig_lib,
                .build_runner_path = tc.build_runner,
                .builtin_path = null,
                .global_cache_dir = null,
                .wasi_preopens = {},
            },
            .diagnostics_collection = &self.diagnostics,
        };
    }

    pub fn deinit(self: *TypeContext) void {
        self.store.deinit();
        self.diagnostics.deinit();
        self.ip.deinit(self.gpa);
    }
};

// ── TypeResolver ─────────────────────────────────────────────────────

/// Per-file type resolver.  Borrows a TypeContext (DocumentStore +
/// InternPool).  Per-file documents stay open for the thread's lifetime
/// so InternPool entries referencing them remain valid.
pub const TypeResolver = struct {
    gpa: std.mem.Allocator,
    ctx: *TypeContext,
    arena: std.heap.ArenaAllocator,
    handle: *DocumentStore.Handle,
    analyser: Analyser,

    pub fn init(
        self: *TypeResolver,
        ctx: *TypeContext,
        gpa: std.mem.Allocator,
        file_path: []const u8,
        source: [:0]const u8,
    ) !void {
        self.gpa = gpa;
        self.ctx = ctx;
        self.arena = std.heap.ArenaAllocator.init(gpa);
        errdefer self.arena.deinit();

        const handle_uri: Uri = try .fromPath(self.arena.allocator(), file_path);
        try ctx.store.openLspSyncedDocument(handle_uri, source);
        self.handle = ctx.store.getHandle(handle_uri) orelse return error.HandleMissing;

        self.analyser = Analyser.init(
            gpa,
            self.arena.allocator(),
            &ctx.store,
            &ctx.ip,
            self.handle,
        );
    }

    pub fn deinit(self: *TypeResolver) void {
        self.analyser.deinit();
        self.arena.deinit();
    }

    pub fn typeNameOfNode(self: *TypeResolver, node: Ast.Node.Index) !?[]const u8 {
        const ty_maybe = try self.analyser.resolveTypeOfNode(.of(node, self.handle));
        const ty = ty_maybe orelse return null;

        var cur = ty;
        var i: u32 = 0;
        while (i < 8) : (i += 1) {
            switch (cur.data) {
                .pointer => |p| cur = p.elem_ty.*,
                .optional => |inner| cur = inner.*,
                .array => |a| cur = a.elem_ty.*,
                else => break,
            }
        }

        return switch (cur.data) {
            .container => |container| try containerName(self.arena.allocator(), container),
            else => null,
        };
    }

    pub fn resolvedTypeIsPointer(self: *TypeResolver, node: Ast.Node.Index) !bool {
        const ty_maybe = try self.analyser.resolveTypeOfNode(.of(node, self.handle));
        const ty = ty_maybe orelse return false;
        return ty.data == .pointer;
    }

    pub fn isOptionalType(self: *TypeResolver, node: Ast.Node.Index) !bool {
        const ty_maybe = try self.analyser.resolveTypeOfNode(.of(node, self.handle));
        const ty = ty_maybe orelse return false;
        return switch (ty.data) {
            .optional => true,
            .ip_index => |payload| switch (self.ctx.ip.indexToKey(payload.type)) {
                .optional_type => true,
                else => false,
            },
            else => false,
        };
    }

    pub fn isRawSinglePointerType(self: *TypeResolver, node: Ast.Node.Index) !bool {
        const ty_maybe = try self.analyser.resolveTypeOfNode(.of(node, self.handle));
        const ty = ty_maybe orelse return false;
        return switch (ty.data) {
            .pointer => |info| info.size == .one,
            .ip_index => |payload| switch (self.ctx.ip.indexToKey(payload.type)) {
                .pointer_type => |info| info.flags.size == .one,
                else => false,
            },
            else => false,
        };
    }
};

fn containerName(arena: std.mem.Allocator, container: anytype) !?[]const u8 {
    const handle = container.scope_handle.handle;
    const scope_node = container.scope_handle.toNode();
    const tree = handle.tree;
    const tags = tree.tokens.items(.tag);
    const first_token = tree.firstToken(scope_node);
    const max_scan = 32;
    var i: usize = 0;
    var t = first_token;
    while (i < max_scan and t > 0) : ({
        i += 1;
        t -= 1;
    }) {
        if (tags[t] == .identifier and t > 0) {
            const prev = tags[t - 1];
            if (prev == .keyword_const or prev == .keyword_fn or
                prev == .keyword_var or prev == .keyword_pub)
            {
                return try arena.dupe(u8, tree.tokenSlice(t));
            }
        }
    }
    return null;
}
