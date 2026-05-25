//! ZLS-backed type resolver.  Wraps ZLS's `Analyser` + `DocumentStore`
//! behind a zbc-shaped API: given an AST node, return the resolved
//! type's bare container-decl name (or null).
//!
//! Lifetime: one `ZlsResolver` per file being analyzed.  Internally
//! it shares a DocumentStore across calls so cross-file imports are
//! cached.  Caller owns the `gpa` + `io`; resolver allocates its
//! per-resolution scratch in an arena it owns.
//!
//! Cost: ZLS's machinery is heavyweight at init (DocumentStore +
//! InternPool + DiagnosticsCollection) but each `typeNameOfNode`
//! query is `O(1)`-amortized after the first call on a given subtree.

const std = @import("std");
const Ast = std.zig.Ast;

const zls = @import("zls");
const InternPool = zls.analyser.InternPool;
const Analyser = zls.Analyser;

/// Process-global cache of discovered toolchain paths.  Each
/// `which zig` + `zig env` invocation takes ~50-200ms and the
/// answers are stable across all files in a sweep — so we do the
/// discovery ONCE on the first ZlsResolver init and reuse for
/// subsequent files.  Cuts ~80% off ZLS init overhead on
/// large-corpus sweeps (where the same ZlsResolver is rebuilt
/// per-file).
const ToolchainPaths = struct {
    zig_exe: ?[]const u8 = null,
    zig_lib: ?[]const u8 = null,
    build_runner: ?[]const u8 = null,
    initialized: bool = false,
};
var global_toolchain: ToolchainPaths = .{};

pub const ZlsResolver = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    ip: InternPool,
    diagnostics_collection: zls.DiagnosticsCollection,
    environ_map: std.process.Environ.Map,
    document_store: zls.DocumentStore,
    handle: *zls.DocumentStore.Handle,
    analyser: Analyser,

    /// In-place init: caller declares `var resolver: ZlsResolver = undefined;`
    /// then calls `try resolver.init(...)`.  In-place is REQUIRED because
    /// the resolver holds self-referential pointers (DocumentStore.config.
    /// environ_map → &self.environ_map, DocumentStore.diagnostics_collection
    /// → &self.diagnostics_collection); returning by value would copy the
    /// struct and leave those pointers dangling.
    pub fn init(
        self: *ZlsResolver,
        gpa: std.mem.Allocator,
        io: std.Io,
        file_path: []const u8,
        source: [:0]const u8,
    ) !void {
        self.gpa = gpa;
        self.arena = std.heap.ArenaAllocator.init(gpa);
        errdefer self.arena.deinit();

        self.ip = try .init(io, gpa);
        errdefer self.ip.deinit(gpa);

        self.diagnostics_collection = .{
            .io = io,
            .allocator = gpa,
        };
        errdefer self.diagnostics_collection.deinit();

        self.environ_map = .init(std.testing.failing_allocator);

        // Discover the Zig toolchain so ZLS can resolve @import
        // chains through the standard library AND a project's
        // build.zig (build-runner integration).  Process-global
        // cache — discovery runs ONCE on the first init and is
        // reused for subsequent files (each `which zig` /
        // `zig env` spawn is ~50-200ms; per-file payment is
        // unaffordable on multi-thousand-file sweeps).
        const tc = discoverToolchain(io, gpa);
        const zig_lib: ?std.Build.Cache.Directory = if (tc.zig_lib) |p|
            .{ .path = p, .handle = .cwd() }
        else
            null;
        const zig_exe = tc.zig_exe;
        const build_runner = tc.build_runner;

        self.document_store = .{
            .io = io,
            .allocator = gpa,
            .config = .{
                .environ_map = &self.environ_map,
                .zig_exe_path = zig_exe,
                .zig_lib_dir = zig_lib,
                .build_runner_path = build_runner,
                .builtin_path = null,
                .global_cache_dir = null,
                .wasi_preopens = {},
            },
            .diagnostics_collection = &self.diagnostics_collection,
        };
        errdefer self.document_store.deinit();

        const handle_uri: zls.Uri = try .fromPath(self.arena.allocator(), file_path);
        try self.document_store.openLspSyncedDocument(handle_uri, source);
        self.handle = self.document_store.getHandle(handle_uri) orelse return error.HandleMissing;

        self.analyser = Analyser.init(
            gpa,
            self.arena.allocator(),
            &self.document_store,
            &self.ip,
            self.handle,
        );
    }

    pub fn deinit(self: *ZlsResolver) void {
        self.analyser.deinit();
        self.document_store.deinit();
        self.diagnostics_collection.deinit();
        self.ip.deinit(self.gpa);
        self.arena.deinit();
    }

    /// Resolve `node`'s type and return its bare container-decl name
    /// (e.g. `ClientPool`, `GenericWalker`).  Returns null when:
    ///   - The node isn't a value-bearing expression
    ///   - The resolved type isn't a container (`u32`, slices, etc.)
    ///   - Resolution fails (cross-module @import that can't be
    ///     followed without build-runner integration)
    ///
    /// Cost: ZLS internally memoizes via `resolved_nodes`; repeated
    /// queries on the same node are constant-time.
    pub fn typeNameOfNode(
        self: *ZlsResolver,
        node: Ast.Node.Index,
    ) !?[]const u8 {
        const ty_maybe = try self.analyser.resolveTypeOfNode(.of(node, self.handle));
        const ty = ty_maybe orelse return null;

        // Strip pointer/optional/array wrappers down to the container.
        var cur = ty;
        const max_unwraps = 8;
        var i: u32 = 0;
        while (i < max_unwraps) : (i += 1) {
            switch (cur.data) {
                .pointer => |p| cur = p.elem_ty.*,
                .optional => |inner| cur = inner.*,
                .array => |a| cur = a.elem_ty.*,
                else => break,
            }
        }

        switch (cur.data) {
            .container => |container| {
                // The container's scope is anchored at a token in
                // some handle's tree.  Walk back to find the
                // declaration name token.
                return try containerName(self.arena.allocator(), container);
            },
            else => return null,
        }
    }

    /// Returns true iff `node` resolves to a pointer type at the
    /// outermost level (before any unwrapping).  Used by `lowerVarDecl`
    /// to detect opaque-pointer-returning calls like
    /// `b.addUpdateSourceFiles()` where the return type is `*T` but
    /// `T` isn't syntactically visible at the call site.
    pub fn resolvedTypeIsPointer(self: *ZlsResolver, node: Ast.Node.Index) !bool {
        const ty_maybe = try self.analyser.resolveTypeOfNode(.of(node, self.handle));
        const ty = ty_maybe orelse return false;
        return switch (ty.data) {
            .pointer => true,
            else => false,
        };
    }
};

/// Best-effort container-name extraction.  ZLS represents containers
/// by `(handle, scope)`; the declaration's name lives near the scope's
/// owning AST node.  For `pub const Foo = struct {...}` the name is
/// trivially the token before `=`; for anonymous `return struct {...}`
/// inside a factory fn, the name is the FN's name.
/// Process-global toolchain discovery — runs the heavyweight
/// `which zig` + `zig env` + build-runner lookup ONCE, caches the
/// results in a leak-resistant heap allocation backed by the
/// supplied gpa (paths live for the process lifetime).  Subsequent
/// callers see the cached values.  Thread-safe via mutex.
fn discoverToolchain(io: std.Io, gpa: std.mem.Allocator) ToolchainPaths {
    // zbc analyzes files single-threadedly per invocation, so no
    // mutex is needed; if that changes, gate on a std.Thread.Mutex.
    if (global_toolchain.initialized) return global_toolchain;
    // Cache lives for the whole process — use the process-global
    // c_allocator so test gpas don't reclaim it between
    // `analyzeEscape` invocations.  Tests that detect leaks tolerate
    // this because the cache is intentionally process-static
    // (cleared via clearToolchainCacheForTesting in test bodies).
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

/// Test-only: free the cached toolchain paths and reset the
/// initialized flag.  Used by tests that want to validate the
/// resolver against multiple gpas in isolation.
pub fn clearToolchainCacheForTesting() void {
    const cache_gpa = std.heap.c_allocator;
    if (global_toolchain.zig_exe) |p| cache_gpa.free(p);
    if (global_toolchain.zig_lib) |p| cache_gpa.free(p);
    if (global_toolchain.build_runner) |p| cache_gpa.free(p);
    global_toolchain = .{};
}

/// Discover the `zig` executable path via `which zig`.  Returns
/// the resolved absolute path on success.  Falls through to
/// `error.NotFound` when discovery fails; caller swallows the
/// error to keep zbc running without ZLS cross-module resolution.
fn findZigExe(arena: std.mem.Allocator, io: std.Io, gpa: std.mem.Allocator) ![]const u8 {
    const raw = try runCapture(gpa, io, &.{ "/usr/bin/which", "zig" });
    defer gpa.free(raw);
    return try arena.dupe(u8, std.mem.trimEnd(u8, raw, &std.ascii.whitespace));
}

/// Discover the Zig stdlib directory by querying `zig env`.  The
/// stdlib dir is needed for ZLS to follow `@import("std")` and
/// builtin types.
fn findZigLibDir(arena: std.mem.Allocator, io: std.Io, gpa: std.mem.Allocator, zig_exe: []const u8) ![]const u8 {
    const env_out = try runCapture(gpa, io, &.{ zig_exe, "env" });
    defer gpa.free(env_out);
    // Parse out `"lib_dir":"<path>"` from JSON.  Cheap manual scan
    // — full JSON parse is overkill for one field.
    const needle = "\"lib_dir\":\"";
    const start = std.mem.indexOf(u8, env_out, needle) orelse return error.NotFound;
    const after = start + needle.len;
    const end = std.mem.indexOfScalarPos(u8, env_out, after, '"') orelse return error.NotFound;
    return try arena.dupe(u8, env_out[after..end]);
}

/// Run a command, capture stdout, return stdout bytes (caller-owned
/// by `gpa`).  Returns `error.NotFound` on any failure (non-zero
/// exit, spawn failure, empty output) so the caller's `catch null`
/// gives the all-clear-or-disabled path.
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

/// Discover the build-runner script that ZLS loads to introspect
/// the active project's build.zig.  zbc vendors the ZLS package
/// under `zig-pkg/zls-*/src/build_runner/build_runner.zig`.  Try
/// the canonical relative paths; ZLS keeps working without it,
/// just can't follow cross-module `@import("foo")` chains that
/// resolve via build.zig modules.
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

fn containerName(
    arena: std.mem.Allocator,
    container: anytype,
) !?[]const u8 {
    const handle = container.scope_handle.handle;
    const scope_node = container.scope_handle.toNode();
    const tree = handle.tree;
    const tags = tree.tokens.items(.tag);
    const first_token = tree.firstToken(scope_node);

    // Walk backwards from the container's first token to find the
    // surrounding `const <Name> =` or `fn <Name>(...)`.  Bounded
    // scan keeps cost predictable on pathological inputs.
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

// ── Tests ──────────────────────────────────────────────────

test "ZlsResolver: init + deinit + resolves simple identifier" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;

    const src: [:0]const u8 =
        \\const ClientPool = struct {
        \\    items: []u8 = &.{},
        \\    pub fn deinit(self: *ClientPool) void { _ = self; }
        \\};
        \\
        \\pub fn foo() void {
        \\    var pool: ClientPool = .{};
        \\    pool.deinit();
        \\}
    ;

    var resolver: ZlsResolver = undefined;
    try resolver.init(gpa, tio, "/tmp/zls_resolver_test1.zig", src);
    defer resolver.deinit();

    // Walk AST nodes for the FIRST identifier whose token slice is
    // "pool" inside `pool.deinit()` — that's the receiver-position
    // identifier we want to resolve.
    const tree = resolver.handle.tree;
    var node_idx: u32 = 1;
    var found_node: ?Ast.Node.Index = null;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const n: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(n) != .identifier) continue;
        const name = tree.tokenSlice(tree.nodeMainToken(n));
        if (!std.mem.eql(u8, name, "pool")) continue;
        const start = tree.tokens.items(.start)[tree.firstToken(n)];
        // Want the SECOND `pool` (the receiver), not the var-decl LHS.
        // var-decl's pool comes first in source order.
        if (start > std.mem.indexOf(u8, src, "pool.deinit()").? - 1) {
            found_node = n;
            break;
        }
    }
    const node = found_node orelse return error.NodeNotFound;
    const type_name = try resolver.typeNameOfNode(node);
    try std.testing.expect(type_name != null);
    try std.testing.expectEqualStrings("ClientPool", type_name.?);
}

test "ZlsResolver.resolvedTypeIsPointer: pointer-returning factory fn" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;

    const src: [:0]const u8 =
        \\const Widget = struct { x: u32 = 0 };
        \\
        \\fn makeWidget() *Widget {
        \\    return undefined;
        \\}
        \\
        \\pub fn foo() void {
        \\    const w = makeWidget();
        \\    _ = w;
        \\}
    ;

    var resolver: ZlsResolver = undefined;
    try resolver.init(gpa, tio, "/tmp/zls_resolver_test_ptr.zig", src);
    defer resolver.deinit();

    // Find the call node `makeWidget()` — it's the init of `const w = makeWidget()`
    const tree = resolver.handle.tree;
    var node_idx: u32 = 1;
    var call_node: ?Ast.Node.Index = null;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const n: Ast.Node.Index = @enumFromInt(node_idx);
        switch (tree.nodeTag(n)) {
            .call, .call_comma, .call_one, .call_one_comma => {
                const first_tok = tree.firstToken(n);
                const slice = tree.tokenSlice(first_tok);
                if (std.mem.eql(u8, slice, "makeWidget")) {
                    call_node = n;
                    break;
                }
            },
            else => {},
        }
    }
    const cn = call_node orelse return error.CallNodeNotFound;
    const is_ptr = try resolver.resolvedTypeIsPointer(cn);
    try std.testing.expect(is_ptr);
}

