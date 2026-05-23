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

        self.document_store = .{
            .io = io,
            .allocator = gpa,
            .config = .{
                .environ_map = &self.environ_map,
                .zig_exe_path = null,
                .zig_lib_dir = null,
                .build_runner_path = null,
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
};

/// Best-effort container-name extraction.  ZLS represents containers
/// by `(handle, scope)`; the declaration's name lives near the scope's
/// owning AST node.  For `pub const Foo = struct {...}` the name is
/// trivially the token before `=`; for anonymous `return struct {...}`
/// inside a factory fn, the name is the FN's name.
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
