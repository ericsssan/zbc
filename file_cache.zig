//! Per-file shared state for pattern detectors.
//!
//! Both `FileModel` (per-file TypeTable + FnTable) and `LocalBindings`
//! (per-fn binding-origin tracker) are expensive to build but identical
//! for every consumer.  Before this cache, ARCHITECTURE.md claimed they
//! were "built ONCE per file" but the code rebuilt them inside every
//! rule that needed them — for an N-fn file with 13 LocalBindings-using
//! rules, that was 13N builds.
//!
//! The cache materializes each at most once per file:
//!   - `fileModel()` lazily builds (and caches) the FileModel on first
//!     call.
//!   - `localBindings(proto, body)` returns a cached LocalBindings if
//!     present; builds + stores otherwise.  Keyed by the body's node
//!     index.
//!
//! The cache is per-file, owned by lib.zig, deinit'd at the end of each
//! file's analysis.  Threading: main.zig's worker pool processes one
//! file per thread; no cross-thread sharing.

const std = @import("std");
const Ast = std.zig.Ast;

const fmodel = @import("model.zig");
const local = @import("local.zig");
const fn_summary = @import("fn_summary.zig");

pub const FileCache = struct {
    gpa: std.mem.Allocator,
    tree: *const Ast,
    /// Arena for FnSummary's variable-length fields
    /// (may_free_fields, result_heap_fields).  Lazy: only initialized
    /// on first summaryOf call that needs it.
    summary_arena: ?std.heap.ArenaAllocator = null,
    file_model: ?fmodel.FileModel = null,
    bindings: std.AutoHashMapUnmanaged(u32, local.LocalBindings) = .empty,
    summaries: std.AutoHashMapUnmanaged(u32, fn_summary.FnSummary) = .empty,

    pub fn init(gpa: std.mem.Allocator, tree: *const Ast) FileCache {
        return .{ .gpa = gpa, .tree = tree };
    }

    pub fn deinit(self: *FileCache) void {
        if (self.file_model) |*m| m.deinit();
        if (self.summary_arena) |*a| a.deinit();
        var it = self.bindings.valueIterator();
        while (it.next()) |b| b.deinit();
        self.bindings.deinit(self.gpa);
        self.summaries.deinit(self.gpa);
    }

    /// Lazily build (and cache) the FileModel for this file.
    pub fn fileModel(self: *FileCache) !*const fmodel.FileModel {
        if (self.file_model == null) {
            self.file_model = try fmodel.build(self.gpa, self.tree);
        }
        return &self.file_model.?;
    }

    /// Lazily build (and cache) LocalBindings for the given fn body.
    /// Keyed by body node — rules processing the same fn share one
    /// build.  The returned pointer is borrowed from the cache and
    /// stable for the lifetime of the cache.
    pub fn localBindings(
        self: *FileCache,
        proto: Ast.full.FnProto,
        body: Ast.Node.Index,
    ) !*const local.LocalBindings {
        const key = @intFromEnum(body);
        const gop = try self.bindings.getOrPut(self.gpa, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = try local.build(self.gpa, self.tree, proto, body);
        }
        return gop.value_ptr;
    }

    /// Lazily infer (and cache) the behavioral summary for the given
    /// fn body.  Same caching contract as localBindings.  Parallel
    /// API to annotations.Db; new code should prefer this for the
    /// queries it covers.  Body-only inference — for the deep fields
    /// (may_free_fields / result_heap_fields / heap_allocates_self),
    /// use `summaryOfFn` instead.
    pub fn summaryOf(
        self: *FileCache,
        proto: Ast.full.FnProto,
        body: Ast.Node.Index,
    ) !*const fn_summary.FnSummary {
        const key = @intFromEnum(body);
        const gop = try self.summaries.getOrPut(self.gpa, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = fn_summary.inferFromBody(self.tree, proto, body);
        }
        return gop.value_ptr;
    }

    /// Return the param's type-name (with */?/const wrappers stripped)
    /// by walking the proto's param iterator.  Used by the
    /// may_free_fields filter to look up `(param_type, field)` in the
    /// FileModel.
    fn paramTypeName(tree: *const Ast, proto: Ast.full.FnProto, idx: u32) ?[]const u8 {
        var i: u32 = 0;
        var it = proto.iterate(tree);
        while (it.next()) |p| : (i += 1) {
            if (i != idx) continue;
            const type_node = p.type_expr orelse return null;
            // Strip wrappers — same logic as model.baseTypeName but
            // inline here so we don't add a public dependency.
            const tags = tree.tokens.items(.tag);
            var t = tree.firstToken(type_node);
            const last = tree.lastToken(type_node);
            while (t <= last) : (t += 1) {
                switch (tags[t]) {
                    .asterisk, .question_mark, .keyword_const, .keyword_var, .l_bracket, .r_bracket => {},
                    .identifier => return tree.tokenSlice(t),
                    else => return null,
                }
            }
            return null;
        }
        return null;
    }

    /// Filter may_free_fields entries to match annotations.zig R10
    /// Case B's resolveMethod conservatism.  An entry survives only
    /// when:
    ///   - param's type is locally declared
    ///   - field is not pointer-typed
    ///   - field's declared type is locally declared
    ///   - the field-type's method (the one recorded in ff.method)
    ///     exists AND has takes_ownership_of != null (i.e. R10/R8b
    ///     determined that the method actually consumes its
    ///     receiver — not just that it exists).  Without this check
    ///     value-typed fields whose type has a non-consuming deinit
    ///     (e.g. ManifestLogModel.deinit that just releases
    ///     subordinate resources) get treated as freed when they
    ///     shouldn't.
    fn filterMayFreeFields(
        self: *FileCache,
        arena: std.mem.Allocator,
        model: *const fmodel.FileModel,
        tree: *const Ast,
        proto: Ast.full.FnProto,
        raw: []const fn_summary.FieldFree,
    ) ![]const fn_summary.FieldFree {
        if (raw.len == 0) return &.{};
        var out: std.ArrayListUnmanaged(fn_summary.FieldFree) = .empty;
        for (raw) |ff| {
            const param_ty = paramTypeName(tree, proto, ff.param) orelse continue;
            if (!model.hasType(param_ty)) continue;
            if (model.fieldIsPointer(param_ty, ff.field)) continue;
            const field_ty = model.fieldType(param_ty, ff.field) orelse continue;
            if (!model.hasType(field_ty)) continue;
            const ti = model.findType(field_ty) orelse continue;
            if (!ti.hasMethod(ff.method)) continue;
            // Check the field-type's method actually consumes its
            // receiver per FnSummary's transitive analysis.
            const callee_summary = (try self.summaryByMethod(field_ty, ff.method)) orelse continue;
            if (callee_summary.takes_ownership_of == null) continue;
            try out.append(arena, ff);
        }
        return out.toOwnedSlice(arena);
    }

    /// Resolve a name in `proto`'s param list to its 0-indexed
    /// position.  Local helper for the R10 transitive pass.
    fn paramIndexFor(tree: *const Ast, proto: Ast.full.FnProto, name: []const u8) ?u32 {
        var idx: u32 = 0;
        var it = proto.iterate(tree);
        while (it.next()) |p| : (idx += 1) {
            const name_tok = p.name_token orelse continue;
            if (std.mem.eql(u8, tree.tokenSlice(name_tok), name)) return idx;
        }
        return null;
    }

    /// Fixed-point pass: for every fn in the file, propagate
    /// `takes_ownership_of` transitively across `<param>.<method>()`
    /// chains.  When `method`'s summary takes its receiver (arg 0),
    /// the outer fn takes `<param>`.  Iterates until no new takes
    /// are inferred (bounded by `max_iters` to guard against
    /// pathological cases).
    ///
    /// Corresponds to annotations.zig R10 Case A (direct chain — no
    /// intermediate field segments).  Case B (`<param>.<field>.
    /// <method>()`) is deferred; tracker is `may_free_fields` for
    /// that case, which this pass already inherits via direct
    /// inference.
    ///
    /// Idempotent.  Call once per file after rule registration,
    /// before any consumer reads summaries that depend on
    /// transitive ownership.
    pub fn resolveTransitiveTakes(self: *FileCache) !void {
        const model = try self.fileModel();
        const lexer = @import("lexer.zig");

        // Phase 1a: pre-warm summaries for every fn.
        for (model.fns) |fi| _ = try self.summaryOfFn(fi.fn_decl);
        for (model.types) |ti| {
            for (ti.methods) |m| _ = try self.summaryOfFn(m.fn_decl);
        }

        // Phase 1b: seed takes_ownership_of via direct R8b inference.
        // Done explicitly here (not in inferFromBody) so the seed is
        // only applied when transitive resolution is requested —
        // pattern rules that don't go through this path get the
        // conservative .unknown / null defaults.
        const seedFn = struct {
            fn run(self2: *FileCache, fn_decl: Ast.Node.Index) !void {
                const lex = @import("lexer.zig");
                var pbuf: [1]Ast.Node.Index = undefined;
                const proto = lex.fnProto(self2.tree, &pbuf, fn_decl) orelse return;
                const body = lex.bodyOf(self2.tree, fn_decl) orelse return;
                if (fn_summary.inferDirectTakes(self2.tree, proto, body)) |idx| {
                    const key = @intFromEnum(body);
                    if (self2.summaries.getPtr(key)) |entry| {
                        if (entry.takes_ownership_of == null) {
                            entry.takes_ownership_of = idx;
                        }
                    }
                }
            }
        }.run;
        for (model.fns) |fi| try seedFn(self, fi.fn_decl);
        for (model.types) |ti| {
            for (ti.methods) |m| try seedFn(self, m.fn_decl);
        }
        _ = lexer; // imported for nested fn (above)

        // Phase 2: fixed-point R10 Case A propagation.
        var iters: u32 = 0;
        while (iters < 16) : (iters += 1) {
            var changed = false;
            for (model.fns) |fi| {
                if (try self.propagateTransitiveTakesOne(fi.fn_decl, null)) changed = true;
            }
            for (model.types) |ti| {
                for (ti.methods) |m| {
                    if (try self.propagateTransitiveTakesOne(m.fn_decl, ti.name)) changed = true;
                }
            }
            if (!changed) break;
        }

        // Phase 3: filter may_free_fields per fn.  Done here (not in
        // summaryOfFn) because the filter consults OTHER fn summaries
        // — moving it inside summaryOfFn creates a comptime dep cycle.
        // Filter requires Phase 2 to be done so the called methods'
        // takes_ownership_of reflects the transitive analysis.
        for (model.fns) |fi| try self.filterMayFreeFieldsOne(fi.fn_decl);
        for (model.types) |ti| {
            for (ti.methods) |m| try self.filterMayFreeFieldsOne(m.fn_decl);
        }
    }

    /// Apply filterMayFreeFields to one fn's summary in-place.
    fn filterMayFreeFieldsOne(self: *FileCache, fn_decl: Ast.Node.Index) !void {
        const lexer = @import("lexer.zig");
        var buf: [1]Ast.Node.Index = undefined;
        const proto = lexer.fnProto(self.tree, &buf, fn_decl) orelse return;
        const body = lexer.bodyOf(self.tree, fn_decl) orelse return;
        const key = @intFromEnum(body);
        const entry = self.summaries.getPtr(key) orelse return;
        if (entry.may_free_fields.len == 0) return;
        const model = try self.fileModel();
        if (self.summary_arena == null) {
            self.summary_arena = std.heap.ArenaAllocator.init(self.gpa);
        }
        const a = self.summary_arena.?.allocator();
        entry.may_free_fields = try self.filterMayFreeFields(a, model, self.tree, proto, entry.may_free_fields);
    }

    /// Returns true iff the fn's summary's `takes_ownership_of` was
    /// updated by this call.  Scans body for `<param>.<method>()`
    /// chains; when method's cached summary takes arg 0, the outer
    /// fn takes the param.
    fn propagateTransitiveTakesOne(
        self: *FileCache,
        fn_decl: Ast.Node.Index,
        receiver_type: ?[]const u8,
    ) !bool {
        const lexer = @import("lexer.zig");
        var buf: [1]Ast.Node.Index = undefined;
        const proto = lexer.fnProto(self.tree, &buf, fn_decl) orelse return false;
        const body = lexer.bodyOf(self.tree, fn_decl) orelse return false;

        // If we already know a takes for this fn, no work to do.
        const s_ptr = try self.summaryOfFn(fn_decl);
        if (s_ptr.takes_ownership_of != null) return false;

        const tree = self.tree;
        const tags = tree.tokens.items(.tag);
        const first = tree.firstToken(body);
        const last = tree.lastToken(body);

        var t = first;
        while (t + 3 <= last) : (t += 1) {
            if (tags[t] == .keyword_fn) {
                t = lexer.skipNestedFn(tags, t, last);
                continue;
            }
            if (tags[t] != .identifier) continue;
            if (tags[t + 1] != .period) continue;
            if (tags[t + 2] != .identifier) continue;
            if (tags[t + 3] != .l_paren) continue;
            // Reject longer chains (`a.b.c(` shouldn't match at `b.c(`).
            if (t > first and tags[t - 1] == .period) continue;

            const param_name = tree.tokenSlice(t);
            const pi = paramIndexFor(tree, proto, param_name) orelse continue;
            const method = tree.tokenSlice(t + 2);

            // Look up callee summary: method on receiver_type when
            // available, else by bare name.  Both queries hit the
            // cache (pre-warmed above), so this is O(1) per call site.
            // Try looking up the callee on the param's type (when
            // we know it from receiver_type).  Otherwise fall back
            // to the bare-name lookup — catches top-level fns and
            // methods that don't disambiguate by type.
            const callee_summary: ?*const fn_summary.FnSummary = blk: {
                if (receiver_type) |rt| {
                    if (try self.summaryByMethod(rt, method)) |s| break :blk s;
                }
                break :blk try self.summaryByName(method);
            };
            const cs = callee_summary orelse continue;
            if (cs.takes_ownership_of) |idx| {
                if (idx == 0) {
                    // Mutate the cached entry in place.
                    const key = @intFromEnum(body);
                    if (self.summaries.getPtr(key)) |entry| {
                        entry.takes_ownership_of = pi;
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// Look up the FnSummary for a top-level fn named `name`.
    /// Replaces the old `db.lookup(name)` query for the intra-file
    /// (same-file) path.  Returns null when no top-level fn matches.
    pub fn summaryByName(
        self: *FileCache,
        name: []const u8,
    ) !?*const fn_summary.FnSummary {
        const model = try self.fileModel();
        const fi = model.findFn(name) orelse return null;
        return try self.summaryOfFn(fi.fn_decl);
    }

    /// Look up the FnSummary for a method `method_name` on `type_name`.
    /// Replaces the old `db.lookupTyped(type, name)` query for the
    /// intra-file path.  Returns null when the type or method isn't
    /// declared in this file.
    pub fn summaryByMethod(
        self: *FileCache,
        type_name: []const u8,
        method_name: []const u8,
    ) !?*const fn_summary.FnSummary {
        const model = try self.fileModel();
        const ti = model.findType(type_name) orelse return null;
        const m = ti.findMethod(method_name) orelse return null;
        return try self.summaryOfFn(m.fn_decl);
    }

    /// True iff any method on the file's type `type_name` has a
    /// body that allocates a heap instance of the type itself
    /// (`<x>.create(<type_name>)` or `<x>.create(Self)`).
    ///
    /// Composes FileModel + summaryOfFn — runs FnSummary inference
    /// across the type's methods, short-circuits on first hit.
    /// Replaces the old `db.fns.iter()` heap_allocates_self scan
    /// from annotations.Db.
    pub fn anyMethodAllocatesSelf(
        self: *FileCache,
        type_name: []const u8,
    ) !bool {
        const model = try self.fileModel();
        const ti = model.findType(type_name) orelse return false;
        for (ti.methods) |m| {
            const s = try self.summaryOfFn(m.fn_decl);
            if (s.heap_allocates_self) return true;
        }
        return false;
    }

    /// Like summaryOf but also fills the deep inference fields that
    /// require allocation (`may_free_fields`, `result_heap_fields`)
    /// and the contextual field (`heap_allocates_self`).  Slice
    /// storage lives in the cache's `summary_arena`.
    pub fn summaryOfFn(
        self: *FileCache,
        fn_decl: Ast.Node.Index,
    ) !*const fn_summary.FnSummary {
        // Resolve proto + body via lexer helpers.
        var proto_buf: [1]Ast.Node.Index = undefined;
        const lexer = @import("lexer.zig");
        const proto = lexer.fnProto(self.tree, &proto_buf, fn_decl) orelse {
            // Caller passed a non-fn_decl node — return a sentinel
            // .unknown summary.  Cache by fn_decl index so we don't
            // recompute.
            const key = @intFromEnum(fn_decl) | 0x8000_0000;
            const gop = try self.summaries.getOrPut(self.gpa, key);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            return gop.value_ptr;
        };
        const body = lexer.bodyOf(self.tree, fn_decl) orelse {
            const key = @intFromEnum(fn_decl) | 0x8000_0000;
            const gop = try self.summaries.getOrPut(self.gpa, key);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            return gop.value_ptr;
        };

        const key = @intFromEnum(body);
        const gop = try self.summaries.getOrPut(self.gpa, key);
        if (gop.found_existing and gop.value_ptr._resolved) {
            // Already resolved; preserves any R10 transitive
            // mutations from prior `resolveTransitiveTakes` passes.
            return gop.value_ptr;
        }

        // Start from the cheap body-only summary, or upgrade an
        // existing (cheap-only) entry in place.
        var s = if (gop.found_existing) gop.value_ptr.* else fn_summary.inferFromBody(self.tree, proto, body);

        // Lazy-init the summary arena.
        if (self.summary_arena == null) {
            self.summary_arena = std.heap.ArenaAllocator.init(self.gpa);
        }
        const a = self.summary_arena.?.allocator();

        s.may_free_fields = try fn_summary.inferMayFreeFields(a, self.tree, proto, body);
        s.result_heap_fields = try fn_summary.inferResultHeapFields(a, self.tree, body);

        // Containing-type lookup → heap_allocates_self.
        const model = try self.fileModel();
        const ct: ?[]const u8 = if (model.containingTypeOf(fn_decl)) |ti| ti.name else null;
        s.heap_allocates_self = fn_summary.inferHeapAllocatesSelf(self.tree, body, ct);

        // NOTE: may_free_fields here is the RAW body-only inference.
        // resolveTransitiveTakes filters it as a finalization pass,
        // since the filter needs to consult OTHER summaries (creating
        // a comptime-dependency cycle if done inside summaryOfFn).

        s._resolved = true;
        gop.value_ptr.* = s;
        return gop.value_ptr;
    }
};

// ── Tests ──────────────────────────────────────────────────

test "FileCache: fileModel builds once" {
    const gpa = std.testing.allocator;
    const src: [:0]const u8 =
        \\const Foo = struct {
        \\    x: u32,
        \\    pub fn deinit(self: *Foo) void { _ = self; }
        \\};
    ;
    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);
    var cache = FileCache.init(gpa, &tree);
    defer cache.deinit();

    const a = try cache.fileModel();
    const b = try cache.fileModel();
    try std.testing.expect(a == b);
}

test "FileCache: localBindings caches per body" {
    const gpa = std.testing.allocator;
    const src: [:0]const u8 =
        \\fn foo(x: u32) void { _ = x; }
        \\fn bar(y: u32) void { _ = y; }
    ;
    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);
    var cache = FileCache.init(gpa, &tree);
    defer cache.deinit();

    // Find the two fn bodies.
    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = @import("lexer.zig").iterFnDecls(&tree);
    const foo = fns.next(&proto_buf).?;
    const bar = fns.next(&proto_buf).?;

    const a1 = try cache.localBindings(foo.proto, foo.body);
    const a2 = try cache.localBindings(foo.proto, foo.body);
    const b1 = try cache.localBindings(bar.proto, bar.body);
    try std.testing.expect(a1 == a2);
    try std.testing.expect(a1 != b1);
}

test "FileCache: resolveTransitiveTakes chains via .destroy(self) seed" {
    const gpa = std.testing.allocator;
    // A real consuming chain: kill calls .destroy(self) directly
    // (R8b infers takes=0), wrapper/outer propagate via R10 Case A.
    const src: [:0]const u8 =
        \\const T = struct {
        \\    pub fn kill(self: *T, gpa: std.mem.Allocator) void {
        \\        gpa.destroy(self);
        \\    }
        \\    pub fn wrapper(self: *T, gpa: std.mem.Allocator) void {
        \\        self.kill(gpa);
        \\    }
        \\    pub fn outer(self: *T, gpa: std.mem.Allocator) void {
        \\        self.wrapper(gpa);
        \\    }
        \\};
    ;
    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);
    var cache = FileCache.init(gpa, &tree);
    defer cache.deinit();

    try cache.resolveTransitiveTakes();

    // `kill` directly takes self via gpa.destroy(self) (R8b direct).
    const kill_s = (try cache.summaryByMethod("T", "kill")).?;
    try std.testing.expectEqual(@as(?u32, 0), kill_s.takes_ownership_of);
    // `wrapper` calls `self.kill(gpa)` — kill takes 0, so wrapper takes self.
    const wrapper_s = (try cache.summaryByMethod("T", "wrapper")).?;
    try std.testing.expectEqual(@as(?u32, 0), wrapper_s.takes_ownership_of);
    // `outer` calls `self.wrapper(gpa)` — third-level chain.
    const outer_s = (try cache.summaryByMethod("T", "outer")).?;
    try std.testing.expectEqual(@as(?u32, 0), outer_s.takes_ownership_of);
}

test "FileCache: anyMethodAllocatesSelf detects type with heap factory method" {
    const gpa = std.testing.allocator;
    const src: [:0]const u8 =
        \\const Foo = struct {
        \\    x: u32,
        \\    pub fn create(alloc: std.mem.Allocator) !*Foo {
        \\        return try alloc.create(Foo);
        \\    }
        \\    pub fn deinit(self: *Foo) void { _ = self; }
        \\};
        \\const Bar = struct {
        \\    pub fn deinit(self: *Bar) void { _ = self; }
        \\};
    ;
    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);
    var cache = FileCache.init(gpa, &tree);
    defer cache.deinit();

    try std.testing.expect(try cache.anyMethodAllocatesSelf("Foo"));
    try std.testing.expect(!try cache.anyMethodAllocatesSelf("Bar"));
    try std.testing.expect(!try cache.anyMethodAllocatesSelf("Missing"));
}

test "FileCache: summaryOfFn fills deep fields (heap_allocates_self + result_heap_fields)" {
    const gpa = std.testing.allocator;
    const src: [:0]const u8 =
        \\const Foo = struct {
        \\    bytes: []u8,
        \\    pub fn init(self_alloc: std.mem.Allocator) !*Foo {
        \\        const f = try self_alloc.create(Foo);
        \\        f.* = .{ .bytes = try self_alloc.alloc(u8, 16) };
        \\        return f;
        \\    }
        \\};
    ;
    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);
    var cache = FileCache.init(gpa, &tree);
    defer cache.deinit();

    // Find the init fn_decl.
    var idx: u32 = 1;
    while (idx < tree.nodes.len) : (idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        const s = try cache.summaryOfFn(node);
        // Body has gpa.create(Foo) on a fn inside Foo → heap_allocates_self.
        try std.testing.expect(s.heap_allocates_self);
        try std.testing.expect(s.allocates);
        break;
    }
}

test "FileCache: summaryOf caches per body, classifies alloc as heap" {
    const gpa = std.testing.allocator;
    const src: [:0]const u8 =
        \\fn alloc_one(gpa: std.mem.Allocator) ![]u8 {
        \\    return try gpa.alloc(u8, 1);
        \\}
    ;
    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);
    var cache = FileCache.init(gpa, &tree);
    defer cache.deinit();

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = @import("lexer.zig").iterFnDecls(&tree);
    const f = fns.next(&proto_buf).?;
    const a = try cache.summaryOf(f.proto, f.body);
    const b = try cache.summaryOf(f.proto, f.body);
    try std.testing.expect(a == b);
    try std.testing.expect(a.returns == .heap);
    try std.testing.expect(a.allocates);
}
