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

/// Opaque interface for resolving cross-file FileCaches.  Lives here
/// (rather than importing remote_resolver.zig) so FileCache can be
/// queried for cross-file summaries without creating an import cycle
/// — remote_resolver.zig already imports file_cache.zig.
///
/// Implementations: see `remote_resolver.RemoteSummaryAdapter` for the
/// production wrapper around `Cache + imports.Map`.
pub const RemoteSummaryCtx = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Resolve namespace name (e.g. "lib" from `const lib =
        /// @import("lib.zig");`) to a remote FileCache.  Returns null
        /// when the namespace isn't in the imap or the file can't be
        /// loaded.
        getByNamespace: *const fn (ptr: *anyopaque, namespace: []const u8) ?*FileCache,
        /// Iterate every loaded remote FileCache.  Caller initializes
        /// `state` to 0; each call returns the next cache (or null when
        /// exhausted).  Used for "anonymous param type" scans where
        /// the wrapper has no namespace to target.
        next: *const fn (ptr: *anyopaque, state: *u32) ?*FileCache,
    };

    pub fn getByNamespace(self: RemoteSummaryCtx, namespace: []const u8) ?*FileCache {
        return self.vtable.getByNamespace(self.ptr, namespace);
    }

    pub fn next(self: RemoteSummaryCtx, state: *u32) ?*FileCache {
        return self.vtable.next(self.ptr, state);
    }
};

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
    /// Transient cross-file resolution ctx — set by
    /// `resolveTransitiveTakes` for the duration of its pass so R7
    /// inference can chase delegating returns into imported files,
    /// cleared on return.  Not persisted: the cross-file query
    /// helpers in cfg.zig do their own resolution.
    remote: ?RemoteSummaryCtx = null,

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
    /// by walking the proto's param iterator.  Returns the FIRST
    /// identifier — for `*lib.T` returns "lib", not "T".  Used by
    /// the may_free_fields filter where we need to look up against
    /// `(local_type, field)` and prefix-as-namespace cases would miss
    /// anyway.  Use `paramTypePath` for cross-file resolution.
    fn paramTypeName(tree: *const Ast, proto: Ast.full.FnProto, idx: u32) ?[]const u8 {
        const path = paramTypePath(tree, proto, idx) orelse return null;
        return path.ns orelse path.type_name;
    }

    /// Like `paramTypeName` but distinguishes `<ns>.<Type>` from a
    /// bare `<Type>` leaf:
    ///   `*T`        → { ns = null,  type_name = "T" }
    ///   `*lib.T`    → { ns = "lib", type_name = "T" }
    ///   `anytype`   → null
    /// Cross-file R10 / R7 inference uses `ns` to look up via remote
    /// imap; `type_name` is the actual type whose methods we query.
    fn paramTypePath(
        tree: *const Ast,
        proto: Ast.full.FnProto,
        idx: u32,
    ) ?struct { ns: ?[]const u8, type_name: []const u8 } {
        var i: u32 = 0;
        var it = proto.iterate(tree);
        while (it.next()) |p| : (i += 1) {
            if (i != idx) continue;
            const type_node = p.type_expr orelse return null;
            const tags = tree.tokens.items(.tag);
            const last = tree.lastToken(type_node);
            var t = tree.firstToken(type_node);
            // Skip wrapper tokens; stop at the first identifier (the
            // namespace OR the type name itself).
            while (t <= last) : (t += 1) {
                switch (tags[t]) {
                    .asterisk, .question_mark, .keyword_const, .keyword_var, .l_bracket, .r_bracket => {},
                    .identifier => break,
                    else => return null,
                }
            }
            if (t > last or tags[t] != .identifier) return null;
            const first_id = tree.tokenSlice(t);
            // Is this followed by `.<identifier>`?  If so it's a
            // `<ns>.<Type>` leaf.
            if (t + 2 <= last and tags[t + 1] == .period and tags[t + 2] == .identifier) {
                return .{ .ns = first_id, .type_name = tree.tokenSlice(t + 2) };
            }
            return .{ .ns = null, .type_name = first_id };
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
            // Walk the field path one segment at a time so multi-
            // segment chains like "inner.handle" resolve to the
            // deepest type before looking up the method.
            const deepest_path = walkFieldPath(model, param_ty, ff.field) orelse continue;
            // Resolve the callee summary on the deepest field's TYPE
            // — same-file when the field type is local, else cross-
            // file via imported namespace.
            const callee_summary: ?*const fn_summary.FnSummary = blk: {
                if (deepest_path.ns) |ns| {
                    if (self.remote) |r| {
                        if (r.getByNamespace(ns)) |remote_cache| {
                            break :blk try remote_cache.summaryByMethod(deepest_path.type_name, ff.method);
                        }
                    }
                    break :blk null;
                }
                if (!model.hasType(deepest_path.type_name)) break :blk null;
                const ti = model.findType(deepest_path.type_name) orelse break :blk null;
                if (!ti.hasMethod(ff.method)) break :blk null;
                break :blk try self.summaryByMethod(deepest_path.type_name, ff.method);
            };
            const cs = callee_summary orelse continue;
            if (cs.takes_ownership_of == null) continue;
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
        return self.resolveTransitiveTakesWithRemote(null);
    }

    /// Variant that consults `remote` for cross-file R7 inference.
    /// When non-null, the R7 pass (Phase 4) can chase delegating
    /// returns into imported files via the RemoteSummaryCtx vtable.
    pub fn resolveTransitiveTakesWithRemote(
        self: *FileCache,
        remote: ?RemoteSummaryCtx,
    ) !void {
        self.remote = remote;
        defer self.remote = null;

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

        // Phase 4: fixed-point R7 inference — propagate
        // `returns = .borrowed_from(N)` across delegating wrappers.
        // Mirrors annotations.zig's R7 pass: a fn whose body returns a
        // delegating call to another fn that's annotated/inferred
        // borrowed_from inherits the borrowed_from with the local
        // param index.  Skipped when the fn's returns is already known
        // (preserves .heap / .owned / explicit borrowed_from).
        iters = 0;
        while (iters < 16) : (iters += 1) {
            var changed = false;
            for (model.fns) |fi| {
                if (try self.inferDelegatorBorrowOne(fi.fn_decl)) changed = true;
            }
            for (model.types) |ti| {
                for (ti.methods) |m| {
                    if (try self.inferDelegatorBorrowOne(m.fn_decl)) changed = true;
                }
            }
            if (!changed) break;
        }
    }

    /// Apply R7 delegator-borrow inference to one fn.  Returns true
    /// iff this call set/updated the fn's `returns` field.
    fn inferDelegatorBorrowOne(self: *FileCache, fn_decl: Ast.Node.Index) !bool {
        const lexer = @import("lexer.zig");
        var buf: [1]Ast.Node.Index = undefined;
        const proto = lexer.fnProto(self.tree, &buf, fn_decl) orelse return false;
        const body = lexer.bodyOf(self.tree, fn_decl) orelse return false;

        const s_ptr = try self.summaryOfFn(fn_decl);
        // Only fill when returns hasn't been determined yet.  Matches
        // annotations.zig R7's "only fills missing annotation" rule.
        switch (s_ptr.returns) {
            .unknown => {},
            else => return false,
        }

        const idx = try self.inferDelegatorBorrow(proto, body) orelse return false;
        const key = @intFromEnum(body);
        if (self.summaries.getPtr(key)) |entry| {
            entry.returns = .{ .borrowed_from = idx };
            return true;
        }
        return false;
    }

    /// Mirror annotations.inferDelegatorBorrow.  Tries the single-return
    /// shape first; falls back to multi-return.  Returns the borrowed
    /// param index when inference fires.
    fn inferDelegatorBorrow(
        self: *FileCache,
        proto: Ast.full.FnProto,
        body: Ast.Node.Index,
    ) !?u32 {
        if (fn_summary.singleReturnExpr(self.tree, body)) |re| {
            if (try self.tryInferFromReturnExpr(proto, re)) |idx| return idx;
        }
        return try self.inferDelegatorBorrowMultiReturn(proto, body);
    }

    /// Try every R7 shape on a single return expression.
    fn tryInferFromReturnExpr(
        self: *FileCache,
        proto: Ast.full.FnProto,
        return_expr: Ast.Node.Index,
    ) !?u32 {
        // Extends-storage form (struct literal carrying a param).
        if (fn_summary.inferReturnStructLiteralBorrowsParam(self.tree, proto, return_expr)) |idx| {
            return idx;
        }
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = self.tree.fullCall(&buf, return_expr) orelse return null;
        if (try self.inferMethodStyle(proto, return_expr)) |idx| return idx;
        return try self.inferNamespaceStyle(proto, call_full);
    }

    /// `return <param>.<chain>.<method>(args);` shape.  Fires when
    /// `<method>` is `borrowed_from(self)` (target_idx 0).
    fn inferMethodStyle(
        self: *FileCache,
        proto: Ast.full.FnProto,
        return_expr: Ast.Node.Index,
    ) !?u32 {
        const tree = self.tree;
        const first = tree.firstToken(return_expr);
        const last = tree.lastToken(return_expr);
        const tags = tree.tokens.items(.tag);

        if (tags[first] != .identifier) return null;
        if (first + 1 > last or tags[first + 1] != .period) return null;

        const head_name = tree.tokenSlice(first);
        const param_idx = fn_summary.resolveParamIndex(tree, proto, head_name) orelse return null;

        var k: Ast.TokenIndex = first + 1;
        var method_tok: Ast.TokenIndex = 0;
        while (k + 1 <= last and tags[k] == .period and tags[k + 1] == .identifier) {
            method_tok = k + 1;
            k += 2;
            if (k > last) break;
            if (tags[k] == .l_paren) break;
            if (tags[k] != .period) {
                method_tok = 0;
                break;
            }
        }
        if (method_tok == 0) return null;
        if (k > last or tags[k] != .l_paren) return null;

        const method_name = tree.tokenSlice(method_tok);
        var target_idx = try self.lookupBorrowedFromSameFile(method_name);
        if (target_idx == null) {
            target_idx = try self.lookupBorrowedFromParamType(proto, param_idx, method_name);
        }
        if ((target_idx orelse return null) == 0) return param_idx;
        return null;
    }

    /// `return <Path>.<method>(arg0, arg1, ...);` shape.  Fires when
    /// `<method>` is `borrowed_from(N)` and arg N resolves to one of
    /// our params.  Same-file first; then cross-file via namespace.
    fn inferNamespaceStyle(
        self: *FileCache,
        proto: Ast.full.FnProto,
        call_full: Ast.full.Call,
    ) !?u32 {
        const tree = self.tree;
        const callee = call_full.ast.fn_expr;
        const method_tok = switch (tree.nodeTag(callee)) {
            .identifier => tree.nodeMainToken(callee),
            .field_access => tree.nodeData(callee).node_and_token[1],
            else => return null,
        };
        const method_name = tree.tokenSlice(method_tok);
        var target_idx = try self.lookupBorrowedFromSameFile(method_name);
        if (target_idx == null) {
            // Cross-file: when callee is `Foo.method(...)` and Foo is
            // an imap namespace, look up `method` in Foo's FileCache.
            if (tree.nodeTag(callee) == .field_access) {
                const recv = tree.nodeData(callee).node_and_token[0];
                if (tree.nodeTag(recv) == .identifier) {
                    const ns = tree.tokenSlice(tree.nodeMainToken(recv));
                    target_idx = try self.lookupBorrowedFromImport(ns, method_name);
                }
            }
        }
        const idx_resolved = target_idx orelse return null;
        const args = call_full.ast.params;
        if (idx_resolved >= args.len) return null;
        const arg = args[idx_resolved];
        if (tree.nodeTag(arg) != .identifier) return null;
        const arg_name = tree.tokenSlice(tree.nodeMainToken(arg));
        return fn_summary.resolveParamIndex(tree, proto, arg_name);
    }

    /// Same-file equivalent of annotations.lookupBorrowedFromSameFile.
    /// Looks up a top-level fn by name and returns its `borrowed_from`
    /// target index when the summary's returns is that variant.
    fn lookupBorrowedFromSameFile(self: *FileCache, method_name: []const u8) !?u32 {
        const s = (try self.summaryByName(method_name)) orelse return null;
        return switch (s.returns) {
            .borrowed_from => |idx| idx,
            else => null,
        };
    }

    /// Cross-file equivalent: look up `method_name` in the FileCache
    /// of the imported namespace `ns`.  No-ops when remote ctx is
    /// absent or the namespace isn't in the imap.
    fn lookupBorrowedFromImport(self: *FileCache, ns: []const u8, method_name: []const u8) !?u32 {
        const remote = self.remote orelse return null;
        const remote_cache = remote.getByNamespace(ns) orelse return null;
        const s = (try remote_cache.summaryByName(method_name)) orelse return null;
        return switch (s.returns) {
            .borrowed_from => |idx| idx,
            else => null,
        };
    }

    /// AST-level param-type resolution: read the named param's type
    /// annotation, strip wrappers, find the `<ns>.<TypeName>` leaf,
    /// and look up `method_name` in `<ns>`.  For genuinely anonymous
    /// param types (`anytype`, inline struct), scan every loaded
    /// remote file for a unique match.
    fn lookupBorrowedFromParamType(
        self: *FileCache,
        proto: Ast.full.FnProto,
        param_idx: u32,
        method_name: []const u8,
    ) !?u32 {
        const remote = self.remote orelse return null;
        const tree = self.tree;

        var idx: u32 = 0;
        var it = proto.iterate(tree);
        const param = while (it.next()) |p| : (idx += 1) {
            if (idx == param_idx) break p;
        } else return null;
        const type_node = param.type_expr orelse {
            if (param.anytype_ellipsis3 != null) {
                return try scanRemoteForBorrowedFrom(remote, method_name);
            }
            return null;
        };

        // Walk type tokens for the first `<id>.<id>` pair as the
        // namespace.Type leaf.
        const first = tree.firstToken(type_node);
        const last = tree.lastToken(type_node);
        const tags = tree.tokens.items(.tag);
        var t: Ast.TokenIndex = first;
        while (t < last) : (t += 1) {
            if (tags[t] != .identifier) continue;
            if (t > first and tags[t - 1] == .period) continue;
            if (t + 2 > last) break;
            if (tags[t + 1] != .period) continue;
            if (tags[t + 2] != .identifier) continue;
            const ns = tree.tokenSlice(t);
            return try self.lookupBorrowedFromImport(ns, method_name);
        }

        if (isAnonymousParamType(tree, type_node)) {
            return try scanRemoteForBorrowedFrom(remote, method_name);
        }
        return null;
    }

    /// Multi-return-stmt variant: walk every `return EXPR;` whose
    /// token range lies within `body`, infer per-return, and return
    /// `borrowed_from(N)` only when at least one return matched AND
    /// every matched return agreed on the same N.  Non-borrow shapes
    /// (literals / null / undefined / `&.{}`) are skipped.
    fn inferDelegatorBorrowMultiReturn(
        self: *FileCache,
        proto: Ast.full.FnProto,
        body: Ast.Node.Index,
    ) !?u32 {
        const tree = self.tree;
        const body_first = tree.firstToken(body);
        const body_last = tree.lastToken(body);

        var found: ?u32 = null;
        var any_match = false;

        var node_idx: u32 = 1;
        while (node_idx < tree.nodes.len) : (node_idx += 1) {
            const node: Ast.Node.Index = @enumFromInt(node_idx);
            if (tree.nodeTag(node) != .@"return") continue;
            const ft = tree.firstToken(node);
            const lt = tree.lastToken(node);
            if (ft < body_first or lt > body_last) continue;

            const value = tree.nodeData(node).opt_node.unwrap() orelse continue;
            if (fn_summary.isNonBorrowReturnValue(tree, value)) continue;

            const idx = try self.tryInferFromReturnExpr(proto, value) orelse return null;
            if (found) |existing| if (existing != idx) return null;
            found = idx;
            any_match = true;
        }
        if (!any_match) return null;
        return found.?;
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

            // Look up callee summary on PARAM's declared type — that's
            // the receiver of `<param>.<method>(`.  Tries same-file,
            // then cross-file (when type is `<ns>.<Type>` and remote
            // is wired).  Falls back to the outer fn's containing type
            // and bare-name lookup for legacy patterns.
            const callee_summary: ?*const fn_summary.FnSummary = blk: {
                if (paramTypePath(tree, proto, pi)) |path| {
                    if (path.ns) |ns| {
                        // Cross-file: resolve <ns> → remote FileCache,
                        // look up <type_name>.<method> there.
                        if (self.remote) |r| {
                            if (r.getByNamespace(ns)) |remote_cache| {
                                if (try remote_cache.summaryByMethod(path.type_name, method)) |s| {
                                    break :blk s;
                                }
                            }
                        }
                    } else {
                        if (try self.summaryByMethod(path.type_name, method)) |s| break :blk s;
                    }
                }
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

/// Walk a dotted field path (e.g. "inner.handle") through a struct
/// type chain, returning the DEEPEST field's type as a path split.
/// For a single-segment path "f", returns `<outer>.f`'s type.  For
/// multi-segment "f.g.h", walks outer.f -> field-type-of-f, then
/// that.g, then that.h, returning the leaf type.
///
/// Stops + returns null when any intermediate field's type isn't
/// resolvable in the local model (cross-file intermediates that
/// aren't loaded yet — uncommon, and the conservative answer is to
/// drop the entry).
fn walkFieldPath(
    model: *const fmodel.FileModel,
    outer_type: []const u8,
    path: []const u8,
) ?fmodel.FileModel.FieldTypePath {
    var it = std.mem.splitScalar(u8, path, '.');
    var cur_outer: []const u8 = outer_type;
    var last_result: ?fmodel.FileModel.FieldTypePath = null;
    while (it.next()) |segment| {
        const ftp = model.fieldTypePath(cur_outer, segment) orelse return null;
        last_result = ftp;
        // For the next iteration we need a bare type name — if this
        // segment's type was `<ns>.<Type>` we'd need to load the
        // remote file to walk further.  We don't have a remote
        // pointer here; conservative: stop and return null if there
        // are more segments to walk.
        if (it.peek() == null) break;
        if (ftp.ns != null) return null;
        cur_outer = ftp.type_name;
    }
    return last_result;
}

/// True iff the param's type-expr is `anytype` or an inline
/// `struct { ... }` — both lack a name we can resolve through imap.
fn isAnonymousParamType(tree: *const Ast, type_node: Ast.Node.Index) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .asterisk, .question_mark, .l_bracket, .r_bracket => continue,
            .keyword_const => continue,
            .identifier => {
                const s = tree.tokenSlice(t);
                if (std.mem.eql(u8, s, "anytype")) return true;
                return false;
            },
            .keyword_struct, .keyword_union, .keyword_enum, .keyword_opaque => return true,
            else => return false,
        }
    }
    return false;
}

/// Scan every loaded remote FileCache for `method_name`.  Returns the
/// SINGLE target_idx if exactly one remote has it as `borrowed_from`;
/// null on miss OR ambiguity (two remotes with different indices).
fn scanRemoteForBorrowedFrom(remote: RemoteSummaryCtx, method_name: []const u8) !?u32 {
    var state: u32 = 0;
    var found: ?u32 = null;
    while (remote.next(&state)) |remote_cache| {
        const s = (try remote_cache.summaryByName(method_name)) orelse continue;
        const idx = switch (s.returns) {
            .borrowed_from => |i| i,
            else => continue,
        };
        if (found) |existing| if (existing != idx) return null;
        found = idx;
    }
    return found;
}

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
