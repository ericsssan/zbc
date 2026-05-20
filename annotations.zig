//! Annotation database — extracts `/// @returns ...` doc comments from
//! a parsed file, keyed by function name.  classifyCall consults this
//! when it sees a call so the analyzer can model the callee's
//! lifetime contract without inlining its body.
//!
//! Two annotation forms — the minimum vocabulary for arena-escape:
//!   /// @returns owned                  — caller owns the result
//!   /// @returns borrowed_from(<param>) — result borrows from param
//!
//! Plus one inference rule (R6): fns returning a slice whose body
//! contains an allocation call get @returns owned inferred.  Caller
//! doesn't need to write the annotation just to silence Layer-1
//! hygiene warnings.

const std = @import("std");
const Ast = std.zig.Ast;
const config_mod = @import("config.zig");
const imports_mod = @import("imports.zig");
const remote_resolver_mod = @import("remote_resolver.zig");

/// R8 inference uses these to recognize alloc/free wrappers.
/// Default to the canonical std allocator surface so callers that
/// pass `null` get the common patterns out of the box.
const default_heap_alloc_patterns: []const []const u8 = &.{
    ".alloc(",        ".allocSentinel(", ".create(",
    ".dupe(",         ".dupeZ(",         ".allocPrint(",
    ".allocPrintZ(",
};
const default_heap_free_patterns: []const []const u8 = &.{
    ".free(", ".destroy(",
};

pub const ReturnsAnnotation = union(enum) {
    /// `/// @returns owned` — caller owns, no lifetime constraint.
    owned,
    /// `/// @returns borrowed_from(<param>)` — return borrows from the
    /// named param.  `param_index` is the 0-based position resolved at
    /// extraction time so call sites don't re-walk params.
    borrowed_from: u32,
    /// `/// @returns owns_locals` — escape hatch for the canonical
    /// init() pattern.  Suppresses the composite-borrow check in
    /// this fn: any local arena/heap referenced in the returned
    /// composite is treated as MOVED to the caller, not borrowed.
    /// Use when zbc's pattern inference flags a value-shape return
    /// that semantically transfers ownership.
    owns_locals,
    /// `/// @returns heap` — caller receives a fresh heap allocation.
    /// Stronger than `.owned`: result gets a tracked HeapId at the
    /// call site so subsequent free/use-after-free analysis fires.
    /// Use on allocator wrappers (`fn xalloc(gpa, n) ![]u8 { ... }`).
    heap,
};

pub const TakesAnnotation = union(enum) {
    /// `/// @takes ownership(<param>)` — the call is a free site
    /// for the named param's heap allocation.  Caller emits a
    /// .heap_free against that arg at the call site.
    ownership: u32,
};

/// One field-of-param free effect.  Carried in lists on
/// `FnEntry.may_free_fields`; one entry per `<param>.<field>.<method>()`
/// chain found in the body that resolves to a destroying method.
pub const FieldFree = struct {
    /// Index of the param whose field is freed.  0 is the receiver
    /// for method-call-style invocations; > 0 is a regular arg.
    param: u32,
    /// Field name (borrowed from source — keep tree alive).
    field: []const u8,
};

pub const FnEntry = struct {
    /// Function name (slice into source — keep source alive).
    name: []const u8,
    /// Name of the struct/union/enum the fn was declared inside, or
    /// null for top-level fns.  Used by lookupTyped to disambiguate
    /// methods that share a name across types (`finalize` on both
    /// `HTMLRewriter` and `HTMLRewriterLoader`).
    containing_type: ?[]const u8 = null,
    /// `@returns ...` annotation if present.  Null for fns that
    /// only carry a `@takes` signal — their return value isn't
    /// classified specially at call sites.
    annotation: ?ReturnsAnnotation,
    /// Optional `@takes` annotation.  Independent of `annotation`.
    takes: ?TakesAnnotation = null,
    /// True iff the fn's declared return type is `noreturn`.
    /// Detected at extraction time so call sites can terminate
    /// their basic block (the call diverges, no successor state).
    is_noreturn: bool = false,
    /// (Unused stub; reserved for future R9 self-freeing inference
    /// that's distinct from R8b's `@takes(ownership)`.)
    may_free_self: bool = false,
    /// Per-param field-frees inferred from `<param>.<field>.
    /// <destroying-method>()` chains in the body — R10's
    /// field-chain inference.  Each entry says "the call frees
    /// `<arg_at_param>.<field>`."  Caller maps the param index to
    /// the corresponding call argument and emits a
    /// `.field_heap_free` per entry.
    ///
    /// Slices borrow field names from source; the outer slice is
    /// owned by the Db (freed on `Db.deinit`).  Empty when no
    /// chain matched.  Supports multiple frees per body and frees
    /// on non-receiver params alike.
    may_free_fields: []const FieldFree = &.{},
};

pub const Db = struct {
    /// Multi-map: each name keys an array of entries, one per
    /// fn_decl with that name.  Most names have exactly one entry;
    /// methods that overload across types (e.g. `finalize` on both
    /// `HTMLRewriter` and `HTMLRewriterLoader`) have more.
    /// Disambiguation by containing_type lives in `lookupTyped`.
    fns: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(FnEntry)),
    /// fn_decl AST node → containing struct/union/enum type name.
    /// Populated by buildFull's pre-pass.  Lets the cfg builder
    /// pull `self_type` for the fn it's lowering so `*Self` /
    /// `*@This()` resolve correctly and `<recv>.method()` look-ups
    /// disambiguate by recv type.
    containing_types: std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8) = .empty,
    /// (containing-struct, field-name) → declared field type name
    /// (with `*` / `?` / `const` stripped, `Self` resolved).  Lets
    /// `<local>.<field>.<method>()` call sites scope the method
    /// lookup to the FIELD's type rather than the local's type or
    /// the bare name.
    field_types: std.HashMapUnmanaged(FieldKey, []const u8, FieldKey.Context, std.hash_map.default_max_load_percentage) = .empty,

    pub fn deinit(self: *Db, gpa: std.mem.Allocator) void {
        var it = self.fns.valueIterator();
        while (it.next()) |list| {
            for (list.items) |e| {
                if (e.may_free_fields.len > 0) gpa.free(e.may_free_fields);
            }
            list.deinit(gpa);
        }
        self.fns.deinit(gpa);
        self.containing_types.deinit(gpa);
        self.field_types.deinit(gpa);
    }

    /// (struct_name, field_name) → declared field type name, or
    /// null when the struct or field isn't known (or the field has
    /// no resolvable base type — slice / array / fn ptr).
    pub fn fieldType(self: *const Db, struct_name: []const u8, field_name: []const u8) ?[]const u8 {
        return self.field_types.get(.{ .containing_type = struct_name, .name = field_name });
    }

    pub const FieldKey = struct {
        containing_type: []const u8,
        name: []const u8,
        pub const Context = struct {
            pub fn hash(_: Context, k: FieldKey) u64 {
                var h: u64 = 0;
                for (k.containing_type) |c| h = h *% 31 +% c;
                h = h *% 31 +% '.';
                for (k.name) |c| h = h *% 31 +% c;
                return h;
            }
            pub fn eql(_: Context, a: FieldKey, b: FieldKey) bool {
                return std.mem.eql(u8, a.containing_type, b.containing_type) and
                    std.mem.eql(u8, a.name, b.name);
            }
        };
    };

    /// Returns the containing type name for a fn_decl AST node, or
    /// null when the fn is top-level (or the node isn't a fn_decl).
    pub fn containingType(self: *const Db, fn_decl: Ast.Node.Index) ?[]const u8 {
        return self.containing_types.get(fn_decl);
    }

    /// True iff this file declares any fn inside the struct/union/
    /// enum named `type_name`.  Used by cross-file type-aware
    /// lookups to skip imports that don't define the type.
    pub fn hasType(self: *const Db, type_name: []const u8) bool {
        var it = self.containing_types.valueIterator();
        while (it.next()) |v| {
            if (std.mem.eql(u8, v.*, type_name)) return true;
        }
        return false;
    }

    /// Look up by name only.  Counts entries with at least one signal
    /// (annotation, takes, or is_noreturn).  Returns the single
    /// signal-carrying entry, or null when count != 1.
    ///
    /// Empty entries (Pass 1 placeholders for overloads without
    /// inferred or explicit signal) are skipped — they're load-
    /// bearing for the multi-map's count of total declarations but
    /// shouldn't shadow a sibling overload's real annotation when
    /// the caller has no receiver-type information.  Multiple
    /// signal-carrying entries DO collapse to null, matching the
    /// "we can't pick an overload without type info" rule.
    pub fn lookup(self: *const Db, name: []const u8) ?FnEntry {
        const list = self.fns.get(name) orelse return null;
        var found: ?FnEntry = null;
        var count: u32 = 0;
        for (list.items) |e| {
            if (entryIsEmpty(e)) continue;
            count += 1;
            found = e;
        }
        if (count != 1) return null;
        return found;
    }

    /// True iff a Pass-1 placeholder — no annotation, no takes, not
    /// noreturn, no inferred field-frees.  Used by `lookup` to skip
    /// these when counting overloads.
    fn entryIsEmpty(e: FnEntry) bool {
        return e.annotation == null and e.takes == null and !e.is_noreturn and
            e.may_free_fields.len == 0 and !e.may_free_self;
    }

    /// Look up a method by (containing_type, name).  When `ty` is
    /// known: return the entry whose containing_type matches
    /// exactly, or null.  Crucially: do NOT fall back to bare-name
    /// lookup when ty was given — that would return a sibling
    /// overload's entry (the classic `HTMLRewriter.finalize` /
    /// `HTMLRewriterLoader.finalize` trap, where the wrong-type
    /// match would propagate @takes(0) to all `<loader>.finalize()`
    /// calls).  When `ty` is null (recv type unknown), fall back to
    /// bare-name lookup with its own ambiguity guard.
    pub fn lookupTyped(self: *const Db, ty: ?[]const u8, name: []const u8) ?FnEntry {
        if (ty) |t| {
            const list = self.fns.get(name) orelse return null;
            for (list.items) |e| {
                if (e.containing_type) |ct| {
                    if (std.mem.eql(u8, ct, t)) return e;
                }
            }
            return null;
        }
        return self.lookup(name);
    }

    /// Lower-level helper for callers that want to iterate matching
    /// entries themselves (e.g. R10 inference checking whether ALL
    /// overloads agree on @takes(0)).
    pub fn lookupAll(self: *const Db, name: []const u8) []const FnEntry {
        const list = self.fns.get(name) orelse return &.{};
        return list.items;
    }
};

/// Find an existing entry by (name, containing_type) without
/// inserting.  Returns a copy by value (callers that want to mutate
/// in place go through `putOrUpdate`).
fn findByCt(db: *const Db, name: []const u8, ct: ?[]const u8) ?FnEntry {
    const list = db.fns.get(name) orelse return null;
    for (list.items) |e| {
        const a_null = e.containing_type == null;
        const b_null = ct == null;
        if (a_null and b_null) return e;
        if (!a_null and !b_null and std.mem.eql(u8, e.containing_type.?, ct.?)) return e;
    }
    return null;
}

/// Helper for the build passes: append-or-update an entry by
/// (name, containing_type).  Returns a pointer to the entry in db.fns
/// so callers can mutate fields in place.
fn putOrUpdate(
    db: *Db,
    gpa: std.mem.Allocator,
    name: []const u8,
    containing_type: ?[]const u8,
    initial: FnEntry,
) !*FnEntry {
    const gop = try db.fns.getOrPut(gpa, name);
    if (!gop.found_existing) {
        gop.value_ptr.* = .empty;
    }
    // Find existing entry with the same containing_type, or append.
    for (gop.value_ptr.items) |*e| {
        const a_null = e.containing_type == null;
        const b_null = containing_type == null;
        if (a_null and b_null) return e;
        if (!a_null and !b_null and std.mem.eql(u8, e.containing_type.?, containing_type.?)) return e;
    }
    try gop.value_ptr.append(gpa, initial);
    return &gop.value_ptr.items[gop.value_ptr.items.len - 1];
}

/// Walk every fn_decl in `tree`, extract any explicit `@returns`
/// annotation, then run inference (R6, R7, R8) to fill obvious holes.
/// `config` is consulted for the alloc/free text patterns used by R8;
/// pass null to fall back to the std-allocator defaults.
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !Db {
    return buildWithConfig(gpa, tree, null);
}

/// Optional remote ctx for R7 cross-file inference.  When provided,
/// inferDelegatorBorrow can look up callees defined in imported
/// files and infer wrappers that delegate across module boundaries.
pub const RemoteCtx = struct {
    imap: *const imports_mod.Map,
    base_dir: []const u8,
    cache: *remote_resolver_mod.Cache,
};

pub fn buildWithConfig(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: ?*const config_mod.Config,
) !Db {
    return buildFull(gpa, tree, config, null);
}

pub fn buildFull(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: ?*const config_mod.Config,
    remote: ?RemoteCtx,
) !Db {
    const alloc_patterns = if (config) |c| c.heap_alloc_patterns else default_heap_alloc_patterns;
    const free_patterns = if (config) |c| c.heap_free_patterns else default_heap_free_patterns;

    var db: Db = .{ .fns = .empty };
    errdefer db.deinit(gpa);

    // Pre-pass — for each fn_decl, find its containing struct/union/
    // enum type; for each field declaration, record its declared
    // type.  Together these let `<recv>.<field>.<method>()` calls
    // disambiguate by both the local's type and the field's type.
    try discoverContainingTypes(gpa, tree, &db.containing_types, &db.field_types);
    const fn_to_type = &db.containing_types;

    // Pass 1 — explicit annotations + R6 (slice + body allocs → owned).
    //
    // Only walk fn_decl nodes (fns with bodies).  `fullFnProto` would
    // also succeed for the standalone fn_proto node *inside* each
    // fn_decl — that double-processes every fn and (with the new
    // multi-map keyed by containing_type) inserts duplicate entries
    // for the proto's ct=null entry, making the name ambiguous and
    // poisoning bare-name lookups.
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        const name_tok = fn_proto.name_token orelse continue;

        var annotation = parseReturnsAnnotation(tree, fn_proto);
        const takes_anno = parseTakesAnnotation(tree, fn_proto);
        const is_noreturn = if (fn_proto.ast.return_type.unwrap()) |rt|
            returnTypeIsNoreturn(tree, rt)
        else
            false;

        if (annotation == null and tree.nodeTag(node) == .fn_decl) {
            if (fn_proto.ast.return_type.unwrap()) |rt| {
                if (typeIsSliceShaped(tree, rt)) {
                    const body = tree.nodeData(node).node_and_node[1];
                    if (bodyContainsAllocation(tree, body)) {
                        annotation = .owned;
                    }
                }
            }
        }

        // Register the entry even when it has NO signal of any flavor.
        // Sounds wasteful, but it's load-bearing for type-aware
        // lookup: the multi-map needs to see every overload so that
        // `lookupTyped(T2, name)` can RETURN NULL when name's only
        // entry with a signal belongs to type T1 (the other type's
        // method is unrelated).  Without this, T2's call site falls
        // back to the single-entry bare-name lookup and inherits
        // T1's @takes — the classic html_rewriter FP.
        const name = tree.tokenSlice(name_tok);
        const ct = fn_to_type.get(node);
        _ = try putOrUpdate(&db, gpa, name, ct, .{
            .name = name,
            .containing_type = ct,
            .annotation = annotation,
            .takes = takes_anno,
            .is_noreturn = is_noreturn,
        });
    }

    // Pass 2 — R7: trivial delegators.
    //   pub fn wrap(p: T, ...) RetT { return p.<chain>.<method>(args); }
    // where `method` is annotated `@returns borrowed_from(self)`
    //   →  infer `@returns borrowed_from(p)` for `wrap`.
    //
    // Iterate to fixed point so wrapper-of-wrapper chains resolve
    // regardless of source order (wrap2-before-wrap1 etc.).  Each
    // pass either adds at least one new annotation or stops; with N
    // wrappers, terminates in ≤ N+1 passes.
    while (true) {
        var added = false;
        node_idx = 1;
        while (node_idx < tree.nodes.len) : (node_idx += 1) {
            const node: Ast.Node.Index = @enumFromInt(node_idx);
            if (tree.nodeTag(node) != .fn_decl) continue;
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
            const name_tok = fn_proto.name_token orelse continue;
            const name = tree.tokenSlice(name_tok);
            const ct = fn_to_type.get(node);
            // R7 only fills missing `.annotation`.  An entry with
            // only `.takes` (no return annotation) is still a
            // candidate for R7 to enrich.
            const existing = findByCt(&db, name, ct);
            if (existing != null and existing.?.annotation != null) continue;

            const body = tree.nodeData(node).node_and_node[1];
            const inferred = inferDelegatorBorrow(tree, fn_proto, body, &db, remote) orelse continue;
            const ep = try putOrUpdate(&db, gpa, name, ct, .{
                .name = name,
                .containing_type = ct,
                .annotation = inferred,
                .takes = if (existing) |e| e.takes else null,
                .is_noreturn = if (existing) |e| e.is_noreturn else false,
            });
            ep.annotation = inferred;
            added = true;
        }
        if (!added) break;
    }

        // Pass 3 — R8: alloc-wrapper and free-wrapper inference.
    //   `fn xalloc(g, n) []u8 { return g.alloc(u8, n) catch ...; }`
    //     → infer @returns heap
    //   `fn dispose(g, p) void { g.free(p); }`
    //     → infer @takes ownership(p)
    node_idx = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        const name_tok = fn_proto.name_token orelse continue;
        const name = tree.tokenSlice(name_tok);
        const ct = fn_to_type.get(node);
        const body = tree.nodeData(node).node_and_node[1];

        const existing = findByCt(&db, name, ct);
        var entry: FnEntry = existing orelse .{
            .name = name,
            .containing_type = ct,
            .annotation = null,
            .takes = null,
            .is_noreturn = false,
        };
        var changed = false;

        // R8 .heap overrides R6's .owned because it carries more
        // information (the caller mints a HeapId so free/UAF can
        // fire).  Other annotations (.borrowed_from, .owns_locals,
        // explicit .heap already, R7 outputs) are kept as-is.
        const can_set_heap = entry.annotation == null or entry.annotation.? == .owned;
        if (can_set_heap and inferReturnsHeap(tree, body, alloc_patterns)) {
            entry.annotation = .heap;
            changed = true;
        }
        if (entry.takes == null) {
            if (inferTakesOwnership(tree, fn_proto, body, free_patterns)) |t| {
                entry.takes = t;
                changed = true;
            }
        }
        if (changed) {
            const ep = try putOrUpdate(&db, gpa, name, ct, entry);
            ep.* = entry;
        }
    }

    // Pass 4 — R10: transitive receiver-freeing inference.
    //   `fn outer(this: *T) void { this.finalize(); }` where finalize
    //   is @takes ownership(0) (R8b inferred or annotated)  →  outer
    //   is also @takes ownership(0).
    //
    // Iterate to fixed point so chains resolve regardless of source
    // order (`onFinish` calls `finalize` which calls `bun.destroy(self)`
    // — three levels deep).  Conservative direction matches R8b:
    // "MAY free" is the safe answer for UAF detection.
    while (true) {
        var added = false;
        node_idx = 1;
        while (node_idx < tree.nodes.len) : (node_idx += 1) {
            const node: Ast.Node.Index = @enumFromInt(node_idx);
            if (tree.nodeTag(node) != .fn_decl) continue;
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
            const name_tok = fn_proto.name_token orelse continue;
            const name = tree.tokenSlice(name_tok);
            const ct = fn_to_type.get(node);
            const existing = findByCt(&db, name, ct);
            const had_takes = existing != null and existing.?.takes != null;
            const had_fields = existing != null and existing.?.may_free_fields.len > 0;
            // Skip fns that already have both kinds of info — no
            // further inference can add anything.
            if (had_takes and had_fields) continue;

            const body = tree.nodeData(node).node_and_node[1];
            const inferred = try inferTakesViaReceiverCall(gpa, tree, fn_proto, body, &db, ct, remote);

            // Decide what's NEW.  Don't overwrite existing data —
            // R8b's direct-free inference + explicit @takes are
            // higher-confidence than R10's chain inference.
            const got_new_takes = !had_takes and inferred.takes != null;
            const got_new_fields = !had_fields and inferred.may_free_fields.len > 0;
            if (!got_new_takes and !got_new_fields) {
                // Nothing new — drop any allocated slice on the floor.
                if (inferred.may_free_fields.len > 0) gpa.free(inferred.may_free_fields);
                continue;
            }

            const new_takes = if (had_takes) existing.?.takes else inferred.takes;
            const new_fields = if (had_fields)
                existing.?.may_free_fields
            else
                inferred.may_free_fields;
            // Free the unused allocation if we didn't end up
            // adopting it.
            if (!got_new_fields and inferred.may_free_fields.len > 0) {
                gpa.free(inferred.may_free_fields);
            }
            const ep = try putOrUpdate(&db, gpa, name, ct, .{
                .name = name,
                .containing_type = ct,
                .annotation = if (existing) |e| e.annotation else null,
                .takes = new_takes,
                .is_noreturn = if (existing) |e| e.is_noreturn else false,
                .may_free_fields = new_fields,
            });
            ep.takes = new_takes;
            ep.may_free_fields = new_fields;
            added = true;
        }
        if (!added) break;
    }

    return db;
}

/// R8a: body is `{ return EXPR; }` or `{ var x = EXPR; return x; }`
/// AND EXPR's leading-token text contains any alloc pattern.
/// EXPR may be wrapped in `try`/`catch` — we already see through both
/// at classifyExpr time, so detect them here too.
fn inferReturnsHeap(
    tree: *const Ast,
    body_node: Ast.Node.Index,
    alloc_patterns: []const []const u8,
) bool {
    var expr = singleReturnExpr(tree, body_node) orelse return false;
    while (true) {
        switch (tree.nodeTag(expr)) {
            .@"try" => expr = tree.nodeData(expr).node,
            .@"catch" => expr = tree.nodeData(expr).node_and_node[0],
            else => break,
        }
    }
    const is_call = switch (tree.nodeTag(expr)) {
        .call, .call_one, .call_comma, .call_one_comma => true,
        else => false,
    };
    if (!is_call) return false;
    return callTextMatchesAny(tree, expr, alloc_patterns);
}

/// R10: transitive receiver-freeing inference.
///
/// Walk `body_node`'s tokens for `<param>.<method>(` shape — a method
/// call where the receiver is one of our function's parameters.  If
/// `<method>` resolves to a fn in `db` with `takes = .ownership(0)`
/// (the callee frees its receiver), infer `@takes ownership(<param>)`
/// on this function.
///
/// Same conservative direction as R8b: "MAY free" is the safe answer
/// for UAF detection.  Conditional / loop-nested receiver-freeing
/// calls are intentionally included — the caller can't tell the
/// runtime branch ahead of time, and missing real UAFs is worse than
/// over-reporting on cold paths.
///
/// Does NOT recurse through deeper chains like `this.field.method()`
/// — only direct `<param>.<method>()`.  Deeper field chains would
/// require type info zbc doesn't track.
/// R10 inference result.  Either or both fields may be set.
///   - `takes` is the classic `<param>.<destroying-method>()`
///     shape (frees the param itself).
///   - `may_free_fields` is the list of `{param, field}` pairs
///     from `<param>.<field>.<destroying-method>()` chains.
///     Multi-valued: a wrapper that destroys `this.a`, `this.b`
///     AND `other.c` gets all three entries.  Caller owns the
///     slice via gpa.
const InferReceiverResult = struct {
    takes: ?TakesAnnotation = null,
    may_free_fields: []const FieldFree = &.{},
};

fn inferTakesViaReceiverCall(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body_node: Ast.Node.Index,
    db: *const Db,
    self_type: ?[]const u8,
    remote: ?RemoteCtx,
) !InferReceiverResult {
    const first = tree.firstToken(body_node);
    const last = tree.lastToken(body_node);
    const tags = tree.tokens.items(.tag);

    var result: InferReceiverResult = .{};
    var fields: std.ArrayListUnmanaged(FieldFree) = .empty;
    errdefer fields.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        // Reject longer-chain heads — `a.b.c(...)` where we'd match
        // at `b.c(` but `b` isn't a function param.  Skip if the
        // token BEFORE our receiver is `.` (we're mid-chain).
        if (t > 0 and tags[t - 1] == .period) continue;

        const param_name = tree.tokenSlice(t);
        const param_idx = resolveParamIndex(tree, fn_proto, param_name) orelse continue;
        const parent_ty = paramTypeName(tree, fn_proto, param_idx, self_type);

        // Scan the dotted chain after `<param>` to find the trailing
        // method call.  Build the field path (everything between the
        // param and the method).  Cases:
        //   `<param>.<method>(`                         — depth 0 path (no fields)
        //   `<param>.<f1>.<method>(`                    — depth 1 path "f1"
        //   `<param>.<f1>.<f2>.<method>(`               — depth 2 path "f1.f2"
        //   `<param>.<f1>.<f2>...<fN>.<method>(`        — depth N
        //
        // The trailing `(` is what distinguishes the method ident
        // from a field ident.  Without `(`, the chain is just a
        // field-access expression — no method call to propagate.
        const chain = scanFieldChain(tree, t, last) orelse continue;
        // chain.method_tok is the ident immediately before `(`;
        // chain.first_field_tok / last_field_tok bracket the field
        // identifiers (or null if depth = 0).
        const method_name = tree.tokenSlice(chain.method_tok);

        if (chain.first_field_tok == null) {
            // CASE A.  No fields between param and method.  This is
            // the classic `<param>.<method>()` shape — propagates
            // ownership of the param itself.
            if (result.takes != null) continue; // first match wins
            const callee = resolveMethod(db, parent_ty, method_name, remote) orelse continue;
            const callee_takes = callee.takes orelse continue;
            switch (callee_takes) {
                .ownership => |i| if (i == 0) {
                    result.takes = .{ .ownership = param_idx };
                },
            }
            continue;
        }

        // CASE B.  Walk the type chain so we can look up the method
        // against the deepest field's type.
        const pty = parent_ty orelse continue;
        var cur_ty: []const u8 = pty;
        var resolution_ok = true;
        var ft: Ast.TokenIndex = chain.first_field_tok.?;
        while (ft <= chain.last_field_tok.?) : (ft += 2) {
            const fname = tree.tokenSlice(ft);
            const next_ty = db.fieldType(cur_ty, fname) orelse {
                resolution_ok = false;
                break;
            };
            cur_ty = next_ty;
        }
        if (!resolution_ok) continue;

        const callee = resolveMethod(db, cur_ty, method_name, remote) orelse continue;
        const callee_takes = callee.takes orelse continue;
        switch (callee_takes) {
            .ownership => |i| if (i == 0) {
                // Build the field-path string as a SOURCE SLICE
                // from the first field's start to the last field's
                // end — no allocation needed.
                const start_byte = tree.tokens.items(.start)[chain.first_field_tok.?];
                const last_start = tree.tokens.items(.start)[chain.last_field_tok.?];
                const last_len = tree.tokenSlice(chain.last_field_tok.?).len;
                const path = tree.source[start_byte..(last_start + last_len)];
                // Dedupe: same (param, path) seen?
                var already_seen = false;
                for (fields.items) |existing| {
                    if (existing.param == param_idx and
                        std.mem.eql(u8, existing.field, path))
                    {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen) try fields.append(gpa, .{
                    .param = param_idx,
                    .field = path,
                });
            },
        }
    }

    if (fields.items.len > 0) {
        result.may_free_fields = try fields.toOwnedSlice(gpa);
    }
    return result;
}

/// Resolve a method by (containing_type, name) — local DB first,
/// then cross-file when remote is available.  Used by R10 inference.
fn resolveMethod(
    db: *const Db,
    ty: ?[]const u8,
    method_name: []const u8,
    remote: ?RemoteCtx,
) ?FnEntry {
    if (db.lookupTyped(ty, method_name)) |e| return e;
    if (ty != null and remote != null) {
        if (lookupCrossFile(remote.?, ty.?, method_name)) |e| return e;
    }
    return null;
}

/// Parsed shape of a `<param>(.<field>)*.<method>(` token chain.
/// `method_tok` is the ident immediately before `(`.  When the
/// param is followed directly by the method (depth 0),
/// `first_field_tok` / `last_field_tok` are both null.  Otherwise
/// they bracket the inclusive range of field idents between param
/// and method.
const FieldChain = struct {
    method_tok: Ast.TokenIndex,
    first_field_tok: ?Ast.TokenIndex,
    last_field_tok: ?Ast.TokenIndex,
};

/// Scan starting at param-ident token `t` (which is followed by
/// `.<ident>`) for a `<ident>(.<ident>)*.<ident>(` shape.  Returns
/// the chain layout, or null if no trailing `(` is found.
fn scanFieldChain(
    tree: *const Ast,
    t: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?FieldChain {
    const tags = tree.tokens.items(.tag);
    // tags[t] = ident (param); tags[t+1] = `.`; tags[t+2] = ident.
    // Walk: `<.>.<ident>` repetitions, stopping when we see ident
    // followed by `(`.
    var pos: Ast.TokenIndex = t + 2;
    var first_field: ?Ast.TokenIndex = null;
    var last_field: ?Ast.TokenIndex = null;
    while (pos <= last) {
        if (tags[pos] != .identifier) return null;
        // Look ahead: is this ident the method (followed by `(`)?
        if (pos + 1 <= last and tags[pos + 1] == .l_paren) {
            return .{
                .method_tok = pos,
                .first_field_tok = first_field,
                .last_field_tok = last_field,
            };
        }
        // Otherwise, treat it as a field; continue if there's
        // another `.<ident>` after.
        if (first_field == null) first_field = pos;
        last_field = pos;
        if (pos + 2 <= last and tags[pos + 1] == .period and tags[pos + 2] == .identifier) {
            pos += 2;
            continue;
        }
        // Chain ends without a `(` — not a method-call shape we
        // care about for R10 inference.
        return null;
    }
    return null;
}

/// Cross-file equivalent of `Db.lookupTyped` — walks remote's imap
/// for a file that declares `type_name`, then looks up
/// `(type_name, method_name)` there.  Used by R10's inference and
/// by callers needing pre-build cross-file resolution.
fn lookupCrossFile(
    remote: RemoteCtx,
    type_name: []const u8,
    method_name: []const u8,
) ?FnEntry {
    var it = remote.imap.entries.iterator();
    while (it.next()) |kv| {
        const file = (remote.cache.loadOrLookup(remote.base_dir, kv.value_ptr.path) catch continue) orelse continue;
        if (!file.db.hasType(type_name)) continue;
        if (file.db.lookupTyped(type_name, method_name)) |e| return e;
    }
    return null;
}

/// Return the param's declared base type name (with `*`/`?`/`const`
/// stripped, and `Self` / `@This()` resolved to `self_type`).  Null
/// when the param has no type annotation, the type is a slice/array,
/// or the param index is out of range.
fn paramTypeName(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    param_idx: u32,
    self_type: ?[]const u8,
) ?[]const u8 {
    var it = fn_proto.iterate(tree);
    var i: u32 = 0;
    while (it.next()) |p| : (i += 1) {
        if (i != param_idx) continue;
        const type_expr = p.type_expr orelse return null;
        return stripTypeWrappers(tree, type_expr, self_type);
    }
    return null;
}

/// Strip leading `?`, `*`, `const` tokens; return the LAST
/// identifier in a dotted chain (`*lib.Foo` → "Foo").  Resolves
/// `Self` and `@This()` to `self_type`.  Returns null for slices,
/// arrays, function ptrs, or anonymous types.
fn stripTypeWrappers(
    tree: *const Ast,
    type_node: Ast.Node.Index,
    self_type: ?[]const u8,
) ?[]const u8 {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .question_mark, .asterisk, .keyword_const => continue,
            .l_bracket => return null,
            .identifier, .builtin => break,
            else => return null,
        }
    }
    if (t > last) return null;
    var last_name: ?[]const u8 = null;
    var expecting_ident = true;
    while (t <= last) : (t += 1) {
        const tag = tags[t];
        if (expecting_ident) {
            if (tag == .identifier) {
                const n = tree.tokenSlice(t);
                last_name = if (std.mem.eql(u8, n, "Self")) self_type else n;
                expecting_ident = false;
            } else if (tag == .builtin) {
                const n = tree.tokenSlice(t);
                if (std.mem.eql(u8, n, "@This")) {
                    last_name = self_type;
                    expecting_ident = false;
                } else return null;
            } else return null;
        } else {
            if (tag == .period) {
                expecting_ident = true;
            } else break;
        }
    }
    return last_name;
}

/// R8b: any free-pattern call anywhere in the body whose target
/// identifier is one of our params → infer `@takes ownership(p)`.
///
/// Walks tokens, not just top-level stmts, so conditional / looped /
/// nested free calls also match.  For UAF detection the conservative
/// direction is "assume the callee MAY free" — false positives at
/// call sites where the runtime condition was false are preferred
/// over silently missing real double-frees and UAFs through
/// conditional-free wrappers.
fn inferTakesOwnership(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body_node: Ast.Node.Index,
    free_patterns: []const []const u8,
) ?TakesAnnotation {
    _ = free_patterns;
    const first = tree.firstToken(body_node);
    const last = tree.lastToken(body_node);
    const tags = tree.tokens.items(.tag);

    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        // Match `.free(` or `.destroy(` at the token level — the
        // free-pattern text match operates on substrings, but the
        // token-level form is `.` `identifier` `(`.
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        const method_name = tree.tokenSlice(t + 1);
        if (!std.mem.eql(u8, method_name, "free") and
            !std.mem.eql(u8, method_name, "destroy")) continue;

        // The freed arg is between `(` and the next `)` at the same
        // paren depth.  For the common `g.free(p)` shape the FIRST
        // identifier after `(` is the freed thing; for the slice
        // variant `g.free(buf[0..n])` we'd want the head of the
        // slicee — but param-name matching naturally filters that.
        // We pick the LAST IDENTIFIER inside the parens that matches
        // a param name; covers both `.free(p)` and `.free(T, p)`.
        var depth: u32 = 1;
        var k: Ast.TokenIndex = t + 3;
        var match: ?u32 = null;
        while (k <= last and depth > 0) : (k += 1) {
            switch (tags[k]) {
                .l_paren => depth += 1,
                .r_paren => depth -= 1,
                .identifier => {
                    if (k > 0 and tags[k - 1] == .period) continue;
                    // `<ident>.something` is a FIELD ACCESS on
                    // <ident> — the param itself isn't the freed
                    // thing, the field is.  Without this guard
                    // `.free(this.hostname)` infers @takes(this),
                    // making every `obj.clearData()` call look like
                    // a free of obj.
                    if (k + 1 < tags.len and tags[k + 1] == .period) continue;
                    const name = tree.tokenSlice(k);
                    if (resolveParamIndex(tree, fn_proto, name)) |idx| {
                        match = idx;
                    }
                },
                else => {},
            }
        }
        if (match) |idx| return .{ .ownership = idx };
    }
    return null;
}

/// Iterator over the top-level statements of a block body.
const TopLevelStmts = struct {
    tree: *const Ast,
    kind: enum { two_a, two_b, two_done, range, done },
    stmt_a: Ast.Node.Index = undefined,
    stmt_b: ?Ast.Node.Index = null,
    range_pos: u32 = 0,
    range_end: u32 = 0,

    fn next(self: *TopLevelStmts) ?Ast.Node.Index {
        switch (self.kind) {
            .two_a => {
                self.kind = if (self.stmt_b != null) .two_b else .done;
                return self.stmt_a;
            },
            .two_b => {
                self.kind = .two_done;
                return self.stmt_b.?;
            },
            .two_done, .done => return null,
            .range => {
                if (self.range_pos >= self.range_end) return null;
                const idx: Ast.Node.Index = @enumFromInt(self.tree.extra_data[self.range_pos]);
                self.range_pos += 1;
                return idx;
            },
        }
    }
};

fn topLevelStmts(tree: *const Ast, body_node: Ast.Node.Index) TopLevelStmts {
    switch (tree.nodeTag(body_node)) {
        .block_two, .block_two_semicolon => {
            const d = tree.nodeData(body_node).opt_node_and_opt_node;
            const a_opt = d[0].unwrap();
            const b_opt = d[1].unwrap();
            if (a_opt == null) return .{ .tree = tree, .kind = .done };
            return .{ .tree = tree, .kind = .two_a, .stmt_a = a_opt.?, .stmt_b = b_opt };
        },
        .block, .block_semicolon => {
            const d = tree.nodeData(body_node).extra_range;
            return .{
                .tree = tree,
                .kind = .range,
                .range_pos = @intFromEnum(d.start),
                .range_end = @intFromEnum(d.end),
            };
        },
        else => return .{ .tree = tree, .kind = .done },
    }
}

/// Returns true iff `call_node`'s source-text span contains any of
/// the given substrings.
fn callTextMatchesAny(tree: *const Ast, call_node: Ast.Node.Index, patterns: []const []const u8) bool {
    const first = tree.firstToken(call_node);
    const last = tree.lastToken(call_node);
    const start = tree.tokens.items(.start)[first];
    const last_start = tree.tokens.items(.start)[last];
    const last_len = tree.tokenSlice(last).len;
    const end: usize = last_start + last_len;
    const text = tree.source[start..end];
    for (patterns) |p| {
        if (std.mem.indexOf(u8, text, p) != null) return true;
    }
    return false;
}

/// Like singleReturnExpr but for the "single statement" form
/// (no return required — used by R8b which matches bare-call bodies).
fn singleStmt(tree: *const Ast, body_node: Ast.Node.Index) ?Ast.Node.Index {
    return switch (tree.nodeTag(body_node)) {
        .block_two, .block_two_semicolon => blk: {
            const d = tree.nodeData(body_node).opt_node_and_opt_node;
            const first = d[0].unwrap() orelse return null;
            if (d[1].unwrap() != null) return null;
            break :blk first;
        },
        .block, .block_semicolon => blk: {
            const d = tree.nodeData(body_node).extra_range;
            const s: u32 = @intFromEnum(d.start);
            const e: u32 = @intFromEnum(d.end);
            if (e - s != 1) return null;
            const idx: Ast.Node.Index = @enumFromInt(tree.extra_data[s]);
            break :blk idx;
        },
        else => null,
    };
}

/// R7 helper.  Returns a `borrowed_from(param_idx)` annotation if
/// the fn body is a single-return-stmt that delegates to an
/// annotated callee.  Two shapes supported:
///
///   `return <param>.<chain>.<method>(args);` (method-style)
///     — fires when method is `borrowed_from(self)`, propagates the
///     receiver param's index.
///
///   `return <Path>.<method>(arg0, arg1, ...);` (namespace-style)
///     — fires when method is `borrowed_from(N)` and arg N resolves
///     to one of our params; propagates that param's index.
fn inferDelegatorBorrow(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body_node: Ast.Node.Index,
    db: *const Db,
    remote: ?RemoteCtx,
) ?ReturnsAnnotation {
    // Single-stmt or var+return shape: classify the lone return.
    if (singleReturnExpr(tree, body_node)) |return_expr| {
        if (tryInferFromReturnExpr(tree, fn_proto, return_expr, db, remote)) |a| return a;
    }
    // Multi-return body (e.g. `if (cond) return c.text(); return "";`):
    // infer if EVERY return stmt either delegates to the same param
    // or returns a non-borrow value (literal / null / &.{} / etc.).
    return inferDelegatorBorrowMultiReturn(tree, fn_proto, body_node, db, remote);
}

fn tryInferFromReturnExpr(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    return_expr: Ast.Node.Index,
    db: *const Db,
    remote: ?RemoteCtx,
) ?ReturnsAnnotation {
    var buf: [1]Ast.Node.Index = undefined;
    const call_full = tree.fullCall(&buf, return_expr) orelse return null;
    if (inferMethodStyle(tree, fn_proto, return_expr, db, remote)) |a| return a;
    return inferNamespaceStyle(tree, fn_proto, call_full, db, remote);
}

/// Walk every `.@"return"` node whose token range lies within
/// `body_node`.  For each return stmt:
///   - If the value matches R7 (method-style or namespace-style
///     delegating to `borrowed_from(self/arg)` on one of our
///     params), record the param index.
///   - If the value is a non-borrow shape (literal / null /
///     undefined / empty-tuple slice), skip — non-borrow returns
///     don't constrain the inference.
///   - Anything else (unrecognized call) → abort to avoid wrong
///     inference.
/// Returns `borrowed_from(N)` if at least one return matched and
/// all matched returns agree on the same N.
fn inferDelegatorBorrowMultiReturn(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body_node: Ast.Node.Index,
    db: *const Db,
    remote: ?RemoteCtx,
) ?ReturnsAnnotation {
    const body_first = tree.firstToken(body_node);
    const body_last = tree.lastToken(body_node);

    var found: ?u32 = null;
    var any_match = false;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .@"return") continue;
        const ft = tree.firstToken(node);
        const lt = tree.lastToken(node);
        if (ft < body_first or lt > body_last) continue;

        const value_opt = tree.nodeData(node).opt_node.unwrap();
        const value = value_opt orelse continue; // `return;` — void
        if (isNonBorrowReturnValue(tree, value)) continue;

        const inferred = tryInferFromReturnExpr(tree, fn_proto, value, db, remote) orelse {
            // Recognized neither a borrow delegation nor a known
            // non-borrow — can't safely infer.
            return null;
        };
        switch (inferred) {
            .borrowed_from => |idx| {
                if (found) |existing| if (existing != idx) return null;
                found = idx;
                any_match = true;
            },
            else => return null,
        }
    }
    if (!any_match) return null;
    return .{ .borrowed_from = found.? };
}

/// True iff `expr` is a return-value shape that doesn't borrow
/// from any local/param — string literal, integer, null, undefined,
/// `&.{}` (empty tuple-to-slice coercion).  These are safe to
/// skip when inferring borrowed_from across multiple returns.
fn isNonBorrowReturnValue(tree: *const Ast, expr: Ast.Node.Index) bool {
    switch (tree.nodeTag(expr)) {
        .string_literal, .multiline_string_literal,
        .number_literal, .char_literal,
        => return true,
        .identifier => {
            const name = tree.tokenSlice(tree.nodeMainToken(expr));
            return std.mem.eql(u8, name, "null") or
                std.mem.eql(u8, name, "undefined") or
                std.mem.eql(u8, name, "true") or
                std.mem.eql(u8, name, "false");
        },
        .address_of => {
            // `&.{}` — anonymous empty literal address-of.  Inner
            // is a struct_init_dot_two with no fields.
            const inner = tree.nodeData(expr).node;
            return switch (tree.nodeTag(inner)) {
                .struct_init_dot_two, .struct_init_dot_two_comma => true,
                else => false,
            };
        },
        else => return false,
    }
}

/// Look up `method_name` in the same-file DB, returning its
/// `borrowed_from(N)` target index.  Returns null when missing or
/// when the annotation isn't `borrowed_from`.
fn lookupBorrowedFromSameFile(
    db: *const Db,
    method_name: []const u8,
) ?u32 {
    const entry = db.lookup(method_name) orelse return null;
    const a = entry.annotation orelse return null;
    return switch (a) {
        .borrowed_from => |idx| idx,
        else => null,
    };
}

/// Look up `method_name` in one specific imported file (by imap
/// entry name).  Used for namespace-style R7 (`Foo.method(...)`)
/// where the receiver IS the import namespace — avoids the cost
/// of scanning every imap entry on every method lookup.
fn lookupBorrowedFromImport(
    remote: RemoteCtx,
    namespace: []const u8,
    method_name: []const u8,
) ?u32 {
    const imap_entry = remote.imap.lookup(namespace) orelse return null;
    const file = (remote.cache.loadOrLookup(remote.base_dir, imap_entry.path) catch return null) orelse return null;
    const entry = file.db.lookup(method_name) orelse return null;
    const a = entry.annotation orelse return null;
    return switch (a) {
        .borrowed_from => |idx| idx,
        else => null,
    };
}

/// AST-level type-name resolution.  Read the named param's type
/// annotation tokens, strip leading `*`/`?`/`const`/`[]`/whitespace,
/// and if the leaf form is `<ns>.<Type>` where `<ns>` is in the
/// caller's imap, look up `method_name` in `<ns>.zig`'s DB.
///
/// Why this works without semantic types: every step uses AST text
/// and imap entries we already build.  Limited shape (single-hop
/// `ns.Type` with at most a wrapping pointer chain), but covers
/// the common `pub fn wrap(c: *const ns.Type) RetT { return c.method(); }`
/// shape that real wrappers use.
///
/// For genuinely anonymous param types (`anytype`, inline
/// `struct { ... }`) — where there's no namespace to target — we
/// fall back to scanning every imap entry's DB for the method.
/// Cost is bounded because anonymous param types are rare and the
/// scan only triggers when the targeted lookup misses.  Returns
/// null on ambiguity (two imports each define the method
/// differently) so we err toward no inference rather than wrong.
fn lookupBorrowedFromParamType(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    param_idx: u32,
    method_name: []const u8,
    remote: ?RemoteCtx,
) ?u32 {
    const r = remote orelse return null;

    var idx: u32 = 0;
    var it = fn_proto.iterate(tree);
    const param = while (it.next()) |p| : (idx += 1) {
        if (idx == param_idx) break p;
    } else return null;
    // `anytype` params have type_expr == null (anytype_ellipsis3
    // is set instead).  No named type to resolve — fall straight
    // to the imap scan.
    const type_node = param.type_expr orelse {
        if (param.anytype_ellipsis3 != null) return scanImapForBorrowedFrom(r, method_name);
        return null;
    };

    // Walk the type's tokens.  Skip pointer/const/optional/slice
    // qualifiers; look for the first `<id>.<id>` pair as the leaf
    // namespace.Type form.
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t < last) : (t += 1) {
        if (tags[t] != .identifier) continue;
        // `<id> . <id>` — `id` must NOT be preceded by `.` itself.
        if (t > first and tags[t - 1] == .period) continue;
        if (t + 2 > last) break;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        const ns = tree.tokenSlice(t);
        // We don't actually need the type name — only the namespace
        // tells us which remote file to consult.  The method lookup
        // is by name in that file's full annotation DB.
        return lookupBorrowedFromImport(r, ns, method_name);
    }
    // Bare-identifier leaf type (`const Foo = struct {...};` in the
    // SAME file).  Same-file path would have already caught the
    // method via lookupBorrowedFromSameFile; nothing more to do.
    //
    // For `anytype` or inline `struct { ... }` param types we have
    // no namespace to target.  Fall back to scanning every imap
    // entry for the method — bounded cost (only fires when the
    // param type is genuinely anonymous, which is rare; one scan
    // per such call site).  Returns the target_idx if EXACTLY ONE
    // import has the method annotated borrowed_from(idx); ambiguous
    // matches bail.
    if (isAnonymousParamType(tree, type_node)) {
        return scanImapForBorrowedFrom(r, method_name);
    }
    return null;
}

/// True iff the param's type-expr is `anytype` or an inline
/// `struct { ... }` — both lack a name we can resolve through imap.
fn isAnonymousParamType(tree: *const Ast, type_node: Ast.Node.Index) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    const tags = tree.tokens.items(.tag);

    // Skip leading qualifiers (`*`, `const`, `?`, `[`, `]`, identifiers
    // that are qualifiers like `const`).  Then check the first
    // significant token.
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .asterisk, .question_mark, .l_bracket, .r_bracket => continue,
            .keyword_const => continue,
            .identifier => {
                const s = tree.tokenSlice(t);
                if (std.mem.eql(u8, s, "anytype")) return true;
                return false; // any other identifier is a named type
            },
            .keyword_struct, .keyword_union, .keyword_enum, .keyword_opaque => return true,
            else => return false,
        }
    }
    return false;
}

/// Scan every imap entry's remote DB for `method_name`.  Returns the
/// SINGLE target_idx if exactly one import has it as `borrowed_from`;
/// null on miss or on ambiguity (two imports each define the method
/// with different target indices).
fn scanImapForBorrowedFrom(remote: RemoteCtx, method_name: []const u8) ?u32 {
    var found: ?u32 = null;
    var it = remote.imap.entries.iterator();
    while (it.next()) |kv| {
        const path = kv.value_ptr.path;
        const file = (remote.cache.loadOrLookup(remote.base_dir, path) catch continue) orelse continue;
        const entry = file.db.lookup(method_name) orelse continue;
        const a = entry.annotation orelse continue;
        switch (a) {
            .borrowed_from => |idx| {
                if (found) |existing| if (existing != idx) return null;
                found = idx;
            },
            else => {},
        }
    }
    return found;
}

fn inferMethodStyle(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    return_expr: Ast.Node.Index,
    db: *const Db,
    remote: ?RemoteCtx,
) ?ReturnsAnnotation {
    const first = tree.firstToken(return_expr);
    const last = tree.lastToken(return_expr);
    const tags = tree.tokens.items(.tag);

    if (tags[first] != .identifier) return null;
    if (first + 1 > last or tags[first + 1] != .period) return null;

    const head_name = tree.tokenSlice(first);
    const param_idx = resolveParamIndex(tree, fn_proto, head_name) orelse return null;

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
    // Same-file first.  Then AST-level type resolution: read the
    // param's declared type, strip pointer/const, and if the leaf
    // is `<namespace>.<TypeName>` where namespace is in our imap,
    // try to find the method on TypeName in that file.
    var target_idx = lookupBorrowedFromSameFile(db, method_name);
    if (target_idx == null) {
        target_idx = lookupBorrowedFromParamType(
            tree,
            fn_proto,
            param_idx,
            method_name,
            remote,
        );
    }
    if ((target_idx orelse return null) == 0) return .{ .borrowed_from = param_idx };
    return null;
}

fn inferNamespaceStyle(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    call_full: Ast.full.Call,
    db: *const Db,
    remote: ?RemoteCtx,
) ?ReturnsAnnotation {
    const callee = call_full.ast.fn_expr;
    const method_tok = switch (tree.nodeTag(callee)) {
        .identifier => tree.nodeMainToken(callee),
        .field_access => tree.nodeData(callee).node_and_token[1],
        else => return null,
    };
    const method_name = tree.tokenSlice(method_tok);
    // Same-file first.  For namespace-style `Foo.method(...)` where
    // Foo is in our imap, also try Foo's own DB — bounded to one
    // remote lookup per call site (no broad scanning).
    var target_idx = lookupBorrowedFromSameFile(db, method_name);
    if (target_idx == null) {
        if (tree.nodeTag(callee) == .field_access and remote != null) {
            const recv = tree.nodeData(callee).node_and_token[0];
            if (tree.nodeTag(recv) == .identifier) {
                const ns = tree.tokenSlice(tree.nodeMainToken(recv));
                target_idx = lookupBorrowedFromImport(remote.?, ns, method_name);
            }
        }
    }
    const idx_resolved = target_idx orelse return null;
    const args = call_full.ast.params;
    if (idx_resolved >= args.len) return null;
    const arg = args[idx_resolved];
    if (tree.nodeTag(arg) != .identifier) return null;
    const arg_name = tree.tokenSlice(tree.nodeMainToken(arg));
    const our_param = resolveParamIndex(tree, fn_proto, arg_name) orelse return null;
    return .{ .borrowed_from = our_param };
}

/// Returns the inner expression of the body's "return value" if the
/// body has a R7-recognizable shape:
///
///   { return EXPR; }                       → EXPR
///   { var/const X = EXPR; return X; }      → EXPR  (X must match)
///
/// Anything else returns null.
fn singleReturnExpr(tree: *const Ast, body_node: Ast.Node.Index) ?Ast.Node.Index {
    const tag = tree.nodeTag(body_node);
    var stmt0: Ast.Node.Index = undefined;
    var stmt1_opt: ?Ast.Node.Index = null;
    switch (tag) {
        .block_two, .block_two_semicolon => {
            const d = tree.nodeData(body_node).opt_node_and_opt_node;
            stmt0 = d[0].unwrap() orelse return null;
            stmt1_opt = d[1].unwrap();
        },
        .block, .block_semicolon => {
            const d = tree.nodeData(body_node).extra_range;
            const start: u32 = @intFromEnum(d.start);
            const end: u32 = @intFromEnum(d.end);
            if (end - start == 1) {
                stmt0 = @enumFromInt(tree.extra_data[start]);
            } else if (end - start == 2) {
                stmt0 = @enumFromInt(tree.extra_data[start]);
                stmt1_opt = @as(Ast.Node.Index, @enumFromInt(tree.extra_data[start + 1]));
            } else return null;
        },
        else => return null,
    }

    // Single-stmt body: must be `return EXPR;`.
    if (stmt1_opt == null) {
        if (tree.nodeTag(stmt0) != .@"return") return null;
        return tree.nodeData(stmt0).opt_node.unwrap();
    }

    // Two-stmt body: must be `var/const X = EXPR;` then `return X;`.
    const stmt1 = stmt1_opt.?;
    if (tree.nodeTag(stmt1) != .@"return") return null;
    const ret_val = tree.nodeData(stmt1).opt_node.unwrap() orelse return null;
    if (tree.nodeTag(ret_val) != .identifier) return null;
    const ret_name = tree.tokenSlice(tree.nodeMainToken(ret_val));

    const var_decl = tree.fullVarDecl(stmt0) orelse return null;
    const name_tok = var_decl.ast.mut_token + 1;
    if (tree.tokens.items(.tag)[name_tok] != .identifier) return null;
    const decl_name = tree.tokenSlice(name_tok);
    if (!std.mem.eql(u8, decl_name, ret_name)) return null;

    return var_decl.ast.init_node.unwrap();
}

/// Walk the AST top-down from the root container.  For every
/// `const TypeName = struct { ... };` (or union/enum), record each
/// fn_decl member as belonging to `TypeName`, and every field's
/// declared type into `field_types`.  Recursively descends into
/// nested types.  Top-level fns get no entry (containing type null).
fn discoverContainingTypes(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    fn_out: *std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8),
    field_out: *std.HashMapUnmanaged(Db.FieldKey, []const u8, Db.FieldKey.Context, std.hash_map.default_max_load_percentage),
) !void {
    const root = tree.containerDeclRoot();
    try walkContainerMembers(gpa, tree, root.ast.members, null, fn_out, field_out);
}

fn walkContainerMembers(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    members: []const Ast.Node.Index,
    containing_type: ?[]const u8,
    fn_out: *std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8),
    field_out: *std.HashMapUnmanaged(Db.FieldKey, []const u8, Db.FieldKey.Context, std.hash_map.default_max_load_percentage),
) (std.mem.Allocator.Error)!void {
    for (members) |member| {
        switch (tree.nodeTag(member)) {
            .fn_decl => {
                if (containing_type) |ct| try fn_out.put(gpa, member, ct);
            },
            .simple_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .global_var_decl,
            => {
                const vd = tree.fullVarDecl(member) orelse continue;
                const init_node = vd.ast.init_node.unwrap() orelse continue;
                // The var decl's name (token after `const`/`var`) is
                // the type's identifier when init is a container_decl.
                const name_tok = vd.ast.mut_token + 1;
                if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
                const ty_name = tree.tokenSlice(name_tok);
                try descendContainer(gpa, tree, init_node, ty_name, fn_out, field_out);
            },
            // Struct/union field declarations — `name: T [= default],`.
            .container_field_init,
            .container_field_align,
            .container_field,
            => {
                const ct = containing_type orelse continue;
                const cf = tree.fullContainerField(member) orelse continue;
                const name_tok = cf.ast.main_token;
                if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
                const field_name = tree.tokenSlice(name_tok);
                const type_expr = cf.ast.type_expr.unwrap() orelse continue;
                const field_ty = stripTypeWrappers(tree, type_expr, ct) orelse continue;
                try field_out.putContext(gpa, .{
                    .containing_type = ct,
                    .name = field_name,
                }, field_ty, .{});
            },
            else => {},
        }
    }
}

/// Dispatch on container_decl variant and recurse with the right
/// member slice.  Variants that store members inline in a stack
/// buffer (the `*Two` family) keep the buffer in scope of THIS
/// function so the slice stays valid for the recursive call.
fn descendContainer(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    node: Ast.Node.Index,
    ty_name: []const u8,
    fn_out: *std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8),
    field_out: *std.HashMapUnmanaged(Db.FieldKey, []const u8, Db.FieldKey.Context, std.hash_map.default_max_load_percentage),
) (std.mem.Allocator.Error)!void {
    switch (tree.nodeTag(node)) {
        .container_decl, .container_decl_trailing => {
            try walkContainerMembers(gpa, tree, tree.containerDecl(node).ast.members, ty_name, fn_out, field_out);
        },
        .container_decl_two, .container_decl_two_trailing => {
            var buf: [2]Ast.Node.Index = undefined;
            try walkContainerMembers(gpa, tree, tree.containerDeclTwo(&buf, node).ast.members, ty_name, fn_out, field_out);
        },
        .container_decl_arg, .container_decl_arg_trailing => {
            try walkContainerMembers(gpa, tree, tree.containerDeclArg(node).ast.members, ty_name, fn_out, field_out);
        },
        .tagged_union, .tagged_union_trailing => {
            try walkContainerMembers(gpa, tree, tree.taggedUnion(node).ast.members, ty_name, fn_out, field_out);
        },
        .tagged_union_two, .tagged_union_two_trailing => {
            var buf: [2]Ast.Node.Index = undefined;
            try walkContainerMembers(gpa, tree, tree.taggedUnionTwo(&buf, node).ast.members, ty_name, fn_out, field_out);
        },
        .tagged_union_enum_tag, .tagged_union_enum_tag_trailing => {
            try walkContainerMembers(gpa, tree, tree.taggedUnionEnumTag(node).ast.members, ty_name, fn_out, field_out);
        },
        else => {},
    }
}

fn fullFnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) ?Ast.full.FnProto {
    return switch (tree.nodeTag(node)) {
        .fn_decl => switch (tree.nodeTag(tree.nodeData(node).node_and_node[0])) {
            .fn_proto => tree.fnProto(tree.nodeData(node).node_and_node[0]),
            .fn_proto_multi => tree.fnProtoMulti(tree.nodeData(node).node_and_node[0]),
            .fn_proto_one => tree.fnProtoOne(buf, tree.nodeData(node).node_and_node[0]),
            .fn_proto_simple => tree.fnProtoSimple(buf, tree.nodeData(node).node_and_node[0]),
            else => null,
        },
        .fn_proto => tree.fnProto(node),
        .fn_proto_multi => tree.fnProtoMulti(node),
        .fn_proto_one => tree.fnProtoOne(buf, node),
        .fn_proto_simple => tree.fnProtoSimple(buf, node),
        else => null,
    };
}

fn parseReturnsAnnotation(tree: *const Ast, fn_proto: Ast.full.FnProto) ?ReturnsAnnotation {
    const fn_first_tok: Ast.TokenIndex = fn_proto.visib_token orelse
        fn_proto.extern_export_inline_token orelse
        fn_proto.ast.fn_token;
    if (fn_first_tok == 0) return null;

    var t: i64 = @as(i64, @intCast(fn_first_tok)) - 1;
    while (t >= 0) : (t -= 1) {
        const tok_idx: Ast.TokenIndex = @intCast(t);
        if (tree.tokens.items(.tag)[tok_idx] != .doc_comment) break;
        const raw = tree.tokenSlice(tok_idx);
        const body = stripDocPrefix(raw);
        const trimmed = std.mem.trim(u8, body, " \t");

        // Order matters: more-specific prefixes must precede their
        // less-specific siblings (e.g. `owns_locals` before `owned`).
        if (std.mem.startsWith(u8, trimmed, "@returns owns_locals")) return .owns_locals;
        if (std.mem.startsWith(u8, trimmed, "@returns owned")) return .owned;
        if (std.mem.startsWith(u8, trimmed, "@returns heap")) return .heap;

        const prefix = "@returns borrowed_from(";
        if (std.mem.startsWith(u8, trimmed, prefix)) {
            const after = trimmed[prefix.len..];
            const close = std.mem.indexOfScalar(u8, after, ')') orelse continue;
            const param_name = std.mem.trim(u8, after[0..close], " \t");
            const idx = resolveParamIndex(tree, fn_proto, param_name) orelse continue;
            return .{ .borrowed_from = idx };
        }
    }
    return null;
}

fn parseTakesAnnotation(tree: *const Ast, fn_proto: Ast.full.FnProto) ?TakesAnnotation {
    const fn_first_tok: Ast.TokenIndex = fn_proto.visib_token orelse
        fn_proto.extern_export_inline_token orelse
        fn_proto.ast.fn_token;
    if (fn_first_tok == 0) return null;

    var t: i64 = @as(i64, @intCast(fn_first_tok)) - 1;
    while (t >= 0) : (t -= 1) {
        const tok_idx: Ast.TokenIndex = @intCast(t);
        if (tree.tokens.items(.tag)[tok_idx] != .doc_comment) break;
        const raw = tree.tokenSlice(tok_idx);
        const body = stripDocPrefix(raw);
        const trimmed = std.mem.trim(u8, body, " \t");

        const prefix = "@takes ownership(";
        if (std.mem.startsWith(u8, trimmed, prefix)) {
            const after = trimmed[prefix.len..];
            const close = std.mem.indexOfScalar(u8, after, ')') orelse continue;
            const param_name = std.mem.trim(u8, after[0..close], " \t");
            const idx = resolveParamIndex(tree, fn_proto, param_name) orelse continue;
            return .{ .ownership = idx };
        }
    }
    return null;
}

fn resolveParamIndex(tree: *const Ast, fn_proto: Ast.full.FnProto, name: []const u8) ?u32 {
    var idx: u32 = 0;
    var it = fn_proto.iterate(tree);
    while (it.next()) |param| : (idx += 1) {
        const name_tok = param.name_token orelse continue;
        if (std.mem.eql(u8, tree.tokenSlice(name_tok), name)) return idx;
    }
    return null;
}

fn stripDocPrefix(raw: []const u8) []const u8 {
    var s = raw;
    if (std.mem.startsWith(u8, s, "///")) s = s[3..];
    if (s.len > 0 and s[0] == ' ') s = s[1..];
    return s;
}

// ── R6 helpers (returns-owned inference via body allocation scan) ──

fn returnTypeIsNoreturn(tree: *const Ast, type_node: Ast.Node.Index) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    if (first != last) return false; // composite type, not bare keyword
    if (tree.tokens.items(.tag)[first] != .identifier) return false;
    return std.mem.eql(u8, tree.tokenSlice(first), "noreturn");
}

fn typeIsSliceShaped(tree: *const Ast, type_node: Ast.Node.Index) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t < last) : (t += 1) {
        if (tags[t] == .l_bracket) return true;
    }
    return false;
}

fn bodyContainsAllocation(tree: *const Ast, body_node: Ast.Node.Index) bool {
    const first = tree.firstToken(body_node);
    const last = tree.lastToken(body_node);
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        if (isAllocatorMethodName(tree.tokenSlice(t + 1))) return true;
    }
    return false;
}

fn isAllocatorMethodName(name: []const u8) bool {
    const allocators = [_][]const u8{
        "alloc",        "allocSentinel",     "allocAdvanced",
        "dupe",         "dupeZ",
        "create",
        "allocPrint",   "allocPrintZ",
        "toOwnedSlice", "toOwnedSliceSentinel",
    };
    for (allocators) |a| {
        if (std.mem.eql(u8, name, a)) return true;
    }
    return false;
}

// ── Tests ──────────────────────────────────────────────────

const TestBundle = struct {
    src_z: [:0]u8,
    tree: Ast,
    db: Db,

    fn deinit(self: *TestBundle, gpa: std.mem.Allocator) void {
        self.db.deinit(gpa);
        self.tree.deinit(gpa);
        gpa.free(self.src_z);
    }
};

fn buildFromSrc(gpa: std.mem.Allocator, src: []const u8) !TestBundle {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    errdefer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    errdefer tree.deinit(gpa);
    const db = try build(gpa, &tree);
    return .{ .src_z = src_z, .tree = tree, .db = db };
}

test "extract @returns owned" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\/// @returns owned
        \\pub fn alloc(gpa_: u32) ![]u8 { _ = gpa_; return ""; }
        \\
    );
    defer r.deinit(gpa);
    try std.testing.expect(r.db.lookup("alloc").?.annotation.? == .owned);
}

test "extract @returns borrowed_from" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ctx = struct {};
        \\/// @returns borrowed_from(ctx)
        \\pub fn slice(ctx: *const Ctx) []const u8 { _ = ctx; return ""; }
        \\
    );
    defer r.deinit(gpa);
    const entry = r.db.lookup("slice").?;
    try std.testing.expect(entry.annotation.? == .borrowed_from);
    try std.testing.expectEqual(@as(u32, 0), entry.annotation.?.borrowed_from);
}

test "R6: slice return + body allocates → @returns owned inferred" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const std = @import("std");
        \\pub fn dupString(g: std.mem.Allocator, s: []const u8) ![]u8 {
        \\    return g.dupe(u8, s);
        \\}
        \\
    );
    defer r.deinit(gpa);
    // R8 fires on top of R6: dupString's body is `g.dupe(...)` which
    // matches a heap-alloc pattern, so the more-specific .heap
    // annotation wins over R6's .owned.
    try std.testing.expect(r.db.lookup("dupString").?.annotation.? == .heap);
}

test "R6: no allocation in body → no inference" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\pub fn greeting() []const u8 { return "hi"; }
        \\
    );
    defer r.deinit(gpa);
    try std.testing.expect(r.db.lookup("greeting") == null);
}

test "non-annotated fn → not in db" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\pub fn add(a: u32, b: u32) u32 { return a + b; }
        \\
    );
    defer r.deinit(gpa);
    try std.testing.expect(r.db.lookup("add") == null);
}
