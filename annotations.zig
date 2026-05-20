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

pub const FnEntry = struct {
    /// Function name (slice into source — keep source alive).
    name: []const u8,
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
    /// **Inferred receiver-freeing effects (R9 / R10).**  Set when
    /// the function body contains a free call whose argument is the
    /// first param's identifier (R9: frees the receiver itself) or
    /// `<first_param>.<field>` (R10: frees a field).  Conservative —
    /// the free may be conditional on a runtime branch, but for
    /// UAF detection "may free" is the safe direction.  At call
    /// sites, applying these effects lets us catch
    /// `obj.method(); use(obj);`  /  `obj.freeFoo(); use(obj.foo);`
    /// — the canonical inter-procedural UAF class.
    may_free_self: bool = false,
    /// Names of `this.<field>` references that appear as the first
    /// arg of a free call inside the body.  Owned by the Db's
    /// arena via the source slice.  Empty when none detected.
    may_free_fields: []const []const u8 = &.{},
};

pub const Db = struct {
    fns: std.StringHashMapUnmanaged(FnEntry),
    /// Set of fn names that appear MORE THAN ONCE as fn_decl in the
    /// source file (e.g. `finalize` defined on both `HTMLRewriter`
    /// and `HTMLRewriterLoader`).  zbc's annotation DB is keyed by
    /// bare name — no struct scoping — so the second definition
    /// silently overwrites the first.  Marking names as ambiguous
    /// disables `@takes` / `@returns` propagation through `lookup`
    /// for them, preventing the kind of FP where R8b infers
    /// `@takes(0)` on the destroy-flavoured `finalize` and every
    /// unrelated `<recv>.finalize()` call site then looks like a
    /// destruction.
    ambiguous: std.StringHashMapUnmanaged(void) = .empty,

    pub fn deinit(self: *Db, gpa: std.mem.Allocator) void {
        var it = self.fns.valueIterator();
        while (it.next()) |e| {
            if (e.may_free_fields.len > 0) gpa.free(e.may_free_fields);
        }
        self.fns.deinit(gpa);
        self.ambiguous.deinit(gpa);
    }

    /// True iff the name has multiple fn_decl definitions in the
    /// file (e.g. method overload across types).  Callers that
    /// depend on cross-fn semantics — R10 inference, call-site
    /// `@takes` resolution — should skip ambiguous names rather
    /// than guess which overload is being called.
    pub fn isAmbiguous(self: *const Db, name: []const u8) bool {
        return self.ambiguous.contains(name);
    }

    /// Look up a fn's annotations.  Returns null for ambiguous names
    /// (multiple definitions) so callers don't latch onto the
    /// arbitrary "last writer wins" entry and propagate annotations
    /// that belong to a sibling overload.
    pub fn lookup(self: *const Db, name: []const u8) ?FnEntry {
        if (self.ambiguous.contains(name)) return null;
        return self.fns.get(name);
    }
};

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

    // Pre-pass — count fn_decl name occurrences to detect overloads.
    // Names with >1 definition go into db.ambiguous; subsequent
    // inference passes and call-site lookups skip them.
    {
        var name_count: std.StringHashMapUnmanaged(u32) = .empty;
        defer name_count.deinit(gpa);
        var ni: u32 = 1;
        while (ni < tree.nodes.len) : (ni += 1) {
            const n: Ast.Node.Index = @enumFromInt(ni);
            if (tree.nodeTag(n) != .fn_decl) continue;
            var nbuf: [1]Ast.Node.Index = undefined;
            const np = fullFnProto(tree, &nbuf, n) orelse continue;
            const nt = np.name_token orelse continue;
            const nn = tree.tokenSlice(nt);
            const gop = try name_count.getOrPut(gpa, nn);
            if (gop.found_existing) gop.value_ptr.* += 1 else gop.value_ptr.* = 1;
        }
        var it = name_count.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* > 1) try db.ambiguous.put(gpa, e.key_ptr.*, {});
        }
    }

    // Pass 1 — explicit annotations + R6 (slice + body allocs → owned).
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
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

        // Skip if no signal of any flavor.
        if (annotation == null and takes_anno == null and !is_noreturn) continue;
        const name = tree.tokenSlice(name_tok);
        try db.fns.put(gpa, name, .{
            .name = name,
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
            // R7 only fills missing `.annotation`.  An entry with
            // only `.takes` (no return annotation) is still a
            // candidate for R7 to enrich.
            const existing = db.fns.get(name);
            if (existing != null and existing.?.annotation != null) continue;

            const body = tree.nodeData(node).node_and_node[1];
            const inferred = inferDelegatorBorrow(tree, fn_proto, body, &db, remote) orelse continue;
            try db.fns.put(gpa, name, .{
                .name = name,
                .annotation = inferred,
                .takes = if (existing) |e| e.takes else null,
                .is_noreturn = if (existing) |e| e.is_noreturn else false,
            });
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
        const body = tree.nodeData(node).node_and_node[1];

        var entry = db.fns.get(name) orelse FnEntry{
            .name = name,
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
        if (changed) try db.fns.put(gpa, name, entry);
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
            const existing = db.fns.get(name);
            // Skip if already has a `takes` — don't overwrite explicit
            // annotations or R8b's direct-free inference.
            if (existing != null and existing.?.takes != null) continue;

            const body = tree.nodeData(node).node_and_node[1];
            const inferred = inferTakesViaReceiverCall(tree, fn_proto, body, &db) orelse continue;
            try db.fns.put(gpa, name, .{
                .name = name,
                .annotation = if (existing) |e| e.annotation else null,
                .takes = inferred,
                .is_noreturn = if (existing) |e| e.is_noreturn else false,
            });
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
fn inferTakesViaReceiverCall(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body_node: Ast.Node.Index,
    db: *const Db,
) ?TakesAnnotation {
    const first = tree.firstToken(body_node);
    const last = tree.lastToken(body_node);
    const tags = tree.tokens.items(.tag);

    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        // Pattern: <identifier> `.` <identifier> `(`
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        // Reject longer-chain heads — `a.b.c(...)` where we'd match
        // at `b.c(` but `b` isn't a function param.  Skip if the
        // token BEFORE our receiver is `.` (we're mid-chain).
        if (t > 0 and tags[t - 1] == .period) continue;

        const recv_name = tree.tokenSlice(t);
        const method_name = tree.tokenSlice(t + 2);
        const param_idx = resolveParamIndex(tree, fn_proto, recv_name) orelse continue;
        // `lookup` (not `fns.get`) filters ambiguous names — names with
        // multiple definitions across types — so R10 doesn't propagate
        // a `@takes(0)` that was inferred on a sibling overload.
        const callee = db.lookup(method_name) orelse continue;
        const callee_takes = callee.takes orelse continue;
        switch (callee_takes) {
            .ownership => |i| {
                // Callee frees its arg at index `i`.  For receiver
                // -calls the receiver is arg 0, so only callees that
                // free arg 0 propagate self-freeing-ness.
                if (i == 0) return .{ .ownership = param_idx };
            },
        }
    }
    return null;
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
