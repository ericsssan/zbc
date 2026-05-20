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
};

pub const Db = struct {
    fns: std.StringHashMapUnmanaged(FnEntry),

    pub fn deinit(self: *Db, gpa: std.mem.Allocator) void {
        self.fns.deinit(gpa);
    }

    pub fn lookup(self: *const Db, name: []const u8) ?FnEntry {
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

/// R8b: any top-level body stmt is a call matching a free pattern
/// whose last explicit arg resolves to one of our params.  Doesn't
/// recurse into branches — the body's TOP level must contain the
/// free call (which is the canonical free-wrapper shape; conditional
/// frees are caller responsibility).
fn inferTakesOwnership(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body_node: Ast.Node.Index,
    free_patterns: []const []const u8,
) ?TakesAnnotation {
    var it = topLevelStmts(tree, body_node);
    while (it.next()) |stmt| {
        const is_call = switch (tree.nodeTag(stmt)) {
            .call, .call_one, .call_comma, .call_one_comma => true,
            else => false,
        };
        if (!is_call) continue;
        if (!callTextMatchesAny(tree, stmt, free_patterns)) continue;

        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, stmt) orelse continue;
        if (call_full.ast.params.len == 0) continue;
        const last_arg = call_full.ast.params[call_full.ast.params.len - 1];
        if (tree.nodeTag(last_arg) != .identifier) continue;
        const n = tree.tokenSlice(tree.nodeMainToken(last_arg));
        const idx = resolveParamIndex(tree, fn_proto, n) orelse continue;
        return .{ .ownership = idx };
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
    const return_expr = singleReturnExpr(tree, body_node) orelse return null;
    var buf: [1]Ast.Node.Index = undefined;
    const call_full = tree.fullCall(&buf, return_expr) orelse return null;

    if (inferMethodStyle(tree, fn_proto, return_expr, db, remote)) |a| return a;
    return inferNamespaceStyle(tree, fn_proto, call_full, db, remote);
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
    const type_node = param.type_expr orelse return null;

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
    return null;
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
