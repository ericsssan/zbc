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
};

pub const FnEntry = struct {
    /// Function name (slice into source — keep source alive).
    name: []const u8,
    annotation: ReturnsAnnotation,
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
/// annotation, then run inference (R6, R7) to fill obvious holes.
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !Db {
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

        if (annotation == null) continue;
        const name = tree.tokenSlice(name_tok);
        try db.fns.put(gpa, name, .{ .name = name, .annotation = annotation.? });
    }

    // Pass 2 — R7: trivial delegators.
    //   pub fn wrap(p: T, ...) RetT { return p.<chain>.<method>(args); }
    // where `method` is annotated `@returns borrowed_from(self)`
    //   →  infer `@returns borrowed_from(p)` for `wrap`.
    //
    // Runs after pass 1 so cross-fn lookups see fully-populated db.
    node_idx = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        const name_tok = fn_proto.name_token orelse continue;
        const name = tree.tokenSlice(name_tok);
        if (db.fns.contains(name)) continue;

        const body = tree.nodeData(node).node_and_node[1];
        const inferred = inferDelegatorBorrow(tree, fn_proto, body, &db) orelse continue;
        try db.fns.put(gpa, name, .{ .name = name, .annotation = inferred });
    }

    return db;
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
) ?ReturnsAnnotation {
    const return_expr = singleReturnExpr(tree, body_node) orelse return null;
    var buf: [1]Ast.Node.Index = undefined;
    const call_full = tree.fullCall(&buf, return_expr) orelse return null;

    if (inferMethodStyle(tree, fn_proto, return_expr, db)) |a| return a;
    return inferNamespaceStyle(tree, fn_proto, call_full, db);
}

fn inferMethodStyle(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    return_expr: Ast.Node.Index,
    db: *const Db,
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
    const entry = db.lookup(method_name) orelse return null;
    switch (entry.annotation) {
        .borrowed_from => |idx| if (idx == 0) return .{ .borrowed_from = param_idx },
        else => {},
    }
    return null;
}

fn inferNamespaceStyle(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    call_full: Ast.full.Call,
    db: *const Db,
) ?ReturnsAnnotation {
    const callee = call_full.ast.fn_expr;
    const method_tok = switch (tree.nodeTag(callee)) {
        .identifier => tree.nodeMainToken(callee),
        .field_access => tree.nodeData(callee).node_and_token[1],
        else => return null,
    };
    const method_name = tree.tokenSlice(method_tok);
    const entry = db.lookup(method_name) orelse return null;
    switch (entry.annotation) {
        .borrowed_from => |target_idx| {
            const args = call_full.ast.params;
            if (target_idx >= args.len) return null;
            const arg = args[target_idx];
            if (tree.nodeTag(arg) != .identifier) return null;
            const arg_name = tree.tokenSlice(tree.nodeMainToken(arg));
            const our_param = resolveParamIndex(tree, fn_proto, arg_name) orelse return null;
            return .{ .borrowed_from = our_param };
        },
        else => return null,
    }
}

/// Returns the inner expression of the lone `return X;` statement in
/// a body, or null if the body has any other shape.
fn singleReturnExpr(tree: *const Ast, body_node: Ast.Node.Index) ?Ast.Node.Index {
    const tag = tree.nodeTag(body_node);
    const stmts_data = switch (tag) {
        .block_two, .block_two_semicolon => blk: {
            const d = tree.nodeData(body_node).opt_node_and_opt_node;
            // first slot present, second slot absent → 1 stmt.
            const first = d[0].unwrap() orelse return null;
            if (d[1].unwrap() != null) return null;
            break :blk first;
        },
        .block, .block_semicolon => blk: {
            const d = tree.nodeData(body_node).extra_range;
            const start: u32 = @intFromEnum(d.start);
            const end: u32 = @intFromEnum(d.end);
            if (end - start != 1) return null;
            const idx: Ast.Node.Index = @enumFromInt(tree.extra_data[start]);
            break :blk idx;
        },
        else => return null,
    };
    if (tree.nodeTag(stmts_data) != .@"return") return null;
    return tree.nodeData(stmts_data).opt_node.unwrap();
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

        if (std.mem.startsWith(u8, trimmed, "@returns owned")) return .owned;
        if (std.mem.startsWith(u8, trimmed, "@returns owns_locals")) return .owns_locals;

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
    try std.testing.expect(r.db.lookup("alloc").?.annotation == .owned);
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
    try std.testing.expect(entry.annotation == .borrowed_from);
    try std.testing.expectEqual(@as(u32, 0), entry.annotation.borrowed_from);
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
    try std.testing.expect(r.db.lookup("dupString").?.annotation == .owned);
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
