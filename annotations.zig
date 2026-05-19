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
/// annotation, then run inference (R6) to fill obvious holes.
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !Db {
    var db: Db = .{ .fns = .empty };
    errdefer db.deinit(gpa);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        const name_tok = fn_proto.name_token orelse continue;

        var annotation = parseReturnsAnnotation(tree, fn_proto);

        // R6 inference: returns a slice + body allocates → @returns owned.
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
    return db;
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
