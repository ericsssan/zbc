//! Annotation database — extract every `/// @returns ...` doc-comment
//! from a parsed file, keyed by function name.  Layer 2's classifyExpr
//! consults this when it sees a method/function call.
//!
//! v1 scope: same-file lookup only.  Cross-file (and cross-module via
//! @import resolution) is future work.

const std = @import("std");
const Ast = std.zig.Ast;

pub const ReturnsAnnotation = union(enum) {
    /// `/// @returns owned` — caller owns despite borrowed-shape sig.
    owned,
    /// `/// @returns borrowed_from(<param>)` — return borrows from the
    /// named param.  `param_index` is the 0-based position of that
    /// param in the function signature (resolved at extraction time
    /// so call sites don't re-walk params).
    borrowed_from: u32,
    /// `/// @returns node_index_of(<param>)` — return is a NodeIndex
    /// tagged with the Ast that `<param>` carries.  Used to enforce
    /// invariant #1 at call sites: a NodeIndex obtained from Ast A
    /// must only flow back into A.  `param_index` is the 0-based
    /// position of the Ast-carrier arg.  Phase 24 parses only;
    /// classifyCall + transfer wiring lands in phase 25.
    node_index_of: u32,
};

pub const FnEntry = struct {
    /// Function name (slice into the source — keep source alive).
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

/// Walk every fn_decl in `tree`, extract its @returns annotation (if any),
/// and build a name → entry map.  Duplicate names overwrite — Zig allows
/// shadowing inside structs; conservative behaviour for our purposes.
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !Db {
    var db: Db = .{ .fns = .empty };
    errdefer db.deinit(gpa);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        const name_tok = fn_proto.name_token orelse continue;

        const annotation = parseReturnsAnnotation(tree, fn_proto) orelse continue;
        const name = tree.tokenSlice(name_tok);
        try db.fns.put(gpa, name, .{ .name = name, .annotation = annotation });
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

        if (parseParenParamForm(trimmed, "@returns borrowed_from(", tree, fn_proto)) |idx| {
            return .{ .borrowed_from = idx };
        }
        if (parseParenParamForm(trimmed, "@returns node_index_of(", tree, fn_proto)) |idx| {
            return .{ .node_index_of = idx };
        }
    }
    return null;
}

/// Match `<prefix><paramname>)` and resolve paramname to its 0-based
/// position in the function signature.  Returns null on either a
/// prefix miss, a malformed close-paren, or an unknown param.
fn parseParenParamForm(
    trimmed: []const u8,
    prefix: []const u8,
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
) ?u32 {
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    const after = trimmed[prefix.len..];
    const close = std.mem.indexOfScalar(u8, after, ')') orelse return null;
    const param_name = std.mem.trim(u8, after[0..close], " \t");
    return resolveParamIndex(tree, fn_proto, param_name);
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

// ── Tests ──────────────────────────────────────────────────

/// Test helper.  Caller owns the returned bundle and must call .deinit(gpa).
/// The `src_z` field outlives both `tree` and `db` — tree.source borrows
/// from it, and db's keys borrow from tree.source.
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

test "extract @returns borrowed_from annotation" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\/// @returns borrowed_from(self)
        \\pub fn tokenText(self: *const Ast, idx: u32) []const u8 {
        \\    _ = self; _ = idx; return "";
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("tokenText").?;
    try std.testing.expect(entry.annotation == .borrowed_from);
    try std.testing.expectEqual(@as(u32, 0), entry.annotation.borrowed_from);
}

test "extract @returns owned annotation" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\/// @returns owned
        \\pub fn alloc(gpa: u32) ![]u8 {
        \\    _ = gpa; return "";
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("alloc").?;
    try std.testing.expect(entry.annotation == .owned);
}

test "no annotation → not in db" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\pub fn add(a: u32, b: u32) u32 { return a + b; }
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expect(r.db.lookup("add") == null);
}

test "param index resolves correctly for borrowed_from(non-self)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\/// @returns borrowed_from(ast)
        \\pub fn extract(gpa: u32, ast: *const Ast, idx: u32) []const u8 {
        \\    _ = gpa; _ = ast; _ = idx; return "";
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("extract").?;
    try std.testing.expect(entry.annotation == .borrowed_from);
    try std.testing.expectEqual(@as(u32, 1), entry.annotation.borrowed_from);
}

test "extract @returns node_index_of annotation (phase 24)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(ast)
        \\pub fn rootNode(ast: *const Ast) NodeIndex {
        \\    _ = ast; return 0;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("rootNode").?;
    try std.testing.expect(entry.annotation == .node_index_of);
    try std.testing.expectEqual(@as(u32, 0), entry.annotation.node_index_of);
}

test "node_index_of param resolution: non-self position" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(target)
        \\pub fn lookupNode(gpa_: u32, target: *const Ast, name: []const u8) NodeIndex {
        \\    _ = gpa_; _ = target; _ = name; return 0;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("lookupNode").?;
    try std.testing.expect(entry.annotation == .node_index_of);
    try std.testing.expectEqual(@as(u32, 1), entry.annotation.node_index_of);
}

test "node_index_of with unknown param name → no entry" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(typo)
        \\pub fn rootNode(ast: *const Ast) NodeIndex {
        \\    _ = ast; return 0;
        \\}
        \\
    );
    defer r.deinit(gpa);

    // Malformed annotations skip entry creation — consistent with how
    // borrowed_from handles param-resolution failure.
    try std.testing.expect(r.db.lookup("rootNode") == null);
}

