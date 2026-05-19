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
    /// `/// @returns ast` — return is a fresh Ast value.  Mints a new
    /// AstId at transfer time, same effect as our text-detected
    /// `Ast.parse(...)` pattern but explicit and works for any
    /// constructor (custom parser entry points, factory fns, etc.).
    ast,
    /// `/// @returns scope_from(<pass_name>)` — return is a ScopeId
    /// or SymbolId minted by a specific analysis pass.  Use as input
    /// to a different pass is invalid (drives invariant #4).
    /// `pass_name` is a slice into source (caller keeps source alive).
    scope_from: []const u8,
};

/// Function-level `@mutates_ast ...` annotation.
pub const MutatesAstAnnotation = union(enum) {
    /// `/// @mutates_ast` (no parens) — implicit: receiver for method
    /// calls, args[0] for namespace calls.  Phase 37 default.
    implicit,
    /// `/// @mutates_ast(<param>)` — explicit param-index resolution.
    /// Author calls out which arg is the Ast being mutated.  Allows
    /// annotating fns like `mutateChild(parent, child)` where the
    /// SECOND arg is the mutated Ast.  Phase 39 refinement.
    of: u32,
};

/// Function-level `@takes ...` annotation.
pub const TakesAnnotation = union(enum) {
    /// `/// @takes node_index_of(<param>)` — the function consumes
    /// NodeIndex args that must originate from the Ast carried by
    /// `<param>`.  Emits `.ast_takes_check` per-arg stmts.
    node_index_of: u32,
    /// `/// @takes node_index_any` — explicit opt-out.  The function
    /// accepts NodeIndex args from any Ast; emission skips checks
    /// entirely.  Matches the Layer-1 hygiene rule's vocabulary.
    node_index_any,
    /// `/// @takes scope_from(<pass_name>)` — the function consumes
    /// ScopeId / SymbolId args that must originate from the named
    /// pass.  Drives invariant #4 enforcement at call sites.
    /// `pass_name` is a slice into source (caller keeps source alive).
    scope_from: []const u8,
};

pub const FnEntry = struct {
    /// Function name (slice into the source — keep source alive).
    name: []const u8,
    /// Optional `@returns ...`; null when none parsed.
    annotation: ?ReturnsAnnotation = null,
    /// Optional `@takes ...`; null when none parsed.
    takes: ?TakesAnnotation = null,
    /// `/// @mutates_ast` or `/// @mutates_ast(<param>)` — method
    /// mutates an Ast value (writes a field, rebuilds derived caches,
    /// etc.).  Used to enforce invariant #5: any caller that holds
    /// an Origin.ast value (constructed or received via param)
    /// flagged at the call site since post-parse mutation invalidates
    /// the parent_indices and tag CSRs that downstream passes rely on.
    /// Null when no annotation; .implicit for bare `@mutates_ast`;
    /// .of(idx) when an explicit param is named.
    mutates_ast: ?MutatesAstAnnotation = null,
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

        const annotation = parseReturnsAnnotation(tree, fn_proto);
        const takes = parseTakesAnnotation(tree, fn_proto);
        const mutates_ast = parseMutatesAstAnnotation(tree, fn_proto);
        if (annotation == null and takes == null and mutates_ast == null) continue;
        const name = tree.tokenSlice(name_tok);
        try db.fns.put(gpa, name, .{
            .name = name,
            .annotation = annotation,
            .takes = takes,
            .mutates_ast = mutates_ast,
        });
    }
    return db;
}

fn parseMutatesAstAnnotation(tree: *const Ast, fn_proto: Ast.full.FnProto) ?MutatesAstAnnotation {
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

        // Bare form first — whole-word check so `@mutates_ast(foo)`
        // doesn't accidentally match here.
        if (std.mem.eql(u8, trimmed, "@mutates_ast")) return .implicit;
        // Parenthesized form: `@mutates_ast(<param>)`.
        if (parseParenParamForm(trimmed, "@mutates_ast(", tree, fn_proto)) |idx| {
            return .{ .of = idx };
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

        if (std.mem.startsWith(u8, trimmed, "@takes node_index_any")) {
            return .node_index_any;
        }
        if (parseParenParamForm(trimmed, "@takes node_index_of(", tree, fn_proto)) |idx| {
            return .{ .node_index_of = idx };
        }
        if (parseParenNameForm(trimmed, "@takes scope_from(")) |name| {
            return .{ .scope_from = name };
        }
    }
    return null;
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
        // `@returns ast` must check BEFORE the paren forms so the
        // bare keyword doesn't get matched against any parenthesized
        // shape.  Whole-word check to keep things tight.
        if (std.mem.eql(u8, trimmed, "@returns ast")) return .ast;

        if (parseParenParamForm(trimmed, "@returns borrowed_from(", tree, fn_proto)) |idx| {
            return .{ .borrowed_from = idx };
        }
        if (parseParenParamForm(trimmed, "@returns node_index_of(", tree, fn_proto)) |idx| {
            return .{ .node_index_of = idx };
        }
        if (parseParenNameForm(trimmed, "@returns scope_from(")) |name| {
            return .{ .scope_from = name };
        }
    }
    return null;
}

/// Match `<prefix><name>)` and return `<name>` as a source slice.
/// Used by annotations whose payload is an arbitrary identifier
/// (pass name, etc.) rather than a function-param reference.
/// Returns null on prefix miss, missing close-paren, or empty name.
fn parseParenNameForm(trimmed: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    const after = trimmed[prefix.len..];
    const close = std.mem.indexOfScalar(u8, after, ')') orelse return null;
    const name = std.mem.trim(u8, after[0..close], " \t");
    return if (name.len == 0) null else name;
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
    try std.testing.expect(entry.annotation.? == .borrowed_from);
    try std.testing.expectEqual(@as(u32, 0), entry.annotation.?.borrowed_from);
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
    try std.testing.expect(entry.annotation.? == .owned);
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
    try std.testing.expect(entry.annotation.? == .borrowed_from);
    try std.testing.expectEqual(@as(u32, 1), entry.annotation.?.borrowed_from);
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
    try std.testing.expect(entry.annotation.? == .node_index_of);
    try std.testing.expectEqual(@as(u32, 0), entry.annotation.?.node_index_of);
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
    try std.testing.expect(entry.annotation.? == .node_index_of);
    try std.testing.expectEqual(@as(u32, 1), entry.annotation.?.node_index_of);
}

test "extract @mutates_ast annotation (phase 37)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\/// @mutates_ast
        \\pub fn setNodeTag(self: *Ast, _: u32) void { _ = self; }
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("setNodeTag").?;
    try std.testing.expect(entry.mutates_ast.? == .implicit);
}

test "extract @mutates_ast(<param>) explicit form (phase 39)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\/// @mutates_ast(child)
        \\pub fn linkChild(parent: *Ast, child: *Ast) void { _ = parent; _ = child; }
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("linkChild").?;
    try std.testing.expect(entry.mutates_ast.? == .of);
    try std.testing.expectEqual(@as(u32, 1), entry.mutates_ast.?.of);
}

test "extract @returns ast annotation (phase 33)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\/// @returns ast
        \\pub fn customParse(src: []const u8) Ast {
        \\    _ = src; return .{};
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("customParse").?;
    try std.testing.expect(entry.annotation.? == .ast);
}

test "extract @returns scope_from(<pass>) annotation" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const ScopeId = u32;
        \\/// @returns scope_from(scope_resolve)
        \\pub fn mintScope() ScopeId { return 0; }
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("mintScope").?;
    try std.testing.expect(entry.annotation.? == .scope_from);
    try std.testing.expectEqualStrings("scope_resolve", entry.annotation.?.scope_from);
}

test "extract @takes scope_from(<pass>) annotation" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const ScopeId = u32;
        \\/// @takes scope_from(type_check)
        \\pub fn usesScope(s: ScopeId) void { _ = s; }
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("usesScope").?;
    try std.testing.expect(entry.takes.? == .scope_from);
    try std.testing.expectEqualStrings("type_check", entry.takes.?.scope_from);
}

test "extract @takes node_index_any annotation (phase 29)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const NodeIndex = u32;
        \\/// @takes node_index_any
        \\pub fn debugDump(n: NodeIndex) void { _ = n; }
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("debugDump").?;
    try std.testing.expect(entry.takes.? == .node_index_any);
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

