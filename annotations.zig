//! Annotation database — extract every `/// @returns ...` doc-comment
//! from a parsed file, keyed by function name.  Layer 2's classifyExpr
//! consults this when it sees a method/function call.
//!
//! v1 scope: same-file lookup only.  Cross-file (and cross-module via
//! @import resolution) is future work.

const std = @import("std");
const Ast = std.zig.Ast;
const config_mod = @import("config.zig");

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
    /// `/// @returns worker_arena` — return is a pointer into a
    /// worker-thread bump arena.  Reading from main thread before
    /// the worker is joined is unsafe (drives invariant #3).
    worker_arena,
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
    /// `/// @takes worker_arena(<param>)` — function reads from a
    /// worker-arena pointer.  Caller must have joined the worker
    /// thread before this call (state.thread must be `.joined`).
    /// `param_index` is the 0-based position of the worker-arena arg.
    worker_arena: u32,
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

/// Build an annotation DB using the default config (drop-in path).
/// Inference runs against `config.Default` — see `buildWithConfig`
/// for the explicit-config form.
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !Db {
    return buildWithConfig(gpa, tree, &config_mod.Default);
}

/// Walk every fn_decl in `tree`, extract any explicit `///` annotations,
/// then INFER annotations from signature shape (drop-in adoption path —
/// most call sites work without authors writing annotations).
///
/// Inference rules — applied only when no explicit annotation present:
///   R1: fn has exactly one param whose type mentions config.ast_type_name
///       AND a NodeIndex-shaped param  → infer @takes node_index_of(<the_ast_param>).
///   R2: fn has exactly one Ast param AND returns NodeIndex (token-named)
///        → infer @returns node_index_of(<the_ast_param>).
///   R3: fn returns config.ast_type_name (or `!Ast` etc.) → infer @returns ast.
///   R4: fn has exactly one *const-Ast param AND returns a slice type
///       (`[]const u8`, `[]u8`, etc.) → infer @returns borrowed_from(<param>).
///   R5: fn's first Ast param is `*Ast` (NOT *const) AND the body
///       actually mutates through it (field assignment or known
///       mutating method call) → infer @mutates_ast.  Body scan
///       confirms intent so functions that take *Ast purely for ABI
///       consistency don't get spurious mutation annotations.
///
/// Genuinely ambiguous cases (multi-ast + NodeIndex arg, custom pass
/// IDs, worker-arena producers) still require explicit annotations.
pub fn buildWithConfig(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
) !Db {
    var db: Db = .{ .fns = .empty };
    errdefer db.deinit(gpa);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        const name_tok = fn_proto.name_token orelse continue;

        var annotation = parseReturnsAnnotation(tree, fn_proto);
        var takes = parseTakesAnnotation(tree, fn_proto);
        var mutates_ast = parseMutatesAstAnnotation(tree, fn_proto);

        // Inference fills holes the author didn't annotate.  Each
        // rule only fires when the corresponding slot is still null.
        // R5 needs the body too — fn_decl shape carries it as the
        // second node_and_node component.
        const body_node: ?Ast.Node.Index = if (tree.nodeTag(node) == .fn_decl)
            tree.nodeData(node).node_and_node[1]
        else
            null;
        const inferred = inferAnnotations(tree, fn_proto, body_node, config);
        if (annotation == null) annotation = inferred.returns;
        if (takes == null) takes = inferred.takes;
        if (mutates_ast == null) mutates_ast = inferred.mutates_ast;

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
        if (parseParenParamForm(trimmed, "@takes worker_arena(", tree, fn_proto)) |idx| {
            return .{ .worker_arena = idx };
        }
    }
    return null;
}

const Inferred = struct {
    returns: ?ReturnsAnnotation,
    takes: ?TakesAnnotation,
    mutates_ast: ?MutatesAstAnnotation,
};

/// Walk the fn signature (+ body for R5), return inferred annotations
/// or null where inference can't decide.  Intra-procedural — no cross
/// function reasoning, but body scan IS used to confirm mutation
/// intent before inferring @mutates_ast (R5).
fn inferAnnotations(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body_node: ?Ast.Node.Index,
    config: *const config_mod.Config,
) Inferred {
    // First pass: count Ast params, find the (unique) one's index,
    // check for any NodeIndex param, and track whether the unique
    // Ast param is read-only (`*const Ast`-shaped).
    // R1/R2/R4 treat both the Ast type AND any configured holder
    // type as "carrying an Ast".  R5 stays strict (handled separately
    // by inferMutatesAstFromBody using only ast_type_name).
    var ast_param_count: u32 = 0;
    var ast_param_idx: u32 = 0;
    var ast_param_is_const: bool = false;
    var has_node_index_param: bool = false;
    var idx: u32 = 0;
    var it = fn_proto.iterate(tree);
    while (it.next()) |param| : (idx += 1) {
        const type_node = param.type_expr orelse continue;
        if (typeMentionsAstOrHolder(tree, type_node, config)) {
            ast_param_count += 1;
            ast_param_idx = idx;
            ast_param_is_const = typeMentionsKeyword(tree, type_node, .keyword_const);
        }
        if (typeMentionsIdentifier(tree, type_node, "NodeIndex")) {
            has_node_index_param = true;
        }
    }

    var inferred: Inferred = .{ .returns = null, .takes = null, .mutates_ast = null };

    // R5: body-scan inference for @mutates_ast.
    //
    // Single-Ast-param case → .implicit (when *Ast & body mutates).
    // Multi-Ast-param case  → .of(idx) (when EXACTLY ONE param is
    //                        mutated in the body).  Lets fns like
    //                        `linkChild(parent: *Ast, child: *Ast)`
    //                        get the right precision without an
    //                        explicit annotation.
    if (body_node) |body| {
        inferred.mutates_ast = inferMutatesAstFromBody(tree, fn_proto, body, config);
    }

    // R3: returns Ast (or !Ast etc.) → @returns ast.
    if (fn_proto.ast.return_type.unwrap()) |rt| {
        if (typeMentionsIdentifier(tree, rt, config.ast_type_name)) {
            inferred.returns = .ast;
        }
        // R2: returns NodeIndex with exactly one Ast param → tag it.
        if (typeMentionsIdentifier(tree, rt, "NodeIndex") and ast_param_count == 1) {
            inferred.returns = .{ .node_index_of = ast_param_idx };
        }
        // R4: returns a slice type (`[]const u8` etc.) with exactly
        // one *const-Ast param → @returns borrowed_from(<that_param>).
        // The const constraint keeps us conservative: a mutable
        // *Ast might be doing something other than reading source.
        if (ast_param_count == 1 and
            ast_param_is_const and
            inferred.returns == null and
            typeIsSliceShaped(tree, rt))
        {
            inferred.returns = .{ .borrowed_from = ast_param_idx };
        }
    }

    // R1: exactly one Ast param + at least one NodeIndex param →
    //     @takes node_index_of(<the_ast_param>).
    if (ast_param_count == 1 and has_node_index_param) {
        inferred.takes = .{ .node_index_of = ast_param_idx };
    }

    return inferred;
}

/// Does the type expression's token span contain a `[` immediately
/// followed by a `]`?  Catches `[]T`, `[]const T`, `[*]T`, `[:0]const T`,
/// etc.  False positives bounded — extra borrowed_from inferences
/// trigger the same escape check the author would have wanted anyway.
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

/// R5 driver — walks every Ast-typed *Ast param, asks whether the
/// body mutates through it, returns the appropriate MutatesAstAnnotation:
///   - no mutation in any param      → null
///   - exactly one param mutated     → .implicit if that's the only
///                                     Ast param; .of(idx) otherwise
///                                     (multi-param disambiguation)
///   - multiple params mutated       → null (ambiguous, author must
///                                     annotate)
fn inferMutatesAstFromBody(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    body: Ast.Node.Index,
    config: *const config_mod.Config,
) ?MutatesAstAnnotation {
    var mutated_count: u32 = 0;
    var mutated_idx: u32 = 0;
    var total_ast_params: u32 = 0;
    var idx: u32 = 0;
    var it = fn_proto.iterate(tree);
    while (it.next()) |param| : (idx += 1) {
        const type_node = param.type_expr orelse continue;
        if (!typeMentionsIdentifier(tree, type_node, config.ast_type_name)) continue;
        total_ast_params += 1;
        // Filter: only mutable pointers can mutate the caller's Ast.
        if (!typeIsPointerTo(tree, type_node, config.ast_type_name)) continue;
        if (typeMentionsKeyword(tree, type_node, .keyword_const)) continue;
        const name_tok = param.name_token orelse continue;
        const name = tree.tokenSlice(name_tok);
        if (bodyMutatesReceiver(tree, body, name)) {
            mutated_count += 1;
            mutated_idx = idx;
        }
    }
    if (mutated_count == 0) return null;
    if (mutated_count > 1) return null; // ambiguous
    return if (total_ast_params == 1) .implicit else .{ .of = mutated_idx };
}

/// Look up the type-expression node of the param at `param_idx`
/// (0-based).  Needed by R5 to distinguish `*Ast` from `Ast` (by-value).
fn paramTypeNode(fn_proto: Ast.full.FnProto, tree: *const Ast, param_idx: u32) Ast.Node.Index {
    var idx: u32 = 0;
    var it = fn_proto.iterate(tree);
    while (it.next()) |param| : (idx += 1) {
        if (idx == param_idx) {
            if (param.type_expr) |t| return t;
            break;
        }
    }
    // Caller already verified an Ast-typed param exists at this idx;
    // a missing type_expr would mean caller was wrong — return root
    // as a harmless fallback.
    return @enumFromInt(0);
}

/// Does the type's token span START with a `*` (or `*const` etc.)
/// followed by a token that mentions `name`?  Distinguishes `*Ast`
/// from by-value `Ast`.  R5 uses this to skip by-value receivers.
fn typeIsPointerTo(tree: *const Ast, type_node: Ast.Node.Index, name: []const u8) bool {
    const first = tree.firstToken(type_node);
    const tags = tree.tokens.items(.tag);
    if (tags[first] != .asterisk) return false;
    return typeMentionsIdentifier(tree, type_node, name);
}

/// Body scan for R5: does the function body contain a mutation
/// THROUGH `recv_name`?  Two patterns count:
///   1.  <recv> . field ... = expr;         (assignment)
///   2.  <recv> . <method> (...);            where method is in the
///       conservative "known mutating" list (append, put, insert,
///       remove, clear, set, push, pop, resize, swap, sort).
/// Walks the body's token span — no node-tree traversal needed.
fn bodyMutatesReceiver(tree: *const Ast, body_node: Ast.Node.Index, recv_name: []const u8) bool {
    const first = tree.firstToken(body_node);
    const last = tree.lastToken(body_node);
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), recv_name)) continue;
        if (tags[t + 1] != .period) continue;

        // Walk forward through the dotted chain after `<recv>.`,
        // tracking each identifier seen.  Two ways out flag mutation:
        //   1. The chain ends at `<id>(` where <id> is a known mutator.
        //   2. The chain ends at an `=` (not `==`/`!=`) before `;`/`{`.
        //      Any field-access write through the receiver counts.
        var j = t + 2;
        var last_ident: ?Ast.TokenIndex = null;
        while (j <= last) : (j += 1) {
            switch (tags[j]) {
                .identifier => last_ident = j,
                .period => {}, // continue the chain
                .l_paren => {
                    if (last_ident) |li| {
                        if (isMutatingMethodName(tree.tokenSlice(li))) return true;
                    }
                    break; // call args follow; not interested
                },
                .equal => return true,
                .semicolon, .l_brace, .r_brace, .equal_equal, .bang_equal => break,
                .l_bracket => {}, // indexing — continue (e.g. self.items.items[0])
                .r_bracket => {},
                else => continue,
            }
        }
    }
    return false;
}

/// Conservative list of method names whose presence on a receiver
/// implies mutation.  Matches std container API + common verbs.
fn isMutatingMethodName(name: []const u8) bool {
    const mutators = [_][]const u8{
        "append",   "appendSlice",   "appendAssumeCapacity",
        "put",      "putAssumeCapacity",
        "insert",   "insertSlice",
        "remove",   "orderedRemove", "swapRemove",
        "clear",    "clearAndFree",  "clearRetainingCapacity",
        "set",      "setAndFree",
        "push",     "pop",
        "resize",   "ensureTotalCapacity",
        "swap",
        "sort",     "sortUnstable",
        "deinit",
        "writeAll", "writeByte", "writeInt",
    };
    for (mutators) |m| {
        if (std.mem.eql(u8, name, m)) return true;
    }
    return false;
}

/// Does the type expression's token span include `tag`?  Used by R4
/// to check for `const` keyword on Ast-pointer params.
fn typeMentionsKeyword(tree: *const Ast, type_node: Ast.Node.Index, tag: std.zig.Token.Tag) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tags[t] == tag) return true;
    }
    return false;
}

/// Does the type expression mention the Ast type OR any configured
/// holder type?  Used by R1/R2/R4 so wrapper types (e.g.
/// LintContext that carries an Ast) get the same Ast-carrying
/// treatment as a direct *Ast.
fn typeMentionsAstOrHolder(
    tree: *const Ast,
    type_node: Ast.Node.Index,
    config: *const config_mod.Config,
) bool {
    if (typeMentionsIdentifier(tree, type_node, config.ast_type_name)) return true;
    for (config.ast_holder_types) |holder| {
        if (typeMentionsIdentifier(tree, type_node, holder)) return true;
    }
    return false;
}

/// Does the type expression's token span contain the bare identifier
/// `name`?  Same shape as cfg.typeMentionsAst — duplicated here to
/// keep annotations.zig free of cfg.zig dependencies.
fn typeMentionsIdentifier(tree: *const Ast, type_node: Ast.Node.Index, name: []const u8) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tree.tokens.items(.tag)[t] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t), name))
            return true;
    }
    return false;
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
        // Bare-keyword forms checked BEFORE paren forms so they
        // don't get partial-matched against any parenthesized shape.
        if (std.mem.eql(u8, trimmed, "@returns ast")) return .ast;
        if (std.mem.eql(u8, trimmed, "@returns worker_arena")) return .worker_arena;

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

test "inference R1: single Ast param + NodeIndex param → @takes node_index_of inferred" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\pub fn nodeTag(self: *const Ast, idx: NodeIndex) u32 {
        \\    _ = self; _ = idx; return 0;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("nodeTag").?;
    try std.testing.expect(entry.takes.? == .node_index_of);
    try std.testing.expectEqual(@as(u32, 0), entry.takes.?.node_index_of);
}

test "inference R2: single Ast param + returns NodeIndex → @returns node_index_of inferred" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
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

test "inference R3: returns Ast type → @returns ast inferred" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\pub fn customParse(src: []const u8) Ast {
        \\    _ = src; return .{};
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("customParse").?;
    try std.testing.expect(entry.annotation.? == .ast);
}

test "inference R4: *const Ast + slice return → @returns borrowed_from inferred" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
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

test "inference R4: mutable *Ast NOT inferred (conservative)" {
    // *Ast (no const) could be doing more than reading — R4 declines
    // to guess.  Author must annotate explicitly if borrowed_from
    // semantics are intended.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\pub fn weird(self: *Ast, idx: u32) []const u8 {
        \\    _ = self; _ = idx; return "";
        \\}
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expect(r.db.lookup("weird") == null);
}

test "inference R4: returns NodeIndex wins over slice — R2 takes precedence" {
    // Returns NodeIndex (not a slice) — R2 fires first.  R4 only
    // runs when inferred.returns is still null.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\pub fn rootNode(ast: *const Ast) NodeIndex { _ = ast; return 0; }
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("rootNode").?;
    try std.testing.expect(entry.annotation.? == .node_index_of);
}

test "inference R5: *Ast receiver + field write in body → @mutates_ast" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct { tag: u32 = 0 };
        \\pub fn setTag(self: *Ast, t: u32) void {
        \\    self.tag = t;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("setTag").?;
    try std.testing.expect(entry.mutates_ast.? == .implicit);
}

test "inference R5: *Ast receiver + mutating method call → @mutates_ast" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct { items: u32 = 0 };
        \\pub fn pushItem(self: *Ast, x: u32) void {
        \\    self.items.append(x);
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("pushItem").?;
    try std.testing.expect(entry.mutates_ast.? == .implicit);
}

test "inference R5: *const Ast receiver — NOT inferred even with body access" {
    // R5 filters on `*Ast` (mutable pointer); *const Ast can't
    // mutate by type, so we skip even if the body has writes
    // (which wouldn't compile anyway).
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\pub fn readOnly(self: *const Ast) u32 {
        \\    _ = self;
        \\    return 0;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("readOnly") orelse return;
    try std.testing.expect(entry.mutates_ast == null);
}

test "inference R5: *Ast receiver but body only reads — NOT inferred" {
    // *Ast taken for ABI consistency but body has no mutation.
    // Body-scan filter catches this correctly.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct { tag: u32 = 0 };
        \\pub fn readTag(self: *Ast) u32 {
        \\    return self.tag;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("readTag") orelse return;
    try std.testing.expect(entry.mutates_ast == null);
}

test "inference R5: multi-Ast-param disambiguates → @mutates_ast(<param>)" {
    // Two *Ast params; only `parent` is written.  Inference picks
    // the right one and emits .of(0).
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct { children: u32 = 0 };
        \\pub fn linkChild(parent: *Ast, child: *Ast) void {
        \\    _ = child;
        \\    parent.children = 1;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("linkChild").?;
    try std.testing.expect(entry.mutates_ast.? == .of);
    try std.testing.expectEqual(@as(u32, 0), entry.mutates_ast.?.of);
}

test "inference R5: multi-Ast-param both mutated → ambiguous, not inferred" {
    // Both params written → can't disambiguate.  Author must
    // annotate explicitly.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct { x: u32 = 0 };
        \\pub fn swapBoth(a: *Ast, b: *Ast) void {
        \\    a.x = 1;
        \\    b.x = 2;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("swapBoth") orelse return;
    try std.testing.expect(entry.mutates_ast == null);
}

test "inference R5: comparison through receiver is NOT mutation" {
    // `if (self.tag == 0)` mustn't trip the assignment scan.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct { tag: u32 = 0 };
        \\pub fn isRoot(self: *Ast) bool {
        \\    return self.tag == 0;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("isRoot") orelse return;
    try std.testing.expect(entry.mutates_ast == null);
}

test "inference: multiple Ast params is ambiguous — no auto-takes" {
    // Two Ast params + a NodeIndex arg → which Ast does it belong to?
    // Inference refuses to guess; author must annotate explicitly.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\pub fn ambiguous(a: *const Ast, b: *const Ast, n: NodeIndex) void {
        \\    _ = a; _ = b; _ = n;
        \\}
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expect(r.db.lookup("ambiguous") == null);
}

test "inference: explicit annotation wins over would-be inferred" {
    // Explicit @takes node_index_of(other_param) overrides the
    // inference rule that would have picked the single Ast param.
    // (Currently we only have one Ast param so inference WOULD set
    // takes; explicit annotation already in place must remain.)
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\/// @takes node_index_any
        \\pub fn debugDump(self: *const Ast, n: NodeIndex) void {
        \\    _ = self; _ = n;
        \\}
        \\
    );
    defer r.deinit(gpa);

    const entry = r.db.lookup("debugDump").?;
    try std.testing.expect(entry.takes.? == .node_index_any);
}

test "extract @returns worker_arena annotation" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\/// @returns worker_arena
        \\pub fn spawnWorker() []u8 { return ""; }
        \\
    );
    defer r.deinit(gpa);
    try std.testing.expect(r.db.lookup("spawnWorker").?.annotation.? == .worker_arena);
}

test "extract @takes worker_arena(<param>) annotation" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\/// @takes worker_arena(buf)
        \\pub fn consume(buf: []u8) void { _ = buf; }
        \\
    );
    defer r.deinit(gpa);
    const entry = r.db.lookup("consume").?;
    try std.testing.expect(entry.takes.? == .worker_arena);
    try std.testing.expectEqual(@as(u32, 0), entry.takes.?.worker_arena);
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

test "node_index_of with unknown param name falls back to inferred" {
    // Previously: malformed annotation → no entry.  Now: explicit
    // annotation fails to resolve, inference fills the hole.  The fn
    // shape (one Ast param, returns NodeIndex) matches R2, so we get
    // the correct inferred annotation despite the typo.
    // (A diagnostic for unresolved annotation names is worth adding;
    // for now silently falling back to inference matches the
    // drop-in-adoption goal.)
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

    const entry = r.db.lookup("rootNode").?;
    try std.testing.expect(entry.annotation.? == .node_index_of);
    try std.testing.expectEqual(@as(u32, 0), entry.annotation.?.node_index_of);
}

