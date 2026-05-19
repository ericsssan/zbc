//! Layer 2 CFG types and Zig-AST → CFG lowering.
//!
//! v1 scope: extract a flow graph from a single Zig function over the
//! subset of statement shapes that affect our abstract state.  Most
//! Zig syntax doesn't change lifetime/identity; we collapse it into
//! `.plain_expr` and only emit dedicated statement nodes for the ops
//! we'll actually transfer over in week 4.
//!
//! What we DO model:
//!   - `var/const NAME = INIT;` (local binding)
//!   - `LHS = RHS;` (assignment)
//!   - call expressions (especially annotated-callee returns)
//!   - `arena.deinit()` (arena death)
//!   - `thread.join()` (thread join)
//!   - `return EXPR;` (function exit)
//!   - `if/else` and `while` branching (control flow only)
//!
//! What we DON'T model (yet):
//!   - `for` loops (week 4)
//!   - `switch` (week 4)
//!   - `defer` / `errdefer` (week 4 — needs cleanup-block insertion)
//!   - `try` / `catch` (week 5)
//!   - generics / comptime (skip in v1)
//!
//! Errors during lowering are surfaced as `Stmt{.lowering_gap}` nodes
//! rather than aborts — keeps the analyzer running on the rest of the
//! function even when one statement uses an unsupported construct.

const std = @import("std");
const Ast = std.zig.Ast;
const abstract_state = @import("abstract_state.zig");
const annotations = @import("annotations.zig");

pub const BlockId = abstract_state.BlockId;
pub const LocalId = abstract_state.LocalId;

// ── Source position ─────────────────────────────────────────

pub const SrcPos = struct {
    /// Byte offset into source.
    byte: u32,
    /// 1-indexed line.
    line: u32,
    /// 1-indexed column.
    column: u32,
};

// ── Statements ─────────────────────────────────────────────

pub const StmtKind = union(enum) {
    /// `var/const NAME = INIT;` — local declared, bound to RHS expression.
    /// `init_kind` describes what the RHS produces (a known annotated
    /// call, a literal, an arena init, etc.).
    decl: struct { local: LocalId, init_kind: ExprKind },

    /// `LHS = RHS;` — overwrite local with new RHS.
    assign: struct { target: LocalId, rhs_kind: ExprKind },

    /// `<receiver>.deinit()` on an arena.  Marks the arena dead.
    arena_kill: struct { arena_local: LocalId },

    /// `<thread>.join()` — transitions ThreadContext from worker→joined.
    thread_join,

    /// `return <expr>;` — function exit.  `value_kind` describes what's
    /// being returned.  `is_borrowed_return_type` tags whether the
    /// enclosing function's signature returns a borrowed-shape type
    /// (slice/pointer) — only those returns can leak a borrowed origin.
    /// Value-typed returns (struct, enum, primitive) MOVE the value
    /// to the caller and are exempt from the "arena escapes its scope"
    /// check even when the value contains an arena.
    ret: struct { value_kind: ExprKind, is_borrowed_return_type: bool },

    /// Use of a local (to read it).  Generates "is origin still live?"
    /// checks in the analyzer.
    use: struct { local: LocalId },

    /// Statement shape we couldn't lower precisely.  Conservative:
    /// analyzer assumes any local may be touched (re-set to .plain),
    /// no other side-effects.
    lowering_gap: struct { note: []const u8 },
};

pub const Stmt = struct {
    kind: StmtKind,
    pos: SrcPos,
};

// ── Expression-result classification ────────────────────────

/// Shape of a value produced by an expression.  We don't model expressions
/// as trees; just classify what the RHS produces lifetime-wise.
pub const ExprKind = union(enum) {
    /// Literal, arithmetic, value-typed call — no lifetime constraint.
    plain,
    /// Call to a fn annotated `// @returns borrowed_from(<param>)`.
    /// `borrowed_from_local` is the local that the lifetime is tied to.
    borrowed_from: LocalId,
    /// Call to a fn annotated `// @returns owned` — caller owns, no
    /// lifetime constraint despite borrowed-shape signature.
    owned,
    /// `ArenaAllocator.init(...)` — produces a fresh arena.  The
    /// declaring local becomes the arena's "name" for kill tracking.
    arena_init,
    /// Reading a local — pass-through of that local's current origin.
    copy_of: LocalId,
    /// Couldn't classify — conservative .plain at use site.
    unknown,
};

// ── Basic block ────────────────────────────────────────────

pub const BasicBlock = struct {
    id: BlockId,
    stmts: []Stmt,
    /// Successor blocks in CFG.  Empty for terminal blocks (after return).
    /// Two successors for branches (if/while); the analyzer joins their
    /// post-states at the merge block.
    successors: []BlockId,
};

// ── CFG ────────────────────────────────────────────────────

pub const Cfg = struct {
    blocks: []BasicBlock,
    entry: BlockId,
    /// Source span of the function whose body this CFG represents.
    fn_span: struct { start: u32, end: u32 },
    /// Local-name table (name & decl position keyed by LocalId).
    locals: []LocalInfo,

    pub fn deinit(self: *Cfg, gpa: std.mem.Allocator) void {
        for (self.blocks) |b| {
            gpa.free(b.stmts);
            gpa.free(b.successors);
        }
        gpa.free(self.blocks);
        gpa.free(self.locals);
    }
};

pub const LocalInfo = struct {
    name: []const u8, // borrowed from source — caller keeps source alive
    decl_pos: SrcPos,
};

// ── Lowering ───────────────────────────────────────────────

/// Lower a single Zig function body (block_two or block_two_semicolon
/// for short, block / block_semicolon for longer) into a CFG.  Returns
/// null when the function has no body (extern, etc.).
pub fn lowerFunction(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    fn_decl: Ast.Node.Index,
    db: ?*const annotations.Db,
) !?Cfg {
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = (try fnProto(tree, &buf, fn_decl)) orelse return null;
    const body_node = bodyOf(tree, fn_decl) orelse return null;

    // Pre-classify the fn's return type.  Only borrowed-shape returns
    // (slice/pointer) can leak a borrowed origin to the caller; value
    // returns move the value and are exempt from the escape check.
    const is_borrowed_ret = if (fn_proto.ast.return_type.unwrap()) |rt|
        returnTypeIsBorrowed(tree, rt)
    else
        false;

    var builder: Builder = .{
        .gpa = gpa,
        .tree = tree,
        .db = db,
        .is_borrowed_return_type = is_borrowed_ret,
    };
    defer builder.tempDeinit();

    const entry_id = try builder.newBlock();
    var cur_block = entry_id;
    try builder.lowerBlock(body_node, &cur_block);

    return try builder.finalize(tree, fn_decl, entry_id);
}

fn fnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) !?Ast.full.FnProto {
    return switch (tree.nodeTag(node)) {
        .fn_decl => switch (tree.nodeTag(tree.nodeData(node).node_and_node[0])) {
            .fn_proto => tree.fnProto(tree.nodeData(node).node_and_node[0]),
            .fn_proto_multi => tree.fnProtoMulti(tree.nodeData(node).node_and_node[0]),
            .fn_proto_one => tree.fnProtoOne(buf, tree.nodeData(node).node_and_node[0]),
            .fn_proto_simple => tree.fnProtoSimple(buf, tree.nodeData(node).node_and_node[0]),
            else => null,
        },
        else => null,
    };
}

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
}

// ── Builder ────────────────────────────────────────────────

const Builder = struct {
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: ?*const annotations.Db = null,
    blocks: std.ArrayListUnmanaged(BasicBlock) = .empty,
    /// Per-block staging — stmts being appended.  Flushed to `blocks[i].stmts`
    /// in finalize().
    block_stmts: std.ArrayListUnmanaged(std.ArrayListUnmanaged(Stmt)) = .empty,
    block_successors: std.ArrayListUnmanaged(std.ArrayListUnmanaged(BlockId)) = .empty,
    locals: std.ArrayListUnmanaged(LocalInfo) = .empty,
    /// name → LocalId for current scope.  v1 doesn't handle nested scopes;
    /// names are flat per-function.
    name_to_local: std.StringHashMapUnmanaged(LocalId) = .empty,
    /// Stack of deferred statement source nodes, LIFO.  Pushed by
    /// `lowerStmt` when it sees a `defer` / `errdefer`; popped + replayed
    /// at every `return` site and at function exit.
    deferred: std.ArrayListUnmanaged(Ast.Node.Index) = .empty,
    /// True iff the enclosing fn returns a borrowed-shape type.
    /// Threaded into `Stmt.ret.is_borrowed_return_type`.
    is_borrowed_return_type: bool = false,

    fn tempDeinit(self: *Builder) void {
        for (self.block_stmts.items) |*s| s.deinit(self.gpa);
        self.block_stmts.deinit(self.gpa);
        for (self.block_successors.items) |*s| s.deinit(self.gpa);
        self.block_successors.deinit(self.gpa);
        self.blocks.deinit(self.gpa);
        self.locals.deinit(self.gpa);
        self.name_to_local.deinit(self.gpa);
        self.deferred.deinit(self.gpa);
    }

    fn newBlock(self: *Builder) !BlockId {
        const id: BlockId = @enumFromInt(self.blocks.items.len);
        try self.blocks.append(self.gpa, .{
            .id = id,
            .stmts = &.{},
            .successors = &.{},
        });
        try self.block_stmts.append(self.gpa, .empty);
        try self.block_successors.append(self.gpa, .empty);
        return id;
    }

    fn appendStmt(self: *Builder, block: BlockId, stmt: Stmt) !void {
        try self.block_stmts.items[@intFromEnum(block)].append(self.gpa, stmt);
    }

    fn addEdge(self: *Builder, from: BlockId, to: BlockId) !void {
        try self.block_successors.items[@intFromEnum(from)].append(self.gpa, to);
    }

    fn registerLocal(self: *Builder, name: []const u8, pos: SrcPos) !LocalId {
        const id: LocalId = @enumFromInt(self.locals.items.len);
        try self.locals.append(self.gpa, .{ .name = name, .decl_pos = pos });
        try self.name_to_local.put(self.gpa, name, id);
        return id;
    }

    /// Lower the contents of a Zig block node into `cur` (mutated to the
    /// last block reached — branches may have advanced past the original).
    /// Defer statements encountered are queued and replayed in reverse
    /// order at every `return` exit point.
    fn lowerBlock(self: *Builder, block_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        var stmt_buf: [2]Ast.Node.Index = undefined;
        const stmts = blockStmts(tree, block_node, &stmt_buf);
        for (stmts) |stmt_idx| {
            try self.lowerStmt(stmt_idx, cur);
        }
        // End-of-function — replay deferred statements in LIFO order
        // before falling off the implicit-return edge (no explicit
        // ret_stmt at the tail).  v1 only: top-level block treated as
        // function body; nested blocks don't run defers at exit yet.
        // TODO(week-6): per-block defer scoping for nested blocks.
        try self.flushDefers(cur);
    }

    fn pushDefer(self: *Builder, body_node: Ast.Node.Index) !void {
        try self.deferred.append(self.gpa, body_node);
    }

    /// Replay all deferred statements (LIFO) into `cur`.  Doesn't pop —
    /// returns happen mid-function and we want subsequent code to still
    /// see the same defer set.  Called at function-exit (in lowerBlock)
    /// and at every return (in lowerReturn).
    fn flushDefers(self: *Builder, cur: *BlockId) (std.mem.Allocator.Error)!void {
        var i = self.deferred.items.len;
        while (i > 0) {
            i -= 1;
            try self.lowerStmt(self.deferred.items[i], cur);
        }
    }

    /// Dispatch on statement node tag.  v1: handle decls, assigns,
    /// expression-statement calls, returns, if/while; everything else
    /// becomes a `.lowering_gap` placeholder.
    fn lowerStmt(self: *Builder, stmt_node: Ast.Node.Index, cur: *BlockId) std.mem.Allocator.Error!void {
        const tree = self.tree;
        const tag = tree.nodeTag(stmt_node);
        switch (tag) {
            .simple_var_decl, .local_var_decl, .aligned_var_decl, .global_var_decl => {
                try self.lowerVarDecl(stmt_node, cur);
            },
            .assign, .assign_destructure => {
                try self.lowerAssign(stmt_node, cur);
            },
            .@"return" => {
                // Replay defers BEFORE the return so any arena-kills
                // they perform show up in state before we check the
                // returned value's origin.
                try self.flushDefers(cur);
                try self.lowerReturn(stmt_node, cur);
            },
            .call, .call_one, .call_comma, .call_one_comma => {
                try self.lowerCallStmt(stmt_node, cur);
            },
            .@"defer" => {
                // `defer EXPR;` — data is .node = body.
                const body = tree.nodeData(stmt_node).node;
                try self.pushDefer(body);
            },
            .@"errdefer" => {
                // `errdefer |x| EXPR;` — data is .opt_token_and_node;
                // [0] = optional `|x|` capture token, [1] = body.
                const body = tree.nodeData(stmt_node).opt_token_and_node[1];
                try self.pushDefer(body);
            },
            // TODO(week-6): if/while/for/switch branching.
            else => {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .lowering_gap = .{ .note = @tagName(tag) } },
                    .pos = self.posOf(stmt_node),
                });
            },
        }
    }

    fn lowerVarDecl(self: *Builder, decl_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const var_decl = tree.fullVarDecl(decl_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "var_decl-extract" } },
                .pos = self.posOf(decl_node),
            });
            return;
        };
        const name_tok = var_decl.ast.mut_token + 1;
        if (tree.tokens.items(.tag)[name_tok] != .identifier) {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "var_decl-no-name" } },
                .pos = self.posOf(decl_node),
            });
            return;
        }
        const name = tree.tokenSlice(name_tok);
        const local = try self.registerLocal(name, self.posOfToken(name_tok));

        const init_kind: ExprKind = if (var_decl.ast.init_node.unwrap()) |init|
            self.classifyExpr(init)
        else
            .plain;

        try self.appendStmt(cur.*, .{
            .kind = .{ .decl = .{ .local = local, .init_kind = init_kind } },
            .pos = self.posOf(decl_node),
        });
    }

    fn lowerAssign(self: *Builder, _: Ast.Node.Index, cur: *BlockId) !void {
        // TODO(week-4): identify target local, classify RHS, emit assign.
        try self.appendStmt(cur.*, .{
            .kind = .{ .lowering_gap = .{ .note = "assign" } },
            .pos = .{ .byte = 0, .line = 0, .column = 0 },
        });
    }

    fn lowerReturn(self: *Builder, ret_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const data = tree.nodeData(ret_node);
        const value_kind: ExprKind = if (data.opt_node.unwrap()) |expr|
            self.classifyExpr(expr)
        else
            .plain;
        try self.appendStmt(cur.*, .{
            .kind = .{ .ret = .{
                .value_kind = value_kind,
                .is_borrowed_return_type = self.is_borrowed_return_type,
            } },
            .pos = self.posOf(ret_node),
        });
        // Return terminates the block — no successor.
    }

    fn lowerCallStmt(self: *Builder, call_node: Ast.Node.Index, cur: *BlockId) !void {
        // Detect arena.deinit() and thread.join() patterns; otherwise
        // emit nothing (a side-effect-free call from our analyzer's pov).
        const tree = self.tree;
        const first = tree.firstToken(call_node);
        const last = tree.lastToken(call_node);
        const start = tree.tokens.items(.start)[first];
        const last_start = tree.tokens.items(.start)[last];
        const last_len = tree.tokenSlice(last).len;
        const end: usize = last_start + last_len;
        const text = tree.source[start..end];

        if (std.mem.indexOf(u8, text, ".deinit(") != null) {
            // Identify the receiver local — first identifier in `text`.
            const recv_local = self.firstIdentifierLocal(text) orelse {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .lowering_gap = .{ .note = "deinit-no-receiver" } },
                    .pos = self.posOf(call_node),
                });
                return;
            };
            try self.appendStmt(cur.*, .{
                .kind = .{ .arena_kill = .{ .arena_local = recv_local } },
                .pos = self.posOf(call_node),
            });
            return;
        }
        if (std.mem.indexOf(u8, text, ".join(") != null) {
            try self.appendStmt(cur.*, .{
                .kind = .thread_join,
                .pos = self.posOf(call_node),
            });
            return;
        }
        // Other calls — side-effect from our pov is "nothing tracked".
        try self.appendStmt(cur.*, .{
            .kind = .{ .lowering_gap = .{ .note = "call-untracked" } },
            .pos = self.posOf(call_node),
        });
    }

    fn classifyExpr(self: *Builder, expr_node: Ast.Node.Index) ExprKind {
        const tree = self.tree;
        const tag = tree.nodeTag(expr_node);

        // `ArenaAllocator.init(...)` → .arena_init
        // Source-text check, robust to nesting.
        const first = tree.firstToken(expr_node);
        const last = tree.lastToken(expr_node);
        const start = tree.tokens.items(.start)[first];
        const last_start = tree.tokens.items(.start)[last];
        const last_len = tree.tokenSlice(last).len;
        const end: usize = last_start + last_len;
        const text = tree.source[start..end];

        if (std.mem.indexOf(u8, text, "ArenaAllocator.init") != null) {
            return .arena_init;
        }

        // Identifier reference → .copy_of(local) if known
        if (tag == .identifier) {
            const name = tree.tokenSlice(tree.nodeMainToken(expr_node));
            if (self.name_to_local.get(name)) |id| {
                return .{ .copy_of = id };
            }
        }

        // Annotated method/function call: `<recv>.<method>(args)` or
        // bare `<fn>(args)`.  Look up the callee in the annotation DB
        // and use its @returns to classify the result.
        const is_call = switch (tag) {
            .call, .call_one, .call_comma, .call_one_comma => true,
            else => false,
        };
        if (is_call) {
            return self.classifyCall(expr_node);
        }

        return .unknown;
    }

    fn classifyCall(self: *Builder, call_node: Ast.Node.Index) ExprKind {
        const tree = self.tree;
        const db = self.db orelse return .unknown;

        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return .unknown;
        const callee_node = call_full.ast.fn_expr;
        const args = call_full.ast.params;

        // Two callee shapes we handle:
        //   1. <recv>.<method>(...)   → field_access (receiver is arg 0)
        //   2. <ident>(...)           → identifier
        switch (tree.nodeTag(callee_node)) {
            .field_access => {
                const fa_data = tree.nodeData(callee_node);
                const recv_node = fa_data.node_and_token[0];
                const method_tok = fa_data.node_and_token[1];
                const method_name = tree.tokenSlice(method_tok);
                const entry = db.lookup(method_name) orelse return .unknown;
                return self.applyAnnotationToCall(entry.annotation, recv_node, args, true);
            },
            .identifier => {
                const fn_name = tree.tokenSlice(tree.nodeMainToken(callee_node));
                const entry = db.lookup(fn_name) orelse return .unknown;
                return self.applyAnnotationToCall(entry.annotation, callee_node, args, false);
            },
            else => return .unknown,
        }
    }

    /// Convert a callee annotation + actual-arg context into an ExprKind.
    /// `receiver_is_arg0`: when true (method-call case), the receiver
    /// counts as args[0] and `args` is the explicit list shifted by one.
    fn applyAnnotationToCall(
        self: *Builder,
        anno: annotations.ReturnsAnnotation,
        receiver_or_callee: Ast.Node.Index,
        args: []const Ast.Node.Index,
        receiver_is_arg0: bool,
    ) ExprKind {
        switch (anno) {
            .owned => return .owned,
            .borrowed_from => |target_idx| {
                if (receiver_is_arg0 and target_idx == 0) {
                    return self.identifierToCopyOrUnknown(receiver_or_callee);
                }
                const explicit_idx = if (receiver_is_arg0) target_idx - 1 else target_idx;
                if (explicit_idx >= args.len) return .unknown;
                return self.identifierToCopyOrUnknown(args[explicit_idx]);
            },
        }
    }

    /// If `node` is a bare identifier matching a known local, return
    /// .copy_of(that local) — otherwise .unknown.
    fn identifierToCopyOrUnknown(self: *Builder, node: Ast.Node.Index) ExprKind {
        const tree = self.tree;
        if (tree.nodeTag(node) != .identifier) return .unknown;
        const name = tree.tokenSlice(tree.nodeMainToken(node));
        if (self.name_to_local.get(name)) |id| return .{ .copy_of = id };
        return .unknown;
    }

    fn firstIdentifierLocal(self: *Builder, text: []const u8) ?LocalId {
        var i: usize = 0;
        // Skip leading whitespace
        while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
        const start = i;
        while (i < text.len) : (i += 1) {
            const c = text[i];
            if (!isIdentChar(c)) break;
        }
        if (i == start) return null;
        const name = text[start..i];
        return self.name_to_local.get(name);
    }

    fn isIdentChar(c: u8) bool {
        return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_';
    }

    fn posOf(self: *Builder, node: Ast.Node.Index) SrcPos {
        return self.posOfToken(self.tree.firstToken(node));
    }

    fn posOfToken(self: *Builder, tok: Ast.TokenIndex) SrcPos {
        const tree = self.tree;
        const start = tree.tokens.items(.start)[tok];
        const loc = tree.tokenLocation(0, tok);
        return .{
            .byte = start,
            .line = @intCast(loc.line + 1),
            .column = @intCast(loc.column + 1),
        };
    }

    fn finalize(
        self: *Builder,
        tree: *const Ast,
        fn_decl: Ast.Node.Index,
        entry: BlockId,
    ) !Cfg {
        const blocks = try self.gpa.alloc(BasicBlock, self.blocks.items.len);
        for (self.blocks.items, 0..) |bb, i| {
            blocks[i] = .{
                .id = bb.id,
                .stmts = try self.block_stmts.items[i].toOwnedSlice(self.gpa),
                .successors = try self.block_successors.items[i].toOwnedSlice(self.gpa),
            };
        }
        const locals = try self.locals.toOwnedSlice(self.gpa);
        const start = tree.tokens.items(.start)[tree.firstToken(fn_decl)];
        const end_tok = tree.lastToken(fn_decl);
        const end = tree.tokens.items(.start)[end_tok] + tree.tokenSlice(end_tok).len;
        return .{
            .blocks = blocks,
            .entry = entry,
            .fn_span = .{ .start = start, .end = @intCast(end) },
            .locals = locals,
        };
    }
};

/// True iff the return-type node text starts with `*` or `[` after
/// stripping leading `?` / `E!`.  Same heuristic the Layer-1 rule uses
/// (require_borrowed_from.zig) — Node.Data variant churn between Zig
/// versions makes source-text inspection more robust than the typed
/// API.
fn returnTypeIsBorrowed(tree: *const Ast, node: Ast.Node.Index) bool {
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    const start = tree.tokens.items(.start)[first];
    const last_start = tree.tokens.items(.start)[last];
    const last_len = tree.tokenSlice(last).len;
    const end: usize = last_start + last_len;
    var text = tree.source[start..end];
    while (text.len > 0) {
        switch (text[0]) {
            '?', '!', ' ', '\t' => text = text[1..],
            else => break,
        }
    }
    if (std.mem.indexOfScalar(u8, text, '!')) |bang| {
        text = std.mem.trimStart(u8, text[bang + 1 ..], " \t");
    }
    return text.len > 0 and (text[0] == '*' or text[0] == '[');
}

/// Returns the statements of a block node.  Zig's AST has 4 block variants
/// depending on statement count + trailing semicolon.
fn blockStmts(
    tree: *const Ast,
    block_node: Ast.Node.Index,
    buf: *[2]Ast.Node.Index,
) []const Ast.Node.Index {
    return switch (tree.nodeTag(block_node)) {
        .block, .block_semicolon => tree.extraDataSlice(tree.nodeData(block_node).extra_range, Ast.Node.Index),
        .block_two, .block_two_semicolon => blk: {
            const data = tree.nodeData(block_node);
            buf[0] = data.opt_node_and_opt_node[0].unwrap() orelse break :blk &.{};
            if (data.opt_node_and_opt_node[1].unwrap()) |second| {
                buf[1] = second;
                break :blk buf[0..2];
            }
            break :blk buf[0..1];
        },
        else => &.{},
    };
}

// ── Tests ──────────────────────────────────────────────────

fn parseAndLower(gpa: std.mem.Allocator, src: []const u8) !struct {
    tree: Ast,
    cfg: ?Cfg,
} {
    const src_z = try gpa.dupeZ(u8, src);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    errdefer tree.deinit(gpa);

    // Find first fn_decl in the file.
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) == .fn_decl) {
            const cfg = try lowerFunction(gpa, &tree, node, null);
            return .{ .tree = tree, .cfg = cfg };
        }
    }
    return .{ .tree = tree, .cfg = null };
}

test "lower trivial fn — entry block + return" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    return;
        \\}
        \\
    );
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks[0].stmts.len);
    try std.testing.expect(cfg.blocks[0].stmts[0].kind == .ret);
}

test "lower fn with var decl + arena init + deinit" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\const std = @import("std");
        \\pub fn foo() void {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    arena.deinit();
        \\    return;
        \\}
        \\
    );
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

    // One block, three statements: decl, arena_kill, ret.
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.len);
    const stmts = cfg.blocks[0].stmts;
    try std.testing.expectEqual(@as(usize, 3), stmts.len);

    try std.testing.expect(stmts[0].kind == .decl);
    try std.testing.expect(stmts[0].kind.decl.init_kind == .arena_init);

    try std.testing.expect(stmts[1].kind == .arena_kill);
    // Receiver local should be the same as the declared local.
    try std.testing.expectEqual(stmts[0].kind.decl.local, stmts[1].kind.arena_kill.arena_local);

    try std.testing.expect(stmts[2].kind == .ret);
}

test "lower fn with return of borrowed identifier" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() u32 {
        \\    var x = bar();
        \\    return x;
        \\}
        \\fn bar() u32 { return 0; }
        \\
    );
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

    const stmts = cfg.blocks[0].stmts;
    try std.testing.expectEqual(@as(usize, 2), stmts.len);
    try std.testing.expect(stmts[0].kind == .decl);
    try std.testing.expect(stmts[1].kind == .ret);
    // Return value should be classified as .copy_of(x).
    try std.testing.expect(stmts[1].kind.ret.value_kind == .copy_of);
    try std.testing.expectEqual(stmts[0].kind.decl.local, stmts[1].kind.ret.value_kind.copy_of);
}

test "lower fn with thread join" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var t = undefined;
        \\    t.join();
        \\    return;
        \\}
        \\
    );
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

    const stmts = cfg.blocks[0].stmts;
    try std.testing.expectEqual(@as(usize, 3), stmts.len);
    try std.testing.expect(stmts[0].kind == .decl);
    try std.testing.expect(stmts[1].kind == .thread_join);
    try std.testing.expect(stmts[2].kind == .ret);
}

test "lowering_gap for unsupported statement (if/while)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    if (x) return;
        \\    return;
        \\}
        \\
    );
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

    // v1 doesn't model if/else — emits a lowering_gap for the if_stmt.
    const stmts = cfg.blocks[0].stmts;
    try std.testing.expectEqual(@as(usize, 2), stmts.len);
    try std.testing.expect(stmts[0].kind == .lowering_gap);
    try std.testing.expect(stmts[1].kind == .ret);
}
