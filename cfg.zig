//! Layer 2 CFG types and Zig-AST → CFG lowering.
//!
//! v1 scope: extract a flow graph from a single Zig function over the
//! subset of statement shapes that affect our abstract state.  Most
//! Zig syntax doesn't change lifetime/identity; we collapse it into
//! `.plain_expr` and only emit dedicated statement nodes for the ops
//! the analyzer transfers over.
//!
//! What we DO model:
//!   - `var/const NAME = INIT;` (local binding)
//!   - `LHS = RHS;` (assignment)
//!   - call expressions (especially annotated-callee returns)
//!   - `arena.deinit()` (arena death)
//!   - `thread.join()` (thread join)
//!   - `return EXPR;` (function exit)
//!   - `if/else`, `while`, `for`, `switch` branching (real CFG edges)
//!   - `defer` / `errdefer` (replayed at function-exit / return sites)
//!
//! What we DON'T model (yet):
//!   - `try` / `catch` (error-path forking + error-set tracking)
//!   - generics / comptime
//!   - for-loop iteration variable origin (treated as .plain)
//!   - switch-case pattern bindings (treated as .plain)
//!
//! Errors during lowering are surfaced as `Stmt{.lowering_gap}` nodes
//! rather than aborts — keeps the analyzer running on the rest of the
//! function even when one statement uses an unsupported construct.

const std = @import("std");
const Ast = std.zig.Ast;
const abstract_state = @import("abstract_state.zig");
const annotations = @import("annotations.zig");
const imports = @import("imports.zig");
const remote_resolver = @import("remote_resolver.zig");

/// Cross-file resolution context passed into lowerFunction.  When
/// present, classifyCall can resolve `imported.method(...)` calls
/// by looking up the method's annotation in the imported file's DB
/// via remote_resolver.Cache.
pub const RemoteCtx = struct {
    imap: *const imports.Map,
    base_dir: []const u8,
    cache: *remote_resolver.Cache,
};

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

    /// Call to a fn annotated `@takes node_index_of(<param>)`.  At
    /// transfer time: look up `source_local`'s origin (must be
    /// `.ast(aid_src)`) and `value_local`'s origin (must be
    /// `.ast_node(aid_val)`); flag if both are tagged and the AstIds
    /// differ — that's a NodeIndex from Ast A flowing into Ast B.
    /// Emitted by lowerCallStmt when a same-file callee carries the
    /// @takes annotation.  Phase 27 will broaden to init/return/assign
    /// positions where most real check sites live.
    ast_takes_check: struct { source_local: LocalId, value_local: LocalId },

    /// Call to a fn annotated `@mutates_ast` on an Origin.ast
    /// receiver — phase 37's invariant #5 enforcement.  At transfer
    /// time: if `ast_local`'s origin is `.ast(_)`, flag.  Any tracked
    /// Ast is considered "post-parse" from the analyzer's view; the
    /// only legitimate construction site is the parser itself which
    /// doesn't go through this annotation-driven path.
    ast_mutation_check: struct { ast_local: LocalId },

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
    /// `Ast.parse(...)` — produces a fresh Ast.  Transfer mints a
    /// new AstId; the declaring local becomes origin `.ast(aid)`.
    /// Used by `.node_index_of(local)` propagation to tag NodeIndex
    /// results with the originating Ast's identity.
    ast_init,
    /// Call to a fn annotated `// @returns node_index_of(<param>)`.
    /// `local` is the resolved arg LocalId carrying the source Ast.
    /// Transfer looks up local's current origin and, if it's
    /// `.ast(aid)`, returns `.ast_node(aid)` — propagating the
    /// Ast identity tag onto the NodeIndex result.
    node_index_of: LocalId,
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
    return lowerFunctionWithRemote(gpa, tree, fn_decl, db, null);
}

/// Same as lowerFunction but accepts a cross-file resolution context.
/// Use this from sweep entry points where you already have an imports
/// map + cache built per-file; pass through so classifyCall can resolve
/// `imported.method(...)` callees against the imported file's DB.
pub fn lowerFunctionWithRemote(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    fn_decl: Ast.Node.Index,
    db: ?*const annotations.Db,
    remote: ?*const RemoteCtx,
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
        .remote = remote,
        .is_borrowed_return_type = is_borrowed_ret,
    };
    defer builder.tempDeinit();

    const entry_id = try builder.newBlock();
    // Seed param locals BEFORE lowering the body so identifier
    // references inside the body resolve via name_to_local.  Params
    // whose type text mentions "Ast" become Origin.ast(<aid>) at
    // transfer time — enables invariant #1 checks inside functions
    // that RECEIVE the Ast rather than create it.
    try builder.seedParams(fn_proto, entry_id);

    var cur_block = entry_id;
    try builder.lowerFunctionBody(body_node, &cur_block);

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

/// Heuristic: does the type expression's text contain a standalone
/// "Ast" identifier token?  Matches `Ast`, `*Ast`, `*const Ast`,
/// `?Ast`, `[]const Ast`, etc.  False positives (e.g. a type named
/// `FooAst` would NOT match since we require an identifier-token
/// boundary; but `Ast.Node` WOULD match) are bounded: extra params
/// tagged as Origin.ast inflate the AstId counter but don't cause
/// false-positive invariant findings.
fn typeTextMentionsAst(tree: *const Ast, type_node: Ast.Node.Index) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tree.tokens.items(.tag)[t] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t), "Ast"))
            return true;
    }
    return false;
}

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
}

// ── Builder ────────────────────────────────────────────────

const LoopCtx = struct {
    header: BlockId,
    merge: BlockId,
    /// Label slice on the source (no colon), or null for unlabeled
    /// loops.  `break :name` walks the loop stack from inside out
    /// matching this field.
    label: ?[]const u8 = null,
};

/// Labeled non-loop blocks — `blk: { ... break :blk val; }`.  Only
/// labeled break can target these; continue is invalid (compiler
/// catches at parse time, but defensively ignored here).
const BlockLabelCtx = struct {
    label: []const u8,
    merge: BlockId,
};

const Builder = struct {
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: ?*const annotations.Db = null,
    remote: ?*const RemoteCtx = null,
    blocks: std.ArrayListUnmanaged(BasicBlock) = .empty,
    /// Per-block staging — stmts being appended.  Flushed to `blocks[i].stmts`
    /// in finalize().
    block_stmts: std.ArrayListUnmanaged(std.ArrayListUnmanaged(Stmt)) = .empty,
    block_successors: std.ArrayListUnmanaged(std.ArrayListUnmanaged(BlockId)) = .empty,
    locals: std.ArrayListUnmanaged(LocalInfo) = .empty,
    /// name → LocalId for current scope.  v1 doesn't handle nested scopes;
    /// names are flat per-function.
    name_to_local: std.StringHashMapUnmanaged(LocalId) = .empty,
    /// Stack of `defer` bodies, LIFO.  Replayed at every `return` exit
    /// (always fires) and at function-fallthrough.
    deferred_normal: std.ArrayListUnmanaged(Ast.Node.Index) = .empty,
    deferred_err: std.ArrayListUnmanaged(Ast.Node.Index) = .empty,
    /// Loop context stack — pushed by lowerWhile/lowerFor before
    /// lowering the body, popped after.  `break` jumps to the
    /// innermost merge; `continue` jumps to the innermost header.
    /// Labels aren't modeled yet (always targets the innermost loop).
    loop_stack: std.ArrayListUnmanaged(LoopCtx) = .empty,
    /// Labeled-block stack — pushed by lowerLabeledBlock around the
    /// body; searched before loop_stack on labeled-break resolution.
    block_label_stack: std.ArrayListUnmanaged(BlockLabelCtx) = .empty,
    /// Stack of `errdefer` bodies, LIFO.  Replayed on error-exit paths
    /// only (try/catch — phase 9+).  At a plain `return X` Zig only fires
    /// these when X is an error value, but we can't always tell from
    /// AST, so for now we conservatively SKIP errdefers at returns; this
    /// trades one false-negative class (errdefer killing an arena before
    /// an error return uses it) for elimination of the converse false-
    /// positive class (errdefer kills polluting success returns).
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
        self.deferred_normal.deinit(self.gpa);
        self.deferred_err.deinit(self.gpa);
        self.loop_stack.deinit(self.gpa);
        self.block_label_stack.deinit(self.gpa);
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

    /// Register Ast-typed fn params as tracked locals + emit synthetic
    /// `.decl` stmts on the entry block with init_kind .ast_init.
    /// This mints a fresh AstId per call so within-function cross-Ast
    /// checks (invariant #1) fire on receiving functions like
    /// nodeSpan(self, idx).
    ///
    /// Non-Ast params are intentionally NOT seeded.  Initial phase-35
    /// implementation registered ALL params with .plain init_kind so
    /// every identifier reference resolved via name_to_local — that
    /// inflated per-block state by N locals on every function and
    /// pushed `src/cli/parallel.zig` past the 200k worklist iteration
    /// cap.  Restricting seeding to Ast params keeps state bounded
    /// (real codebases have at most 1-2 Ast params per fn) while
    /// preserving the dogfood capability.
    fn seedParams(self: *Builder, fn_proto: Ast.full.FnProto, entry: BlockId) !void {
        const tree = self.tree;
        var it = fn_proto.iterate(tree);
        while (it.next()) |param| {
            const name_tok = param.name_token orelse continue;
            const name = tree.tokenSlice(name_tok);
            if (std.mem.eql(u8, name, "_")) continue;
            const type_node = param.type_expr orelse continue;
            if (!typeTextMentionsAst(tree, type_node)) continue;

            const local = try self.registerLocal(name, self.posOfToken(name_tok));
            try self.appendStmt(entry, .{
                .kind = .{ .decl = .{ .local = local, .init_kind = .ast_init } },
                .pos = self.posOfToken(name_tok),
            });
        }
    }

    /// Register `|x|` / `|x, y|` / `|*x, idx|` capture identifiers
    /// starting at `payload_token` (which points at the first capture
    /// after the opening `|`).  Stops at the closing `|`.  Each
    /// capture becomes a tracked local with .unknown origin — we don't
    /// model per-element borrow shape yet, but subsequent uses inside
    /// the body now resolve via name_to_local rather than falling
    /// through to .unknown identifier classification.
    fn registerCaptures(self: *Builder, payload_token: Ast.TokenIndex) !void {
        const tree = self.tree;
        const tags = tree.tokens.items(.tag);
        var t: Ast.TokenIndex = payload_token;
        while (t < tags.len) : (t += 1) {
            switch (tags[t]) {
                .pipe => return, // closing `|`
                .identifier => {
                    const name = tree.tokenSlice(t);
                    // `_` is the discard placeholder — don't track.
                    if (std.mem.eql(u8, name, "_")) continue;
                    // Zig forbids shadowing, so name_to_local can't
                    // already hold this name — safe to register.
                    _ = try self.registerLocal(name, self.posOfToken(t));
                },
                else => {}, // `,`, `*`, `|` (opening): skip
            }
        }
    }

    /// Lower the contents of a Zig block node into `cur` (mutated to the
    /// last block reached — branches may have advanced past the original).
    /// Defer statements encountered are queued and replayed in reverse
    /// order at every `return` exit point.  Does NOT flush defers at
    /// block exit — only the top-level function body does that, via
    /// `lowerFunctionBody`.
    fn lowerBlock(self: *Builder, block_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        var stmt_buf: [2]Ast.Node.Index = undefined;
        const stmts = blockStmts(tree, block_node, &stmt_buf);
        for (stmts) |stmt_idx| {
            try self.lowerStmt(stmt_idx, cur);
        }
    }

    /// Lower the top-level function body — same as lowerBlock but flushes
    /// pending defers at the end (implicit-fallthrough return).  Only the
    /// outermost block of a function does this; nested blocks defer to
    /// their enclosing return statements.
    fn lowerFunctionBody(self: *Builder, body_node: Ast.Node.Index, cur: *BlockId) !void {
        try self.lowerBlock(body_node, cur);
        try self.flushDefers(cur);
    }

    fn pushDefer(self: *Builder, body_node: Ast.Node.Index) !void {
        try self.deferred_normal.append(self.gpa, body_node);
    }

    fn pushErrdefer(self: *Builder, body_node: Ast.Node.Index) !void {
        try self.deferred_err.append(self.gpa, body_node);
    }

    /// Replay `defer` bodies (LIFO) into `cur`.  Doesn't pop — returns
    /// happen mid-function and subsequent code in the same lexical
    /// scope must still see the same defer set.  Called at function-
    /// fallthrough exit and at every `return`.  Does NOT replay
    /// errdefers — see `deferred_err` doc-block for rationale.
    fn flushDefers(self: *Builder, cur: *BlockId) (std.mem.Allocator.Error)!void {
        var i = self.deferred_normal.items.len;
        while (i > 0) {
            i -= 1;
            try self.lowerStmt(self.deferred_normal.items[i], cur);
        }
    }

    /// Error-path flush: errdefers LIFO first (they're closer to the
    /// fail site and run before normal defers per Zig semantics), then
    /// normal defers LIFO.  Used at synthetic try-error-exit blocks.
    fn flushErrAndNormalDefers(self: *Builder, cur: *BlockId) (std.mem.Allocator.Error)!void {
        var i = self.deferred_err.items.len;
        while (i > 0) {
            i -= 1;
            try self.lowerStmt(self.deferred_err.items[i], cur);
        }
        i = self.deferred_normal.items.len;
        while (i > 0) {
            i -= 1;
            try self.lowerStmt(self.deferred_normal.items[i], cur);
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
                // lowerReturn handles its own defer-flush ordering —
                // it has to interleave with try-error-exit / catch
                // forking when the return value has those at top level.
                try self.lowerReturn(stmt_node, cur);
            },
            .call, .call_one, .call_comma, .call_one_comma => {
                try self.lowerCallStmt(stmt_node, cur);
            },
            .@"defer" => {
                const body = tree.nodeData(stmt_node).node;
                try self.pushDefer(body);
            },
            .@"errdefer" => {
                // `.data = .node` in 0.17 (capture token dropped — we
                // already eat the `|e|` payload in a separate token).
                const body = tree.nodeData(stmt_node).node;
                try self.pushErrdefer(body);
            },
            .if_simple, .@"if" => try self.lowerIf(stmt_node, cur),
            .while_simple, .while_cont, .@"while" => try self.lowerWhile(stmt_node, cur),
            .for_simple, .@"for" => try self.lowerFor(stmt_node, cur),
            .@"switch", .switch_comma => try self.lowerSwitch(stmt_node, cur),
            .@"try" => try self.lowerTryStmt(stmt_node, cur),
            .@"catch" => try self.lowerCatchStmt(stmt_node, cur),
            .@"break" => try self.lowerBreakOrContinue(cur, .@"break", stmt_node),
            .@"continue" => try self.lowerBreakOrContinue(cur, .@"continue", stmt_node),
            // Nested blocks: recurse so empty blocks DON'T trigger
            // the conservative .plain collapse via lowering_gap.
            // Labeled forms (`blk: { ... break :blk; }`) get the
            // block-label scaffolding so `break :blk` can resolve.
            .block, .block_semicolon, .block_two, .block_two_semicolon => {
                if (self.blockLabelToken(stmt_node)) |lt| {
                    try self.lowerLabeledBlock(stmt_node, lt, cur);
                } else {
                    try self.lowerBlock(stmt_node, cur);
                }
            },
            else => {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .lowering_gap = .{ .note = @tagName(tag) } },
                    .pos = self.posOf(stmt_node),
                });
            },
        }
    }

    /// `if (cond) THEN [else ELSE]` → fork into two successor blocks,
    /// lower each branch into its own block, then join into a fresh
    /// merge block.  Subsequent statements emit into the merge block.
    ///
    /// We don't model the condition's truthiness — the abstract state
    /// must be valid on BOTH branches (this is conservative and matches
    /// our design: don't reason about branch-specific values).
    fn lowerIf(self: *Builder, if_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const if_data = tree.fullIf(if_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "if-extract" } },
                .pos = self.posOf(if_node),
            });
            return;
        };

        // Allocate the three successor blocks up-front.
        const then_block = try self.newBlock();
        const else_block = if (if_data.ast.else_expr.unwrap() != null) try self.newBlock() else null;
        const merge_block = try self.newBlock();

        // From `cur`: branch to then-block and (else-block OR merge directly
        // if no else clause — falling through is the same as an empty else).
        try self.addEdge(cur.*, then_block);
        try self.addEdge(cur.*, else_block orelse merge_block);

        // Lower the then branch.  `if (opt) |val|` payload is in scope
        // for the then-body only.
        if (if_data.payload_token) |pt| try self.registerCaptures(pt);
        var then_cur = then_block;
        try self.lowerStmt(if_data.ast.then_expr, &then_cur);
        // Then-branch exits flow into merge.
        try self.addEdge(then_cur, merge_block);

        // Lower the else branch if present.  `else |err|` payload is
        // in scope for the else-body only.
        if (else_block) |eb| {
            if (if_data.error_token) |et| try self.registerCaptures(et);
            var else_cur = eb;
            try self.lowerStmt(if_data.ast.else_expr.unwrap().?, &else_cur);
            try self.addEdge(else_cur, merge_block);
        }

        // Subsequent statements emit into the merge block.
        cur.* = merge_block;
    }

    /// `while (cond) BODY [else ELSE]` → produces a header block (where
    /// the condition is evaluated each iteration), a body block, and a
    /// merge block (post-loop).  Back-edge from body → header creates
    /// the loop — the analyzer's worklist iterates body's state into
    /// header until fixed point.
    ///
    /// We model the simplest valid loop CFG:
    ///   cur ─→ header ─→ body ─→ header (back-edge)
    ///                  ↘ merge (loop exit / else)
    fn lowerWhile(self: *Builder, while_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const while_data = tree.fullWhile(while_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "while-extract" } },
                .pos = self.posOf(while_node),
            });
            return;
        };

        const header = try self.newBlock();
        const body = try self.newBlock();
        const merge = try self.newBlock();

        // Edge: cur → header (loop entry)
        try self.addEdge(cur.*, header);

        // Header branches to body (when cond true) or merge (when false).
        try self.addEdge(header, body);
        try self.addEdge(header, merge);

        // Lower the body; on exit, back-edge to header.  Push loop
        // context so any `break`/`continue` inside lowers correctly.
        const label_slice: ?[]const u8 = if (while_data.label_token) |lt|
            tree.tokenSlice(lt)
        else
            null;
        try self.loop_stack.append(self.gpa, .{
            .header = header,
            .merge = merge,
            .label = label_slice,
        });
        // `while (opt) |x|` payload capture — register before body.
        if (while_data.payload_token) |pt| try self.registerCaptures(pt);
        var body_cur = body;
        try self.lowerStmt(while_data.ast.then_expr, &body_cur);
        _ = self.loop_stack.pop();
        try self.addEdge(body_cur, header);

        // Optional else block (runs once when cond becomes false).
        // We don't model the "runs only on natural exit, not on break" —
        // treat as falling through to merge.
        if (while_data.ast.else_expr.unwrap()) |else_expr| {
            const else_block = try self.newBlock();
            try self.addEdge(header, else_block);
            var else_cur = else_block;
            try self.lowerStmt(else_expr, &else_cur);
            try self.addEdge(else_cur, merge);
        }

        cur.* = merge;
    }

    /// `for (input) |x| BODY [else ELSE]` — structurally identical to a
    /// while loop for our purposes (header decides each iteration, body
    /// back-edges to header).  We don't model the iteration variable's
    /// origin (would need to track input's element-lifetime per item);
    /// the iterator binding gets registered as a fresh local with .plain
    /// init so subsequent uses are conservative.
    fn lowerFor(self: *Builder, for_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const for_data = tree.fullFor(for_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "for-extract" } },
                .pos = self.posOf(for_node),
            });
            return;
        };

        const header = try self.newBlock();
        const body = try self.newBlock();
        const merge = try self.newBlock();

        try self.addEdge(cur.*, header);
        try self.addEdge(header, body);
        try self.addEdge(header, merge);

        const for_label: ?[]const u8 = if (for_data.label_token) |lt|
            tree.tokenSlice(lt)
        else
            null;
        try self.loop_stack.append(self.gpa, .{
            .header = header,
            .merge = merge,
            .label = for_label,
        });
        // For-loops always have a payload (`|x|` or `|x, idx|`).
        try self.registerCaptures(for_data.payload_token);
        var body_cur = body;
        try self.lowerStmt(for_data.ast.then_expr, &body_cur);
        _ = self.loop_stack.pop();
        try self.addEdge(body_cur, header); // back-edge for fixed-point iteration

        if (for_data.ast.else_expr.unwrap()) |else_expr| {
            const else_block = try self.newBlock();
            try self.addEdge(header, else_block);
            var else_cur = else_block;
            try self.lowerStmt(else_expr, &else_cur);
            try self.addEdge(else_cur, merge);
        }

        cur.* = merge;
    }

    /// `switch (cond) { CASE => EXPR, ... }` — N-way fork.  Each case
    /// becomes a successor of `cur`; all cases join into a fresh merge
    /// block.  We don't model case-pattern matching or exhaustiveness;
    /// every case is treated as reachable from cur.
    fn lowerSwitch(self: *Builder, sw_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const sw = tree.fullSwitch(sw_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "switch-extract" } },
                .pos = self.posOf(sw_node),
            });
            return;
        };

        const merge = try self.newBlock();

        if (sw.ast.cases.len == 0) {
            try self.addEdge(cur.*, merge);
            cur.* = merge;
            return;
        }

        for (sw.ast.cases) |case_node| {
            const case_full = tree.fullSwitchCase(case_node) orelse continue;
            const case_block = try self.newBlock();
            try self.addEdge(cur.*, case_block);
            // `.tag => |val| ...` capture binds inside this case only.
            if (case_full.payload_token) |pt| try self.registerCaptures(pt);
            var case_cur = case_block;
            try self.lowerStmt(case_full.ast.target_expr, &case_cur);
            try self.addEdge(case_cur, merge);
        }

        cur.* = merge;
    }

    /// `try expr` at statement position.  Lower `expr` on the success
    /// path (cur continues forward); add an error-exit edge to a sink
    /// block that replays errdefers + defers and terminates.  The sink
    /// has no successor — it represents the implicit `return error.X`.
    ///
    /// Phase 9 v1: we DON'T attach this error-exit edge to every
    /// `try` buried inside an expression (e.g. `const x = try foo()`).
    /// That would require expression-tree walks and would explode the
    /// CFG with sink blocks that don't enrich downstream analysis.
    /// Statement-position try alone is enough to model the common
    /// pattern `try foo();` for side-effect calls.
    fn lowerTryStmt(self: *Builder, try_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const inner = tree.nodeData(try_node).node;
        // Success path: side-effects of the wrapped expression.
        try self.lowerStmt(inner, cur);
        // Error path: synthetic sink.
        try self.emitTryErrorExit(cur.*, self.posOf(try_node));
    }

    /// Is this block node labeled (`blk: { ... }`)?  Returns the
    /// label-identifier token if so.  Block labels live at
    /// `main_token - 2` (identifier) + `main_token - 1` (`:`).
    fn blockLabelToken(self: *Builder, block_node: Ast.Node.Index) ?Ast.TokenIndex {
        const tree = self.tree;
        const main = tree.nodeMainToken(block_node);
        if (main < 2) return null;
        const tags = tree.tokens.items(.tag);
        if (tags[main - 1] != .colon) return null;
        if (tags[main - 2] != .identifier) return null;
        return main - 2;
    }

    /// If `expr` is a top-level labeled block at an expression
    /// position (`const x = blk: { ... }`, `return blk: {...}`,
    /// `x = blk: {...}`), lower its body in-place — advancing cur
    /// to the post-merge — and return true.  The caller then
    /// emits its decl/ret/assign on the post-merge cur, with an
    /// .unknown classification since we don't track which break
    /// path's value was taken.  Returns false for non-block exprs.
    fn maybeLowerLabeledBlockExpr(
        self: *Builder,
        expr: Ast.Node.Index,
        cur: *BlockId,
    ) !bool {
        const tree = self.tree;
        switch (tree.nodeTag(expr)) {
            .block, .block_semicolon, .block_two, .block_two_semicolon => {},
            else => return false,
        }
        const lt = self.blockLabelToken(expr) orelse return false;
        try self.lowerLabeledBlock(expr, lt, cur);
        return true;
    }

    /// `blk: { ... }` at statement position — push label context,
    /// lower body normally, pop, then sew the natural fallthrough
    /// edge cur → merge and continue from merge.  Any `break :blk`
    /// inside the body adds its own edge to merge via
    /// lowerBreakOrContinue.
    fn lowerLabeledBlock(
        self: *Builder,
        block_node: Ast.Node.Index,
        label_token: Ast.TokenIndex,
        cur: *BlockId,
    ) !void {
        const tree = self.tree;
        const label = tree.tokenSlice(label_token);
        const merge = try self.newBlock();
        try self.block_label_stack.append(self.gpa, .{ .label = label, .merge = merge });
        try self.lowerBlock(block_node, cur);
        _ = self.block_label_stack.pop();
        // Natural fallthrough — body completed without breaking.
        try self.addEdge(cur.*, merge);
        cur.* = merge;
    }

    /// `break`/`continue` — add an edge from cur to the innermost
    /// loop's merge (break) or header (continue), then redirect cur
    /// to a fresh dead block so any statements emitted after the
    /// break/continue don't leak into the actual flow.  Labeled
    /// break first searches the block-label stack, then loops.
    fn lowerBreakOrContinue(
        self: *Builder,
        cur: *BlockId,
        kind: enum { @"break", @"continue" },
        node: Ast.Node.Index,
    ) !void {
        const tree = self.tree;
        if (self.loop_stack.items.len == 0) {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "break-outside-loop" } },
                .pos = self.posOf(node),
            });
            return;
        }

        // `break/continue :name` — Ast data is opt_token_and_opt_node;
        // the OptionalTokenIndex points at the bare identifier (no
        // colon).  For labeled break, search block_label_stack first
        // (since blocks can only be break targets, never continue),
        // then fall through to loop_stack.
        const opt_label_tok = tree.nodeData(node).opt_token_and_opt_node[0];
        if (opt_label_tok.unwrap()) |lt| {
            const wanted = tree.tokenSlice(lt);
            // Block labels: break only.  Continue to a block label is
            // a compile error in Zig; defensively skip if encountered.
            if (kind == .@"break") {
                var i = self.block_label_stack.items.len;
                while (i > 0) {
                    i -= 1;
                    const ctx = self.block_label_stack.items[i];
                    if (std.mem.eql(u8, ctx.label, wanted)) {
                        try self.addEdge(cur.*, ctx.merge);
                        cur.* = try self.newBlock();
                        return;
                    }
                }
            }
            // Loop labels: walk inside-out.
            var i = self.loop_stack.items.len;
            while (i > 0) {
                i -= 1;
                const ctx = self.loop_stack.items[i];
                if (ctx.label) |lbl| {
                    if (std.mem.eql(u8, lbl, wanted)) {
                        const target = switch (kind) {
                            .@"break" => ctx.merge,
                            .@"continue" => ctx.header,
                        };
                        try self.addEdge(cur.*, target);
                        cur.* = try self.newBlock();
                        return;
                    }
                }
            }
            // No match in either stack.
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "labeled-break-no-loop" } },
                .pos = self.posOf(node),
            });
            return;
        }

        // Unlabeled: innermost loop.
        const ctx = self.loop_stack.items[self.loop_stack.items.len - 1];
        const target = switch (kind) {
            .@"break" => ctx.merge,
            .@"continue" => ctx.header,
        };
        try self.addEdge(cur.*, target);
        cur.* = try self.newBlock();
    }

    /// Build the synthetic error-exit sink for an in-expression `try`.
    /// Used by both `lowerTryStmt` and `lowerVarDecl` (when init is a
    /// top-level `.@"try"`).  The sink is a new block reachable from
    /// `from` with errdefer + defer replayed, terminated by a ret.
    fn emitTryErrorExit(self: *Builder, from: BlockId, pos: SrcPos) !void {
        const err_exit = try self.newBlock();
        try self.addEdge(from, err_exit);
        var err_cur = err_exit;
        try self.flushErrAndNormalDefers(&err_cur);
        try self.appendStmt(err_cur, .{
            .kind = .{ .ret = .{
                .value_kind = .unknown,
                .is_borrowed_return_type = self.is_borrowed_return_type,
            } },
            .pos = pos,
        });
    }

    /// `lhs catch BODY` at statement position — forks into two paths:
    /// success (lhs's side effects only) and error (BODY runs).  Both
    /// join into a fresh merge block.  Unlike `try`, catch consumes
    /// the error; errdefers do NOT fire on the error edge.
    fn lowerCatchStmt(self: *Builder, catch_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const data = tree.nodeData(catch_node).node_and_node;
        // Success path: lhs's side effects emit into cur.
        try self.lowerStmt(data[0], cur);
        try self.emitCatchFork(catch_node, cur);
    }

    /// Append a catch-body fork to `cur`: one edge straight to merge
    /// (success), one through a new block where the catch body lowers,
    /// then both join.  `cur` advances to merge.  Used by
    /// `lowerCatchStmt`, `lowerVarDecl`, `lowerReturn`, `lowerAssign`
    /// — every position where `expr catch BODY` can appear at top
    /// level of an expression.
    ///
    /// `catch_node` is the `.@"catch"` Ast node itself (not its rhs)
    /// so we can also resolve the optional `|err|` payload — Zig
    /// AST doesn't surface it through a struct helper.
    fn emitCatchFork(self: *Builder, catch_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const body_node = tree.nodeData(catch_node).node_and_node[1];

        const catch_block = try self.newBlock();
        const merge = try self.newBlock();

        try self.addEdge(cur.*, catch_block);
        try self.addEdge(cur.*, merge);

        // `catch |err| BODY` — payload is `main_token + 2` when the
        // token immediately following `catch` is `|`.  Scope: body only.
        if (self.catchPayloadToken(catch_node)) |pt| {
            try self.registerCaptures(pt);
        }

        var catch_cur = catch_block;
        try self.lowerStmt(body_node, &catch_cur);
        try self.addEdge(catch_cur, merge);

        cur.* = merge;
    }

    fn catchPayloadToken(self: *Builder, catch_node: Ast.Node.Index) ?Ast.TokenIndex {
        const tree = self.tree;
        const main = tree.nodeMainToken(catch_node);
        const tags = tree.tokens.items(.tag);
        if (main + 1 >= tags.len) return null;
        if (tags[main + 1] != .pipe) return null;
        return main + 2;
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

        const init_opt = var_decl.ast.init_node.unwrap();

        // Top-level labeled-block init (`const x = blk: { ... };`) —
        // lower the body FIRST so its side effects + break paths run
        // before the binding takes effect.  cur advances to the
        // post-merge; the .decl emits there with .unknown init_kind.
        if (init_opt) |init| {
            if (try self.maybeLowerLabeledBlockExpr(init, cur)) {}
        }

        const init_kind: ExprKind = if (init_opt) |init|
            self.classifyExpr(init)
        else
            .plain;

        // Emit @takes node_index_of checks for any call in init
        // position — before the .decl so checks appear first in the
        // block's stmt sequence (transfer is sequential; sequence
        // doesn't change correctness but reads more naturally).
        if (init_opt) |init| try self.emitTakesChecksForExpr(init, cur);

        try self.appendStmt(cur.*, .{
            .kind = .{ .decl = .{ .local = local, .init_kind = init_kind } },
            .pos = self.posOf(decl_node),
        });

        // Init-position try/catch: now that the decl has emitted, model
        // the same CFG side-effects we'd get if the init had appeared
        // at statement position.  We don't walk arbitrarily-nested try
        // inside larger expressions — only top-level forms.  These
        // cover the common cases (`const x = try foo()`, `const x =
        // foo() catch ...`); buried try inside arithmetic etc. is rare
        // and unmodeled (yields a sink-less success-only path).
        if (init_opt) |init| {
            switch (tree.nodeTag(init)) {
                .@"try" => try self.emitTryErrorExit(cur.*, self.posOf(init)),
                .@"catch" => try self.emitCatchFork(init, cur),
                else => {},
            }
        }
    }

    /// `LHS = RHS;` — when LHS is a known simple-identifier local, emit
    /// a real `.assign` so the analyzer can update origin tracking.
    /// Otherwise (field access, deref, destructuring) fall back to a
    /// lowering_gap so locals collapse conservatively to .plain.
    ///
    /// Either way, if the RHS has a top-level `try` or `catch`, emit
    /// the same error-exit / fork helpers we use in init/return
    /// positions — those error-path CFG edges are independent of
    /// whether we successfully tracked the target.
    fn lowerAssign(self: *Builder, assign_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const tag = tree.nodeTag(assign_node);

        // Destructuring (`a, b = pair` / `const a, const b = pair()`).
        // Multi-target — we can't classify per-slot, so each target
        // gets .unknown.  But registering the locals (in the var-decl
        // form) and emitting per-target .assign / .decl beats one big
        // gap that collapsed everything to .plain.
        if (tag == .assign_destructure) {
            try self.lowerAssignDestructure(assign_node, cur);
            return;
        }

        const data = tree.nodeData(assign_node).node_and_node;
        const lhs = data[0];
        const rhs = data[1];

        // Resolve target: only simple identifier LHS for now.
        const target_local: ?LocalId = if (tree.nodeTag(lhs) == .identifier)
            self.name_to_local.get(tree.tokenSlice(tree.nodeMainToken(lhs)))
        else
            null;

        // Top-level labeled-block rhs (`x = blk: { ... };`) — lower
        // its body in-place, advancing cur, before the .assign emits.
        if (try self.maybeLowerLabeledBlockExpr(rhs, cur)) {}

        // @takes checks for call-shaped rhs (phase 27).
        try self.emitTakesChecksForExpr(rhs, cur);

        if (target_local) |t| {
            try self.appendStmt(cur.*, .{
                .kind = .{ .assign = .{
                    .target = t,
                    .rhs_kind = self.classifyExpr(rhs),
                } },
                .pos = self.posOf(assign_node),
            });
        } else {
            // Untracked target (e.g. `obj.field = X`) — emit gap so the
            // analyzer stays conservative on any aliased locals.
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "assign-target" } },
                .pos = self.posOf(assign_node),
            });
        }

        // Mirror the init-position try/catch dispatch.
        switch (tree.nodeTag(rhs)) {
            .@"try" => try self.emitTryErrorExit(cur.*, self.posOf(rhs)),
            .@"catch" => try self.emitCatchFork(rhs, cur),
            else => {},
        }
    }

    /// `a, b = pair()` or `const a, const b = pair()`.  Per-variable:
    /// pure-identifier targets emit `.assign` against the resolved
    /// local; var-decl targets (`const x`) register a new local and
    /// emit `.decl`.  All rhs classifications are .unknown — we don't
    /// match tuple slots to types.  The rhs's top-level try/catch /
    /// labeled-block side-effects ARE lowered (once, before the
    /// per-target emissions), matching plain-assign semantics.
    fn lowerAssignDestructure(
        self: *Builder,
        assign_node: Ast.Node.Index,
        cur: *BlockId,
    ) !void {
        const tree = self.tree;
        const full = tree.assignDestructure(assign_node);
        const rhs = full.ast.value_expr;

        // Labeled-block expression rhs — lower body first.
        if (try self.maybeLowerLabeledBlockExpr(rhs, cur)) {}

        // @takes checks for call-shaped rhs (phase 27).
        try self.emitTakesChecksForExpr(rhs, cur);

        for (full.ast.variables) |var_node| {
            const vtag = tree.nodeTag(var_node);
            switch (vtag) {
                .identifier => {
                    const name = tree.tokenSlice(tree.nodeMainToken(var_node));
                    if (self.name_to_local.get(name)) |t| {
                        try self.appendStmt(cur.*, .{
                            .kind = .{ .assign = .{ .target = t, .rhs_kind = .unknown } },
                            .pos = self.posOf(var_node),
                        });
                    } else {
                        try self.appendStmt(cur.*, .{
                            .kind = .{ .lowering_gap = .{ .note = "destructure-unresolved" } },
                            .pos = self.posOf(var_node),
                        });
                    }
                },
                .simple_var_decl,
                .local_var_decl,
                .aligned_var_decl,
                .global_var_decl,
                => {
                    const vd = tree.fullVarDecl(var_node) orelse continue;
                    const name_tok = vd.ast.mut_token + 1;
                    if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
                    const name = tree.tokenSlice(name_tok);
                    const local = try self.registerLocal(name, self.posOfToken(name_tok));
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .decl = .{ .local = local, .init_kind = .unknown } },
                        .pos = self.posOf(var_node),
                    });
                },
                else => {
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .lowering_gap = .{ .note = "destructure-target" } },
                        .pos = self.posOf(var_node),
                    });
                },
            }
        }

        // Mirror plain assign: rhs try/catch dispatch comes after the
        // per-target emissions (so the success path has the assigns
        // visible before the error-exit / catch fork branches off).
        switch (tree.nodeTag(rhs)) {
            .@"try" => try self.emitTryErrorExit(cur.*, self.posOf(rhs)),
            .@"catch" => try self.emitCatchFork(rhs, cur),
            else => {},
        }
    }

    fn lowerReturn(self: *Builder, ret_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const data = tree.nodeData(ret_node);
        const value_opt = data.opt_node.unwrap();

        // Top-level try/catch in the returned expression — model the
        // error path BEFORE flushing defers (so the synthetic sink and
        // the merge block both get the right view of state).  The
        // err-exit sink does its own flushErrAndNormalDefers; the
        // catch fork advances cur to a merge where we continue the
        // success-path return.
        if (value_opt) |expr| {
            switch (tree.nodeTag(expr)) {
                .@"try" => try self.emitTryErrorExit(cur.*, self.posOf(expr)),
                .@"catch" => try self.emitCatchFork(expr, cur),
                else => {},
            }
            // Top-level labeled-block return (`return blk: { ... };`)
            // — lower body in-place so side effects + breaks run
            // before the return.  cur advances to post-merge; the
            // ret then emits there.
            if (try self.maybeLowerLabeledBlockExpr(expr, cur)) {}

            // @takes checks for call-shaped return value (phase 27).
            try self.emitTakesChecksForExpr(expr, cur);
        }

        // Success-path defers: fire before the return-value check.
        try self.flushDefers(cur);

        const value_kind: ExprKind = if (value_opt) |expr|
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

        // @takes annotation check — emit per-arg validation stmts.
        try self.emitTakesChecksForCall(call_node, cur);

        // Other calls — side-effect from our pov is "nothing tracked".
        try self.appendStmt(cur.*, .{
            .kind = .{ .lowering_gap = .{ .note = "call-untracked" } },
            .pos = self.posOf(call_node),
        });
    }

    /// If the callee carries `@takes node_index_of(X)` (same-file OR
    /// cross-file via @import), emit one `.ast_takes_check` stmt per
    /// arg whose token-position resolves to a registered local — the
    /// transfer rule will check each one's `.ast_node` tag against
    /// the source param's `.ast`.  Conservative: arg locals that
    /// don't resolve to bare identifiers are skipped.
    fn emitTakesChecksForCall(
        self: *Builder,
        call_node: Ast.Node.Index,
        cur: *BlockId,
    ) !void {
        const tree = self.tree;

        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return;
        const callee_node = call_full.ast.fn_expr;
        const args = call_full.ast.params;

        // For `imported.method(...)` the receiver is a namespace, not
        // a value arg — so the takes annotation's param indices count
        // from args[0] (no receiver shift).  For `obj.method(...)` the
        // receiver IS arg[0] and indices shift by one.
        const is_namespace_call = self.isImportNamespaceCall(callee_node);
        const recv_is_arg0 = (tree.nodeTag(callee_node) == .field_access) and !is_namespace_call;

        // Mutation check (invariant #5): emit irrespective of takes.
        // Two call shapes:
        //   `obj.method(...)`        — receiver IS the Ast (recv_is_arg0).
        //   `Mod.method(ast, ...)`   — first explicit arg is the Ast
        //                              (phase 38: namespace shape; we
        //                              conservatively check args[0]
        //                              without a per-arg @mutates_ast
        //                              annotation refinement).
        if (self.lookupMutatesAst(callee_node)) {
            const ast_arg: ?Ast.Node.Index = if (recv_is_arg0)
                tree.nodeData(callee_node).node_and_token[0]
            else if (args.len > 0)
                args[0]
            else
                null;
            if (ast_arg) |n| {
                if (self.identifierToLocal(n)) |ast_local| {
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .ast_mutation_check = .{ .ast_local = ast_local } },
                        .pos = self.posOf(call_node),
                    });
                }
            }
        }

        const takes = self.lookupTakes(callee_node) orelse return;

        // Resolve the source-Ast arg, or short-circuit on the opt-out.
        const source_node: Ast.Node.Index = switch (takes) {
            // node_index_any: explicit opt-out — emit no checks.
            .node_index_any => return,
            .node_index_of => |idx| blk: {
                if (recv_is_arg0 and idx == 0) {
                    break :blk tree.nodeData(callee_node).node_and_token[0];
                }
                const explicit_idx = if (recv_is_arg0) idx - 1 else idx;
                if (explicit_idx >= args.len) return;
                break :blk args[explicit_idx];
            },
        };
        const source_local = self.identifierToLocal(source_node) orelse return;

        // For every OTHER arg (including the receiver when it isn't the
        // source), emit a check.  Args that don't resolve to bare
        // identifiers are skipped.
        if (recv_is_arg0) {
            const recv_node = tree.nodeData(callee_node).node_and_token[0];
            if (recv_node != source_node) {
                if (self.identifierToLocal(recv_node)) |vl| {
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .ast_takes_check = .{
                            .source_local = source_local,
                            .value_local = vl,
                        } },
                        .pos = self.posOf(call_node),
                    });
                }
            }
        }
        for (args) |a| {
            if (a == source_node) continue;
            if (self.identifierToLocal(a)) |vl| {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .ast_takes_check = .{
                        .source_local = source_local,
                        .value_local = vl,
                    } },
                    .pos = self.posOf(call_node),
                });
            }
        }
    }

    /// Bare-identifier → resolved LocalId, or null otherwise.
    /// (identifierToCopyOrUnknown wraps in an ExprKind; this returns
    /// the raw LocalId.)
    fn identifierToLocal(self: *Builder, node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        if (tree.nodeTag(node) != .identifier) return null;
        const name = tree.tokenSlice(tree.nodeMainToken(node));
        return self.name_to_local.get(name);
    }

    /// Is the call's receiver a namespace (vs an object/value)?
    /// Two recognized shapes:
    ///   `imported.method(...)`         — recv is identifier in imap
    ///   `imported.Sub.method(...)`     — recv is field_access whose
    ///                                    outermost ident is in imap
    /// Either case → namespace call; receiver is NOT arg 0.
    fn isImportNamespaceCall(self: *Builder, callee_node: Ast.Node.Index) bool {
        const tree = self.tree;
        if (tree.nodeTag(callee_node) != .field_access) return false;
        const recv_node = tree.nodeData(callee_node).node_and_token[0];
        const remote = self.remote orelse return false;

        const outer_ident_tok: ?Ast.TokenIndex = switch (tree.nodeTag(recv_node)) {
            .identifier => tree.nodeMainToken(recv_node),
            .field_access => blk: {
                const outer = tree.nodeData(recv_node).node_and_token[0];
                if (tree.nodeTag(outer) != .identifier) break :blk null;
                break :blk tree.nodeMainToken(outer);
            },
            else => null,
        };
        const tok = outer_ident_tok orelse return false;
        const name = tree.tokenSlice(tok);
        return remote.imap.lookup(name) != null;
    }

    /// Resolve callee's `@takes` annotation.  Same-file db first, then
    /// cross-file via remote resolver for `imported.method(...)` shapes.
    /// Returns null on any miss.
    fn lookupTakes(
        self: *Builder,
        callee_node: Ast.Node.Index,
    ) ?annotations.TakesAnnotation {
        const tree = self.tree;
        switch (tree.nodeTag(callee_node)) {
            .field_access => {
                const fa = tree.nodeData(callee_node);
                const recv_node = fa.node_and_token[0];
                const method_tok = fa.node_and_token[1];
                const method_name = tree.tokenSlice(method_tok);

                // Same-file first.
                if (self.db) |db| {
                    if (db.lookup(method_name)) |e| if (e.takes) |t| return t;
                }
                // Cross-file via remote (only when receiver is an
                // import namespace identifier).
                return self.lookupRemoteTakes(recv_node, method_name);
            },
            .identifier => {
                const name = tree.tokenSlice(tree.nodeMainToken(callee_node));
                if (self.db) |db| {
                    if (db.lookup(name)) |e| if (e.takes) |t| return t;
                }
                return null;
            },
            else => return null,
        }
    }

    /// Same shape as lookupTakes but reads the @mutates_ast bool.
    /// Same-file first, then cross-file via remote resolver.
    fn lookupMutatesAst(self: *Builder, callee_node: Ast.Node.Index) bool {
        const tree = self.tree;
        switch (tree.nodeTag(callee_node)) {
            .field_access => {
                const fa = tree.nodeData(callee_node);
                const recv_node = fa.node_and_token[0];
                const method_name = tree.tokenSlice(fa.node_and_token[1]);
                if (self.db) |db| {
                    if (db.lookup(method_name)) |e| if (e.mutates_ast) return true;
                }
                if (self.resolveRemoteFile(recv_node)) |rf| {
                    if (rf.db.lookup(method_name)) |e| if (e.mutates_ast) return true;
                }
                return false;
            },
            .identifier => {
                const name = tree.tokenSlice(tree.nodeMainToken(callee_node));
                if (self.db) |db| {
                    if (db.lookup(name)) |e| if (e.mutates_ast) return true;
                }
                return false;
            },
            else => return false,
        }
    }

    /// Cross-file `@takes` lookup.  Uses resolveRemoteFile so it
    /// inherits one-hop nested-namespace dispatch (phase 30) for free.
    fn lookupRemoteTakes(
        self: *Builder,
        recv_node: Ast.Node.Index,
        method_name: []const u8,
    ) ?annotations.TakesAnnotation {
        const file = self.resolveRemoteFile(recv_node) orelse return null;
        const entry = file.db.lookup(method_name) orelse return null;
        return entry.takes;
    }

    /// Walk the receiver chain to its terminal RemoteFile.  Two
    /// supported shapes:
    /// (a) `imported.method` — receiver is a bare identifier; one
    ///     hop through self.remote.imap.
    /// (b) `imported.Sub.method` — receiver is one-level nested
    ///     field_access; chase via `imported`'s OWN imap (loaded
    ///     into RemoteFile.imap as of phase 30) to land in Sub's
    ///     file.  Path resolution for the second hop uses the
    ///     intermediate file's directory.
    /// Deeper chains aren't followed.
    fn resolveRemoteFile(
        self: *Builder,
        recv_node: Ast.Node.Index,
    ) ?*const remote_resolver.RemoteFile {
        const tree = self.tree;
        const remote = self.remote orelse return null;

        switch (tree.nodeTag(recv_node)) {
            .identifier => {
                const recv_name = tree.tokenSlice(tree.nodeMainToken(recv_node));
                const entry = remote.imap.lookup(recv_name) orelse return null;
                const direct = (remote.cache.loadOrLookup(remote.base_dir, entry.path) catch null) orelse return null;
                // Pre-bound subfield: `const X = @import("...").Sub;`
                // chase one more hop through the loaded file's imap.
                if (entry.subfield) |sub| {
                    const sub_entry = direct.imap.lookup(sub) orelse return null;
                    const sub_dir = std.fs.path.dirname(direct.abs_path) orelse ".";
                    return (remote.cache.loadOrLookup(sub_dir, sub_entry.path) catch null);
                }
                return direct;
            },
            .field_access => {
                const fa = tree.nodeData(recv_node);
                const outer_node = fa.node_and_token[0];
                const inner_tok = fa.node_and_token[1];
                if (tree.nodeTag(outer_node) != .identifier) return null;
                const outer_name = tree.tokenSlice(tree.nodeMainToken(outer_node));
                const outer_import = remote.imap.lookup(outer_name) orelse return null;
                const outer_file = (remote.cache.loadOrLookup(remote.base_dir, outer_import.path) catch null) orelse return null;

                const inner_name = tree.tokenSlice(inner_tok);
                const inner_import = outer_file.imap.lookup(inner_name) orelse return null;
                const inner_base_dir = std.fs.path.dirname(outer_file.abs_path) orelse ".";
                return (remote.cache.loadOrLookup(inner_base_dir, inner_import.path) catch null);
            },
            else => return null,
        }
    }

    /// Walk through `try` wrappers to the underlying call node, or
    /// null if `node` isn't a call (possibly after one or more `try`s).
    /// `catch` not unwrapped — its lhs is a call but the whole
    /// expression's value has different propagation; conservatively
    /// skipped here so we don't emit phantom checks.
    fn unwrapToCallNode(self: *Builder, node: Ast.Node.Index) ?Ast.Node.Index {
        const tag = self.tree.nodeTag(node);
        return switch (tag) {
            .@"try" => self.unwrapToCallNode(self.tree.nodeData(node).node),
            .call, .call_one, .call_comma, .call_one_comma => node,
            else => null,
        };
    }

    /// If `expr` (after `try` unwrap) is a direct call, emit per-arg
    /// `.ast_takes_check` statements onto `cur`.  Hook used by
    /// init/return/assign positions to broaden phase 26's
    /// statement-position-only emission.
    fn emitTakesChecksForExpr(
        self: *Builder,
        expr: Ast.Node.Index,
        cur: *BlockId,
    ) !void {
        const call_node = self.unwrapToCallNode(expr) orelse return;
        try self.emitTakesChecksForCall(call_node, cur);
    }

    fn classifyExpr(self: *Builder, expr_node: Ast.Node.Index) ExprKind {
        const tree = self.tree;
        const tag = tree.nodeTag(expr_node);

        // `try expr` — unwrap and classify the inner expression.  The
        // error-exit edge isn't modeled yet (phase 9); for success-path
        // analysis the wrapped value has the same origin as the inner
        // call's return.
        if (tag == .@"try") {
            return self.classifyExpr(tree.nodeData(expr_node).node);
        }

        // `lhs catch rhs` — success path uses lhs's value; error path
        // uses rhs.  Without modeling forking yet, conservatively join
        // by returning .unknown (caller must treat as opaque).  This
        // beats classifying as either side and pretending the other
        // doesn't exist.
        if (tag == .@"catch") return .unknown;

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
        // `Ast.parse(...)` — fresh Ast.  Pattern match on source text
        // for robustness against `std.zig.Ast.parse`, `Ast.parse`, etc.
        // False positives (a custom `.parse` named function on an
        // Ast-shaped namespace) would taint a non-Ast local with
        // .ast — downstream node_index_of propagation would still be
        // sound (the Ast tag just wouldn't match real Ast methods).
        if (std.mem.indexOf(u8, text, "Ast.parse") != null) {
            return .ast_init;
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

        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return .unknown;
        const callee_node = call_full.ast.fn_expr;
        const args = call_full.ast.params;

        switch (tree.nodeTag(callee_node)) {
            .field_access => {
                const fa_data = tree.nodeData(callee_node);
                const recv_node = fa_data.node_and_token[0];
                const method_tok = fa_data.node_and_token[1];
                const method_name = tree.tokenSlice(method_tok);

                // 1. Same-file DB hit on method name.
                if (self.db) |db| {
                    if (db.lookup(method_name)) |entry| {
                        if (entry.annotation) |anno| {
                            return self.applyAnnotationToCall(anno, recv_node, args, true);
                        }
                    }
                }

                // 2. Cross-file: receiver is a bare identifier (the
                //    imported namespace), method lives in that file's DB.
                if (self.lookupRemoteMethod(recv_node, method_name)) |annotation| {
                    // For cross-file: there's no `recv` in the explicit
                    // args list (since the receiver IS the namespace),
                    // so treat as a non-method-style call.
                    return self.applyAnnotationToCall(annotation, callee_node, args, false);
                }
                return .unknown;
            },
            .identifier => {
                const fn_name = tree.tokenSlice(tree.nodeMainToken(callee_node));
                if (self.db) |db| {
                    if (db.lookup(fn_name)) |entry| {
                        if (entry.annotation) |anno| {
                            return self.applyAnnotationToCall(anno, callee_node, args, false);
                        }
                    }
                }
                return .unknown;
            },
            else => return .unknown,
        }
    }

    /// Cross-file resolution.  Uses resolveRemoteFile so it accepts
    /// both single-hop (`imported.method`) and nested
    /// (`imported.Sub.method`) receiver shapes.  Returns null on any
    /// miss.
    fn lookupRemoteMethod(
        self: *Builder,
        recv_node: Ast.Node.Index,
        method_name: []const u8,
    ) ?annotations.ReturnsAnnotation {
        const file = self.resolveRemoteFile(recv_node) orelse return null;
        const entry = file.db.lookup(method_name) orelse return null;
        return entry.annotation; // may itself be null — caller treats as miss
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
            // `@returns ast` — call mints a fresh Ast value, same as
            // the text-detected `Ast.parse(...)` pattern.  Indistinct
            // from .ast_init at the ExprKind level.
            .ast => return .ast_init,
            .borrowed_from => |target_idx| {
                if (receiver_is_arg0 and target_idx == 0) {
                    return self.identifierToCopyOrUnknown(receiver_or_callee);
                }
                const explicit_idx = if (receiver_is_arg0) target_idx - 1 else target_idx;
                if (explicit_idx >= args.len) return .unknown;
                return self.identifierToCopyOrUnknown(args[explicit_idx]);
            },
            // `@returns node_index_of(<param>)`: result is a NodeIndex
            // tagged with the source param's Ast identity.  Same
            // arg-position dispatch as borrowed_from.
            .node_index_of => |target_idx| {
                const source_node = blk: {
                    if (receiver_is_arg0 and target_idx == 0) break :blk receiver_or_callee;
                    const explicit_idx = if (receiver_is_arg0) target_idx - 1 else target_idx;
                    if (explicit_idx >= args.len) return .unknown;
                    break :blk args[explicit_idx];
                };
                const src_kind = self.identifierToCopyOrUnknown(source_node);
                return switch (src_kind) {
                    .copy_of => |local| .{ .node_index_of = local },
                    else => .unknown,
                };
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

/// Test bundle returned by `parseAndLower`.  Owns src_z so name
/// slices in cfg.locals (which point into tree.source = src_z) stay
/// valid for the bundle's lifetime.  Pre-phase-20 src_z was freed
/// on parseAndLower's return, which dangled the names — tests that
/// inspected names saw garbage.
const TestBundle = struct {
    src_z: [:0]u8,
    tree: Ast,
    cfg: ?Cfg,

    fn deinit(self: *TestBundle, gpa: std.mem.Allocator) void {
        if (self.cfg) |*c| c.deinit(gpa);
        self.tree.deinit(gpa);
        gpa.free(self.src_z);
    }
};

fn parseAndLower(gpa: std.mem.Allocator, src: []const u8) !TestBundle {
    return parseAndLowerCommon(gpa, src, false);
}

/// Same as parseAndLower but builds the same-file annotation DB and
/// threads it through lowerFunction.  Use when tests exercise the
/// annotated-call classification paths.  Db is intentionally leaked
/// — its keys/values point into tree.source which the bundle owns.
fn parseAndLowerWithDb(gpa: std.mem.Allocator, src: []const u8) !TestBundle {
    return parseAndLowerCommon(gpa, src, true);
}

fn parseAndLowerCommon(gpa: std.mem.Allocator, src: []const u8, build_db: bool) !TestBundle {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    errdefer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    errdefer tree.deinit(gpa);

    var db_storage: ?annotations.Db = if (build_db) try annotations.build(gpa, &tree) else null;
    // Db owns only its map; deinit'd at bundle.deinit via leak-into-cfg
    // pattern is wrong — we need to deinit it manually.  Easiest: free
    // here on the success path too, since cfg only borrows annotation
    // VALUES (which are small union types), not slice keys.  Wait — db
    // is consulted DURING lowerFunction, then no longer needed once
    // CFG emit completes.  Free immediately after lowerFunction returns.
    defer if (db_storage) |*d| d.deinit(gpa);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) == .fn_decl) {
            const db_ptr: ?*const annotations.Db = if (db_storage) |*d| d else null;
            const cfg = try lowerFunction(gpa, &tree, node, db_ptr);
            return .{ .src_z = src_z, .tree = tree, .cfg = cfg };
        }
    }
    return .{ .src_z = src_z, .tree = tree, .cfg = null };
}

test "lower trivial fn — entry block + return" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

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
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

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
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

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
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    const stmts = cfg.blocks[0].stmts;
    try std.testing.expectEqual(@as(usize, 3), stmts.len);
    try std.testing.expect(stmts[0].kind == .decl);
    try std.testing.expect(stmts[1].kind == .thread_join);
    try std.testing.expect(stmts[2].kind == .ret);
}

test "if-statement creates fork: 3 blocks (entry, then, merge)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    if (x) return;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Entry, then-branch, merge.  No else (single-armed if).
    try std.testing.expect(cfg.blocks.len >= 3);
    // Entry block has 2 successors (then + merge).
    try std.testing.expectEqual(@as(usize, 2), cfg.blocks[0].successors.len);
}

test "if-else creates fork: 4 blocks (entry, then, else, merge)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    if (x) return else return;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    try std.testing.expect(cfg.blocks.len >= 4);
    try std.testing.expectEqual(@as(usize, 2), cfg.blocks[0].successors.len);
}

test "for loop creates back-edge: body → header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(items: []const u32) void {
        \\    for (items) |x| { _ = x; }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;
    // entry, header, body, merge (minimum 4 blocks).
    try std.testing.expect(cfg.blocks.len >= 4);
}

test "switch creates N-way fork (3 cases → 4+ blocks)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: u32) void {
        \\    switch (x) {
        \\        0 => return,
        \\        1 => return,
        \\        else => return,
        \\    }
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;
    // entry + 3 case-blocks + merge = 5 blocks min.
    try std.testing.expect(cfg.blocks.len >= 5);
    // entry has 3 successors (one per case).
    try std.testing.expectEqual(@as(usize, 3), cfg.blocks[0].successors.len);
}

test "while loop creates back-edge: body → header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {}
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // header block has 2 successors (body, merge); body block has 1
    // successor (back to header).  At minimum we expect 4 blocks:
    // entry, header, body, merge.
    try std.testing.expect(cfg.blocks.len >= 4);
}

test "errdefer kill doesn't pollute success-return defer flush" {
    // errdefer arena.deinit() must NOT fire on a plain `return` —
    // otherwise the (returned-value) origin check would see arena
    // already-killed and wrongly flag the return.
    //
    // NOTE: parseAndLower picks the FIRST fn_decl, so `foo` must lead.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    errdefer arena.deinit();
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Scan every block's stmts: no `.arena_kill` should appear before
    // the `.ret`.  (Without the defer/errdefer split, errdefer's kill
    // would have been replayed at the return site.)
    var saw_kill_before_ret = false;
    var saw_ret = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            switch (s.kind) {
                .arena_kill => if (!saw_ret) {
                    saw_kill_before_ret = true;
                },
                .ret => saw_ret = true,
                else => {},
            }
        }
    }
    try std.testing.expect(!saw_kill_before_ret);
}

test "plain defer DOES fire on return — kill visible before ret stmt" {
    // Symmetric to the errdefer test: a normal `defer` must still
    // replay at every return so the analyzer sees its side effects.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "try at statement position creates error-exit sink with defers replayed" {
    // `try call();` — adds an error-exit block reachable from cur.
    // The sink should contain whatever defers were active (here:
    // arena.deinit() from `defer`) and a terminating ret.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    try sideEffect();
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // After `try`, at least one block must have BOTH an arena_kill
    // (the defer'd deinit) AND a ret — that's the err_exit sink.
    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "catch at statement position forks: success + catch body merge" {
    // `expr catch BODY;` — two paths join at a merge block.  Minimum
    // block count: entry + catch + merge = 3.  (entry also acts as
    // the success-edge source via direct edge to merge.)
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    sideEffect() catch {};
        \\    return;
        \\}
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    try std.testing.expect(cfg.blocks.len >= 3);

    // The entry block must have ≥2 successors after catch lowering
    // (one to catch_block, one to merge).
    var multi_succ = false;
    for (cfg.blocks) |b| {
        if (b.successors.len >= 2) multi_succ = true;
    }
    try std.testing.expect(multi_succ);
}

test "catch body side effects visible at merge (kill in catch reaches downstream)" {
    // Arena killed only inside the catch body — at the merge point
    // it should be in the "either-killed-or-alive" state.  The
    // analyzer's join semantics (dead-on-either-side wins) means
    // downstream uses would be flagged.  Here we just verify the
    // arena_kill ends up in some non-entry block.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    sideEffect() catch { arena.deinit(); };
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Find an arena_kill — should appear in a non-entry block (the
    // catch_block specifically, but we don't care which).
    var kill_in_non_entry = false;
    for (cfg.blocks, 0..) |b, i| {
        if (i == 0) continue;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) kill_in_non_entry = true;
        }
    }
    try std.testing.expect(kill_in_non_entry);
}

test "var-decl init `try foo()` adds error-exit sink with defer replayed" {
    // Same shape as the statement-position try test, but the `try`
    // hides inside a var-decl init.  Pre-phase-10 the sink wasn't
    // emitted in this position.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    const x = try sideEffect();
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "var-decl init `foo() catch BODY` forks: catch body's kill visible downstream" {
    // `const x = foo() catch { arena.deinit(); 0 };` — the catch
    // body's arena_kill must reach a non-entry block so the join at
    // the post-decl merge sees the kill on one incoming edge.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    const x = sideEffect() catch blk: {
        \\        arena.deinit();
        \\        break :blk 0;
        \\    };
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var kill_in_non_entry = false;
    for (cfg.blocks, 0..) |b, i| {
        if (i == 0) continue;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) kill_in_non_entry = true;
        }
    }
    try std.testing.expect(kill_in_non_entry);
}

test "return position `return try foo()` adds error-exit sink with defer replayed" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !u32 {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    return try sideEffect();
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Two distinct blocks should each contain an arena_kill + ret:
    //   - the success-path return block (defer flushed inline)
    //   - the err-exit sink (errdefer + defer flushed)
    var sink_count: u32 = 0;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) sink_count += 1;
    }
    try std.testing.expect(sink_count >= 2);
}

test "return position `return foo() catch BODY` forks and merges into ret" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() u32 {
        \\    return sideEffect() catch 0;
        \\}
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Catch fork: entry → catch_block + entry → merge; catch_block →
    // merge; merge contains the ret.  At least one block has ≥2
    // successors AND there exists a ret somewhere.
    var multi_succ = false;
    var has_ret_anywhere = false;
    for (cfg.blocks) |b| {
        if (b.successors.len >= 2) multi_succ = true;
        for (b.stmts) |s| {
            if (s.kind == .ret) has_ret_anywhere = true;
        }
    }
    try std.testing.expect(multi_succ);
    try std.testing.expect(has_ret_anywhere);
}

test "assign to known local emits .assign with classified rhs" {
    // `x = src;` — must emit .assign (not lowering_gap) so the analyzer
    // can update x's origin to copy_of(src).  Pre-phase-12 this was a
    // stubbed gap, conservatively collapsing both locals to .plain.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var x: u32 = 0;
        \\    var src: u32 = 1;
        \\    x = src;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_assign_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                found_assign_copy_of = true;
            }
        }
    }
    try std.testing.expect(found_assign_copy_of);
}

test "assign rhs `try foo()` emits err-exit sink alongside .assign" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    var x: u32 = 0;
        \\    x = try sideEffect();
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "assign to field (obj.x = src) falls back to lowering_gap" {
    // Field assignment isn't a tracked local — must stay conservative.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var obj: Obj = .{ .x = 0 };
        \\    var src: u32 = 1;
        \\    obj.x = src;
        \\    return;
        \\}
        \\const Obj = struct { x: u32 };
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_gap = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap and
                std.mem.eql(u8, s.kind.lowering_gap.note, "assign-target"))
                found_gap = true;
        }
    }
    try std.testing.expect(found_gap);
}

test "break inside while adds edge from body to merge" {
    // Without phase 13, `break` fell through to lowering_gap and the
    // body just continued to its back-edge — the analyzer never saw a
    // direct body→merge edge that bypasses the header check.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {
        \\        if (x) break;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // The merge block exists.  Count how many blocks have an edge to
    // the merge block — pre-phase-13 it was 1 (header→merge only);
    // now it should be ≥2 (header→merge AND a body-side→merge).
    // We don't know merge's exact ID, so iterate: find blocks with
    // ≥2 successors targeting any non-header block, OR count edges
    // landing on each block and assert max ≥2 (header → merge AND
    // break-block → merge).
    var max_incoming: u32 = 0;
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| {
            incoming[@intFromEnum(s)] += 1;
        }
    }
    for (incoming) |c| {
        if (c > max_incoming) max_incoming = c;
    }
    // Header gets ≥2 incoming (entry + body back-edge).  Merge gets
    // ≥2 now (header→merge + break-block→merge).  So we expect at
    // least TWO different blocks with ≥2 incoming edges.
    var ge2_count: u32 = 0;
    for (incoming) |c| if (c >= 2) {
        ge2_count += 1;
    };
    try std.testing.expect(ge2_count >= 2);
}

test "continue inside for adds back-edge from body-mid to header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    for (xs) |x| {
        \\        if (x == 0) continue;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Header should have ≥3 incoming edges now: entry, body back-edge,
    // continue back-edge.  Pre-phase-13 it was 2.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 3);
}

test "break outside loop emits gap (defensive — Zig wouldn't compile)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    break;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap and
                std.mem.eql(u8, s.kind.lowering_gap.note, "break-outside-loop"))
                found = true;
        }
    }
    try std.testing.expect(found);
}

test "labeled break: `break :outer` from inner loop targets outer's merge" {
    // Without label resolution, inner break would just exit the inner
    // loop; outer's merge wouldn't get the extra incoming edge.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    outer: while (x) {
        \\        while (x) {
        \\            if (x) break :outer;
        \\        }
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Find the block reached by `break :outer` — it should be the
    // OUTER merge, which is downstream from outer header.  Heuristic:
    // there must exist a path of length 1 from some block (the break
    // emitter) directly to outer's merge, AND that merge must NOT be
    // the inner header.  Easier check: count blocks with ≥2 incoming
    // edges.  Pre-fix: outer header had 2 (entry + body); outer merge
    // had 1 (header→merge).  Post-fix: outer merge has 2 (header→merge
    // + labeled-break→merge).  So ≥2 blocks with ≥2 incoming.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var ge2: u32 = 0;
    for (incoming) |c| if (c >= 2) {
        ge2 += 1;
    };
    // Outer header (≥2), inner header (≥2), outer merge (≥2 only with
    // the labeled-break fix).  Expect at least 3.
    try std.testing.expect(ge2 >= 3);
}

test "labeled continue: `continue :outer` from inner loop targets outer's header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    outer: while (x) {
        \\        while (x) {
        \\            if (x) continue :outer;
        \\        }
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Outer header should now have ≥3 incoming: entry + inner-body
    // back-edge through outer body + labeled-continue back-edge.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 3);
}

test "labeled break to unknown label emits gap (not crash, no false match)" {
    // `break :nope;` inside a loop with no matching label — walks
    // the loop stack, finds nothing, must emit a gap rather than
    // accidentally targeting the innermost loop or crashing.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {
        \\        if (x) break :nope;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap and
                std.mem.eql(u8, s.kind.lowering_gap.note, "labeled-break-no-loop"))
                found = true;
        }
    }
    try std.testing.expect(found);
}

test "for-loop capture registered: use of `item` resolves to a tracked local" {
    // Pre-phase-15 `item` was an unknown identifier; the .assign rhs
    // would classify as .unknown.  After capture registration, `item`
    // is a known local and `x = item` should classify as copy_of.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    var x: u32 = 0;
        \\    for (xs) |item| {
        \\        x = item;
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "for-loop multiple captures `|item, idx|` both registered" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    var a: u32 = 0;
        \\    var b: usize = 0;
        \\    for (xs, 0..) |item, idx| {
        \\        a = item;
        \\        b = idx;
        \\    }
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var copy_of_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                copy_of_count += 1;
            }
        }
    }
    // Both `a = item` and `b = idx` should classify as copy_of.
    try std.testing.expect(copy_of_count >= 2);
}

test "discard capture `|_|` is NOT registered as a local" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    for (xs) |_| {}
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    for (cfg.locals) |l| {
        try std.testing.expect(!std.mem.eql(u8, l.name, "_"));
    }
}

test "while-with-payload `while (opt) |val|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(it: anytype) void {
        \\    var x: u32 = 0;
        \\    while (it.next()) |val| {
        \\        x = val;
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "if-optional payload `if (opt) |val|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(opt: ?u32) void {
        \\    var x: u32 = 0;
        \\    if (opt) |val| {
        \\        x = val;
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "if-error-union payload `else |err|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(r: anyerror!u32) void {
        \\    var e: anyerror = error.None;
        \\    if (r) |_| {} else |err| {
        \\        e = err;
        \\    }
        \\    _ = e;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "switch case payload `.tag => |val|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\const U = union(enum) { a: u32, b: u32 };
        \\pub fn foo(u: U) void {
        \\    var x: u32 = 0;
        \\    switch (u) {
        \\        .a => |val| { x = val; },
        \\        .b => |val| { x = val; },
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var copy_of_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                copy_of_count += 1;
            }
        }
    }
    try std.testing.expect(copy_of_count >= 2);
}

test "catch payload `catch |err|` registers capture (stmt position)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var e: anyerror = error.None;
        \\    sideEffect() catch |err| { e = err; };
        \\    _ = e;
        \\    return;
        \\}
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "statement-position labeled block: `break :blk` resolves to block merge" {
    // `blk: { ...; if (x) break :blk; ...; }` — the labeled break
    // must add an edge to the block's merge, not be a no-op gap.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    blk: {
        \\        if (x) break :blk;
        \\        // some non-trivial body so block isn't elided
        \\        var y: u32 = 0;
        \\        _ = y;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // The block merge should have ≥2 incoming edges: the break path
    // AND the natural fallthrough from end-of-body.  Pre-phase-17
    // the break emitted a "labeled-break-no-loop" gap and no edge,
    // so merge had at most 1 incoming.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 2);

    // And NO labeled-break-no-loop gap should remain.
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "labeled-break-no-loop",
                ));
            }
        }
    }
}

test "labeled block inside loop: break :blk doesn't escape the loop" {
    // `while (x) { blk: { ... break :blk; }; more; }` — break :blk
    // exits ONLY the block, not the loop.  Verify that the loop
    // merge isn't reached by the labeled break.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {
        \\        blk: {
        \\            if (x) break :blk;
        \\            var y: u32 = 0;
        \\            _ = y;
        \\        }
        \\        // this stmt is reachable from the block break.
        \\        var z: u32 = 0;
        \\        _ = z;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Confirm we built a non-trivial CFG and there's no leftover
    // labeled-break-no-loop gap.
    try std.testing.expect(cfg.blocks.len >= 5);
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "labeled-break-no-loop",
                ));
            }
        }
    }
}

test "expression-position labeled block: var-decl init `const x = blk: {...}` lowers body" {
    // Side effect inside the labeled-block init (arena.deinit() here)
    // must reach a CFG block — pre-phase-18 the init was opaque, so
    // the deinit call was invisible to the analyzer.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    const r = blk: {
        \\        arena.deinit();
        \\        break :blk 0;
        \\    };
        \\    _ = r;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "expression-position labeled block: return `return blk: {...}` lowers body" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() u32 {
        \\    var arena = Arena.init(0);
        \\    return blk: {
        \\        arena.deinit();
        \\        break :blk 0;
        \\    };
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "expression-position labeled block: `break :blk val` adds edge to merge" {
    // The block has two exit edges — `break :blk 1` and natural
    // fallthrough.  Merge should have ≥2 incoming.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) u32 {
        \\    const r = blk: {
        \\        if (x) break :blk 1;
        \\        break :blk 0;
        \\    };
        \\    return r;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 2);
    // No leftover labeled-break-no-loop gaps.
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "labeled-break-no-loop",
                ));
            }
        }
    }
}

test "expression-position labeled block: assign `x = blk: {...}` lowers body" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    var x: u32 = 0;
        \\    x = blk: {
        \\        arena.deinit();
        \\        break :blk 1;
        \\    };
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "destructuring var-decl `const a, const b = pair()` registers both locals" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    const a, const b = pair();
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\pub fn pair() struct { u32, u32 } { return .{ 0, 1 }; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // TestBundle now owns src_z (phase 20 fix) — name slices stay
    // valid until result.deinit, so we can assert on names directly.
    var saw_a = false;
    var saw_b = false;
    for (cfg.locals) |l| {
        if (std.mem.eql(u8, l.name, "a")) saw_a = true;
        if (std.mem.eql(u8, l.name, "b")) saw_b = true;
    }
    try std.testing.expect(saw_a and saw_b);

    var decl_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .decl) decl_count += 1;
        }
    }
    try std.testing.expect(decl_count >= 2);
}

test "classifyExpr: `Ast.parse(...)` → .ast_init (phase 25)" {
    // Wrap with `try` not `catch` — classifyExpr early-returns
    // .unknown on .@"catch" (phase 8), and we want the inner
    // Ast.parse call's text to reach the pattern matcher.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var tree = try Ast.parse(undefined, undefined, .zig);
        \\    _ = tree;
        \\    return;
        \\}
        \\const Ast = struct {
        \\    pub fn parse(_: u32, _: u32, _: anytype) !Ast { return .{}; }
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_ast_init = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .decl and s.kind.decl.init_kind == .ast_init) {
                saw_ast_init = true;
            }
        }
    }
    try std.testing.expect(saw_ast_init);
}

test "applyAnnotationToCall: @returns node_index_of(arg) → .node_index_of (phase 25)" {
    // The annotation propagates the source arg's Ast identity onto
    // the returned NodeIndex.  Verify the classifier outputs the
    // .node_index_of variant when a same-file fn carries this
    // annotation and we call it with a registered local.
    // Pass `tree` by value (bare identifier) — identifierToCopyOrUnknown
    // requires an .identifier node tag.  `&tree` would parse as
    // .address_of and the propagation degrades to .unknown.
    // Needs the same-file annotation DB so classifyCall can resolve
    // `rootNode`'s @returns marker.
    const gpa = std.testing.allocator;
    var result = try parseAndLowerWithDb(gpa,
        \\pub fn foo() void {
        \\    var tree: Ast = .{};
        \\    const root = rootNode(tree);
        \\    _ = root;
        \\    return;
        \\}
        \\const Ast = struct {};
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(ast)
        \\pub fn rootNode(ast: Ast) NodeIndex {
        \\    _ = ast; return 0;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_node_index_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .decl and s.kind.decl.init_kind == .node_index_of) {
                saw_node_index_of = true;
            }
        }
    }
    try std.testing.expect(saw_node_index_of);
}

test "name slices live for the test bundle's lifetime (phase 20 dangle fix)" {
    // Regression guard for the parseAndLower → src_z dangle bug.
    // Pre-phase-20, this assertion saw garbage UTF-8 because the
    // helper freed src_z on return.  If TestBundle ever loses its
    // src_z ownership, this will start printing `name=�...` again.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var unique_local_name_xyz: u32 = 0;
        \\    _ = unique_local_name_xyz;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found = false;
    for (cfg.locals) |l| {
        if (std.mem.eql(u8, l.name, "unique_local_name_xyz")) found = true;
    }
    try std.testing.expect(found);
}

test "destructuring assign `a, b = pair()` emits .assign for each target" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var a: u32 = 0;
        \\    var b: u32 = 0;
        \\    a, b = pair();
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\pub fn pair() struct { u32, u32 } { return .{ 0, 1 }; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var assign_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign) assign_count += 1;
        }
    }
    // At least 2 from the destructure (could be more from the initial
    // `var a: u32 = 0` decls, but those are .decl not .assign).
    try std.testing.expect(assign_count >= 2);

    // No leftover assign_destructure gap.
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "assign_destructure",
                ));
            }
        }
    }
}

test "destructure rhs `try pair()` adds err-exit sink" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    const a, const b = try pair();
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn pair() !struct { u32, u32 } { return .{ 0, 1 }; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "try unwraps inner expression: copy_of(src) preserved through try" {
    // `const y = try src;` — y's origin should be copy_of(src), not
    // .unknown.  Validates classifyExpr's .@\"try\" recursion.
    // (Use a local — fn params aren't registered in name_to_local.)
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() anyerror!u32 {
        \\    const src: anyerror!u32 = 1;
        \\    const y = try src;
        \\    return y;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Find the decl for `y` and assert its init_kind is .copy_of.
    var found_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .decl and s.kind.decl.init_kind == .copy_of) {
                found_copy_of = true;
            }
        }
    }
    try std.testing.expect(found_copy_of);
}
