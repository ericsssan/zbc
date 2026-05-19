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
    /// Stack of `defer` bodies, LIFO.  Replayed at every `return` exit
    /// (always fires) and at function-fallthrough.
    deferred_normal: std.ArrayListUnmanaged(Ast.Node.Index) = .empty,
    deferred_err: std.ArrayListUnmanaged(Ast.Node.Index) = .empty,
    /// Loop context stack — pushed by lowerWhile/lowerFor before
    /// lowering the body, popped after.  `break` jumps to the
    /// innermost merge; `continue` jumps to the innermost header.
    /// Labels aren't modeled yet (always targets the innermost loop).
    loop_stack: std.ArrayListUnmanaged(LoopCtx) = .empty,
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
            // (Empty switch arms `else => {}` are a common case.)
            .block, .block_semicolon, .block_two, .block_two_semicolon => {
                try self.lowerBlock(stmt_node, cur);
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

        // Lower the then branch.
        var then_cur = then_block;
        try self.lowerStmt(if_data.ast.then_expr, &then_cur);
        // Then-branch exits flow into merge.
        try self.addEdge(then_cur, merge_block);

        // Lower the else branch if present.
        if (else_block) |eb| {
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

    /// `break`/`continue` — add an edge from cur to the innermost
    /// loop's merge (break) or header (continue), then redirect cur
    /// to a fresh dead block so any statements emitted after the
    /// break/continue don't leak into the actual flow.  Labels not
    /// modeled: always targets the innermost loop.
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
        // colon), already lowercased by the lexer.  Match against
        // LoopCtx.label from innermost out.
        const opt_label_tok = tree.nodeData(node).opt_token_and_opt_node[0];
        const target_ctx: LoopCtx = blk: {
            if (opt_label_tok.unwrap()) |lt| {
                const wanted = tree.tokenSlice(lt);
                var i = self.loop_stack.items.len;
                while (i > 0) {
                    i -= 1;
                    const ctx = self.loop_stack.items[i];
                    if (ctx.label) |lbl| {
                        if (std.mem.eql(u8, lbl, wanted)) break :blk ctx;
                    }
                }
                // Labeled break to a non-loop block label (`blk: { ...
                // break :blk; }`) — block labels aren't modeled yet.
                // Emit gap, leave flow alone.
                try self.appendStmt(cur.*, .{
                    .kind = .{ .lowering_gap = .{ .note = "labeled-break-no-loop" } },
                    .pos = self.posOf(node),
                });
                return;
            }
            // Unlabeled: innermost.
            break :blk self.loop_stack.items[self.loop_stack.items.len - 1];
        };

        const target = switch (kind) {
            .@"break" => target_ctx.merge,
            .@"continue" => target_ctx.header,
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
        try self.emitCatchFork(data[1], cur);
    }

    /// Append a catch-body fork to `cur`: one edge straight to merge
    /// (success), one through a new block where `body_node` lowers
    /// (catch body), then both join.  `cur` advances to merge.
    /// Used by `lowerCatchStmt` and `lowerVarDecl` (when init is a
    /// top-level `.@"catch"` — the body's side effects then become
    /// visible at the post-decl merge point).
    fn emitCatchFork(self: *Builder, body_node: Ast.Node.Index, cur: *BlockId) !void {
        const catch_block = try self.newBlock();
        const merge = try self.newBlock();

        try self.addEdge(cur.*, catch_block);
        try self.addEdge(cur.*, merge);

        var catch_cur = catch_block;
        try self.lowerStmt(body_node, &catch_cur);
        try self.addEdge(catch_cur, merge);

        cur.* = merge;
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
        const init_kind: ExprKind = if (init_opt) |init|
            self.classifyExpr(init)
        else
            .plain;

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
                .@"catch" => {
                    const data = tree.nodeData(init).node_and_node;
                    try self.emitCatchFork(data[1], cur);
                },
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

        // Destructuring (`a, b = pair`) — multi-target; not yet tracked.
        if (tag == .assign_destructure) {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "assign_destructure" } },
                .pos = self.posOf(assign_node),
            });
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
            .@"catch" => {
                const c = tree.nodeData(rhs).node_and_node;
                try self.emitCatchFork(c[1], cur);
            },
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
                .@"catch" => {
                    const c = tree.nodeData(expr).node_and_node;
                    try self.emitCatchFork(c[1], cur);
                },
                else => {},
            }
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
        // Other calls — side-effect from our pov is "nothing tracked".
        try self.appendStmt(cur.*, .{
            .kind = .{ .lowering_gap = .{ .note = "call-untracked" } },
            .pos = self.posOf(call_node),
        });
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
    const src_z = try gpa.dupeSentinel(u8, src, 0);
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

test "if-statement creates fork: 3 blocks (entry, then, merge)" {
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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);
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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);
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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
    defer result.tree.deinit(gpa);
    var cfg = result.cfg.?;
    defer cfg.deinit(gpa);

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
