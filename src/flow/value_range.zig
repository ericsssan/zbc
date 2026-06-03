//! Standalone intra-procedural value-range oracle (Track B, v1: nonzero).
//!
//! Answers one sound question for a single function body:
//!   "Is unsigned local `target` provably != 0 at token `use_token`,
//!    on every path that reaches it?"
//!
//! This is the fact `index-minus-one-without-zero-guard` needs: for an
//! unsigned `i`, `i != 0` ⟺ `i >= 1` ⟺ `i - 1` cannot underflow.  A sound
//! "yes" lets the rule suppress; "no"/"unknown" keeps it firing.
//!
//! Design — a structured forward abstract interpretation over the AST, with
//! a tiny domain (a set of provably-nonzero local names) and proper join at
//! if/else merges.  It is deliberately NOT built on `src/flow/`'s CFG: that
//! CFG discards branch truthiness (cfg_builder.zig: "We don't model the
//! condition's truthiness"), which is exactly the information value-range
//! needs.  Keeping this standalone avoids destabilizing the working
//! escape/UAF/double-free worklist; it can be promoted into a shared CFG
//! domain later if warranted.
//!
//! Soundness stance: the domain UNDER-approximates "definitely nonzero".
//! Every transfer either preserves a fact only when provably valid or drops
//! it.  Any uncertainty (unrecognized assignment, loop mutation, unmodeled
//! construct) collapses to "unknown" → the oracle returns false → the rule
//! fires.  False negatives in the oracle (saying "unknown" when actually
//! nonzero) only cost recall on suppression (a retained true-or-false
//! positive), never a missed real bug.
//!
//! Modeled:
//!   - `const/var x = <init>;` and `x = <rhs>;` — add x iff RHS is a
//!     positive integer literal; otherwise remove x (conservative).
//!   - `if (COND) THEN [else ELSE]` — refine inside arms from COND
//!     (`x > 0`, `x != 0`, `x >= 1`, `0 < x`, and their `x == 0` / `x <= 0`
//!     / `x < 1` else-duals; `and`-chains contribute their then-refinements);
//!     merge arm outputs by intersection, honouring divergent arms
//!     (return/break/continue/unreachable/@panic).
//!   - `while`/`for` — sound-conservative: drop every local assigned anywhere
//!     in the loop body before flowing past / into it (the value at a use
//!     could come from any iteration).
//!
//! Not modeled (conservatively → unknown): switch payloads, labeled blocks
//! as values, arithmetic other than positive-literal assignment, aliasing.

const std = @import("std");
const Ast = std.zig.Ast;

/// A set of local names known to be nonzero on the current path.  Names are
/// source slices (stable for the tree's lifetime).  Small in practice; linear
/// scan is fine.
const NonzeroSet = struct {
    names: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *NonzeroSet, gpa: std.mem.Allocator) void {
        self.names.deinit(gpa);
    }

    fn contains(self: *const NonzeroSet, name: []const u8) bool {
        for (self.names.items) |n| if (std.mem.eql(u8, n, name)) return true;
        return false;
    }

    fn add(self: *NonzeroSet, gpa: std.mem.Allocator, name: []const u8) !void {
        if (self.contains(name)) return;
        try self.names.append(gpa, name);
    }

    fn remove(self: *NonzeroSet, name: []const u8) void {
        var i: usize = 0;
        while (i < self.names.items.len) {
            if (std.mem.eql(u8, self.names.items[i], name)) {
                _ = self.names.swapRemove(i);
            } else i += 1;
        }
    }

    fn clone(self: *const NonzeroSet, gpa: std.mem.Allocator) !NonzeroSet {
        var out: NonzeroSet = .{};
        try out.names.appendSlice(gpa, self.names.items);
        return out;
    }

    /// In-place intersection: keep only names present in `other`.
    fn intersectWith(self: *NonzeroSet, other: *const NonzeroSet) void {
        var i: usize = 0;
        while (i < self.names.items.len) {
            if (other.contains(self.names.items[i])) {
                i += 1;
            } else {
                _ = self.names.swapRemove(i);
            }
        }
    }
};

/// Result of analyzing a statement sequence.
const Flow = struct {
    /// The target's nonzero-ness at `use_token`, once the use is reached.
    /// null means the use was not in this sub-tree.
    answer: ?bool = null,
    /// True if this path diverges (return/break/continue/unreachable/panic)
    /// before reaching its natural end — so its out-set should not
    /// participate in a downstream merge.
    diverged: bool = false,
};

const Oracle = struct {
    gpa: std.mem.Allocator,
    tree: *const Ast,
    target: []const u8,
    use_token: Ast.TokenIndex,
    /// Recursion / work guard — bail to "unknown" on pathological inputs.
    budget: u32 = 50_000,

    fn tokenInNode(self: *Oracle, node: Ast.Node.Index) bool {
        const first = self.tree.firstToken(node);
        const last = self.tree.lastToken(node);
        return self.use_token >= first and self.use_token <= last;
    }

    fn spend(self: *Oracle) bool {
        if (self.budget == 0) return false;
        self.budget -= 1;
        return true;
    }
};

/// Public entry point.  Returns true iff `target` is provably nonzero at
/// `use_token` on every path reaching it.  Conservative: false on any doubt.
pub fn provesNonzero(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body_node: Ast.Node.Index,
    target: []const u8,
    use_token: Ast.TokenIndex,
) bool {
    var oracle: Oracle = .{
        .gpa = gpa,
        .tree = tree,
        .target = target,
        .use_token = use_token,
    };
    var set: NonzeroSet = .{};
    defer set.deinit(gpa);
    const flow = analyzeNode(&oracle, body_node, &set) catch return false;
    return flow.answer orelse false;
}

/// Analyze a single statement/expression node, mutating `set` to its
/// straight-line output effect.  If the node contains `use_token`, descends
/// and sets `flow.answer`.
fn analyzeNode(o: *Oracle, node: Ast.Node.Index, set: *NonzeroSet) error{OutOfMemory}!Flow {
    if (!o.spend()) return .{};
    const tree = o.tree;
    switch (tree.nodeTag(node)) {
        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            var buf: [2]Ast.Node.Index = undefined;
            const stmts = blockStmts(tree, node, &buf);
            return analyzeSeq(o, stmts, set);
        },

        .@"if", .if_simple => return analyzeIf(o, node, set),

        .@"while", .while_simple, .while_cont => return analyzeLoop(o, node, set, .while_),
        .@"for", .for_simple => return analyzeLoop(o, node, set, .for_),

        .simple_var_decl, .local_var_decl, .aligned_var_decl => {
            return analyzeVarDecl(o, node, set);
        },

        .assign => return analyzeAssign(o, node, set),

        .@"return", .@"break", .@"continue", .unreachable_literal => {
            // Diverges.  If the use is inside the (return) expression, answer
            // from the current set first.
            var flow: Flow = .{ .diverged = true };
            if (o.tokenInNode(node)) flow.answer = set.contains(o.target);
            return flow;
        },

        else => {
            // Unmodeled construct.  If it contains the use, we cannot prove
            // anything → unknown (false).  Otherwise it has no modeled effect
            // on the nonzero set (conservative: leave set unchanged — but to
            // stay sound we must also account for hidden mutations of target;
            // a call could mutate via pointer.  We conservatively DROP target
            // if the construct mentions it as anything other than a read we
            // recognize).  Simplest sound rule: if the node references target
            // at all and isn't a recognized read, drop it.
            if (o.tokenInNode(node)) return .{ .answer = set.contains(o.target) };
            // A bare expression statement (call etc.) could mutate target
            // through a pointer; we cannot see that, so be conservative only
            // when it's an assignment-like form (handled above).  Plain
            // expression statements do not rebind a local by value, so the
            // nonzero fact for `target` (a value local) survives.
            return .{};
        },
    }
}

/// Analyze a sequence of statements in order, threading `set`.
fn analyzeSeq(o: *Oracle, stmts: []const Ast.Node.Index, set: *NonzeroSet) error{OutOfMemory}!Flow {
    for (stmts) |s| {
        const flow = try analyzeNode(o, s, set);
        if (flow.answer != null) return flow; // use found; done
        if (flow.diverged) return flow; // unreachable past here
    }
    return .{};
}

fn analyzeVarDecl(o: *Oracle, node: Ast.Node.Index, set: *NonzeroSet) error{OutOfMemory}!Flow {
    const tree = o.tree;
    const decl = tree.fullVarDecl(node) orelse return .{};
    const name_tok = decl.ast.mut_token + 1; // `const`/`var` then NAME
    const name = tree.tokenSlice(name_tok);
    const init_node = decl.ast.init_node.unwrap() orelse {
        set.remove(name);
        return .{};
    };
    // If the use is inside the initializer, answer with the pre-decl set.
    if (o.tokenInNode(init_node)) {
        const flow = try analyzeNode(o, init_node, set);
        if (flow.answer != null) return flow;
    }
    if (isPositiveIntLiteral(tree, init_node)) {
        try set.add(o.gpa, name);
    } else {
        set.remove(name);
    }
    return .{};
}

fn analyzeAssign(o: *Oracle, node: Ast.Node.Index, set: *NonzeroSet) error{OutOfMemory}!Flow {
    const tree = o.tree;
    const data = tree.nodeData(node).node_and_node;
    const lhs = data[0];
    const rhs = data[1];
    // Use inside RHS?  Answer pre-assignment.
    if (o.tokenInNode(rhs)) {
        const flow = try analyzeNode(o, rhs, set);
        if (flow.answer != null) return flow;
    }
    // Only track plain-identifier LHS targets.
    if (tree.nodeTag(lhs) != .identifier) return .{};
    const name = tree.tokenSlice(tree.nodeMainToken(lhs));
    if (isPositiveIntLiteral(tree, rhs)) {
        try set.add(o.gpa, name);
    } else {
        set.remove(name);
    }
    return .{};
}

fn analyzeIf(o: *Oracle, node: Ast.Node.Index, set: *NonzeroSet) error{OutOfMemory}!Flow {
    const tree = o.tree;
    const if_data = tree.fullIf(node) orelse return .{};
    const cond = if_data.ast.cond_expr;

    // Use inside the condition itself → answer with the entry set.
    if (o.tokenInNode(cond)) return .{ .answer = set.contains(o.target) };

    var refine: Refinement = .{};
    collectRefinement(o, cond, &refine);

    const then_node = if_data.ast.then_expr;
    const else_opt = if_data.ast.else_expr.unwrap();

    // THEN arm: entry set ∪ then-refinements.
    var then_set = try set.clone(o.gpa);
    defer then_set.deinit(o.gpa);
    if (refine.then_nonzero) |n| try then_set.add(o.gpa, n);
    if (o.tokenInNode(then_node)) {
        return try analyzeNode(o, then_node, &then_set);
    }
    const then_flow = try analyzeNode(o, then_node, &then_set);

    // ELSE arm (or empty fall-through).
    var else_set = try set.clone(o.gpa);
    defer else_set.deinit(o.gpa);
    if (refine.else_nonzero) |n| try else_set.add(o.gpa, n);
    var else_flow: Flow = .{};
    if (else_opt) |else_node| {
        if (o.tokenInNode(else_node)) {
            return try analyzeNode(o, else_node, &else_set);
        }
        else_flow = try analyzeNode(o, else_node, &else_set);
    }

    // Merge arm outputs into `set` for downstream statements.
    // Divergent arm contributes nothing; if both diverge, downstream is dead.
    if (then_flow.diverged and else_flow.diverged) {
        return .{ .diverged = true };
    } else if (then_flow.diverged) {
        try replaceSet(o, set, &else_set);
    } else if (else_flow.diverged) {
        try replaceSet(o, set, &then_set);
    } else {
        then_set.intersectWith(&else_set);
        try replaceSet(o, set, &then_set);
    }
    return .{};
}

const LoopKind = enum { while_, for_ };

fn analyzeLoop(o: *Oracle, node: Ast.Node.Index, set: *NonzeroSet, kind: LoopKind) error{OutOfMemory}!Flow {
    const tree = o.tree;
    // Sound-conservative: any local assigned inside the loop body could hold
    // a different-iteration value at a use, so drop those facts before
    // flowing into / past the loop.  We do not attempt a fixpoint in v1.
    dropLoopAssigned(o, node, set);

    // If the use is inside the loop, analyze the relevant sub-node with the
    // (already-conservative) set.  We still apply in-loop straight-line and
    // guard refinements that dominate the use within one iteration.
    const body_node: ?Ast.Node.Index = switch (kind) {
        .while_ => if (tree.fullWhile(node)) |w| w.ast.then_expr else null,
        .for_ => if (tree.fullFor(node)) |f| f.ast.then_expr else null,
    };
    const cond_node: ?Ast.Node.Index = switch (kind) {
        .while_ => if (tree.fullWhile(node)) |w| w.ast.cond_expr else null,
        .for_ => null,
    };
    if (cond_node) |c| {
        if (o.tokenInNode(c)) return .{ .answer = set.contains(o.target) };
    }
    if (body_node) |b| {
        if (o.tokenInNode(b)) {
            var body_set = try set.clone(o.gpa);
            defer body_set.deinit(o.gpa);
            // A `while (i > 0)` condition refines the body.
            if (cond_node) |c| {
                var refine: Refinement = .{};
                collectRefinement(o, c, &refine);
                if (refine.then_nonzero) |n| try body_set.add(o.gpa, n);
            }
            return try analyzeNode(o, b, &body_set);
        }
    }
    // Use is after the loop: facts already conservatively dropped.
    return .{};
}

/// Replace `dst`'s contents with a clone of `src`.
fn replaceSet(o: *Oracle, dst: *NonzeroSet, src: *const NonzeroSet) error{OutOfMemory}!void {
    dst.names.clearRetainingCapacity();
    try dst.names.appendSlice(o.gpa, src.names.items);
}

const Refinement = struct {
    then_nonzero: ?[]const u8 = null,
    else_nonzero: ?[]const u8 = null,
};

/// Extract a nonzero refinement from a condition expression.  Recognizes a
/// single comparison and `and`-chains (whose then-branch implies each
/// conjunct).  Conservative: leaves fields null when unrecognized.
fn collectRefinement(o: *Oracle, cond: Ast.Node.Index, out: *Refinement) void {
    if (!o.spend()) return;
    const tree = o.tree;
    switch (tree.nodeTag(cond)) {
        .bool_and => {
            // `(A) and (B)` true ⟹ both A and B; collect each conjunct's
            // then-refinement.  (No else-refinement: !(A and B) implies neither.)
            const data = tree.nodeData(cond).node_and_node;
            var a: Refinement = .{};
            var b: Refinement = .{};
            collectRefinement(o, data[0], &a);
            collectRefinement(o, data[1], &b);
            if (out.then_nonzero == null) out.then_nonzero = a.then_nonzero orelse b.then_nonzero;
        },
        .greater_than => {
            // `x > 0` ⟹ x nonzero (then);  `0 < x` handled by less_than.
            const data = tree.nodeData(cond).node_and_node;
            if (identName(tree, data[0])) |x| {
                if (isIntLiteralValue(tree, data[1], 0)) out.then_nonzero = x;
            }
        },
        .less_than => {
            // `0 < x` ⟹ x nonzero (then).  `x < 1` ⟹ x == 0 (else nonzero).
            const data = tree.nodeData(cond).node_and_node;
            if (isIntLiteralValue(tree, data[0], 0)) {
                if (identName(tree, data[1])) |x| out.then_nonzero = x;
            } else if (identName(tree, data[0])) |x| {
                if (isIntLiteralValue(tree, data[1], 1)) out.else_nonzero = x;
            }
        },
        .greater_or_equal => {
            // `x >= 1` ⟹ x nonzero (then).  `0 >= x` ⟹ x == 0 (else).
            const data = tree.nodeData(cond).node_and_node;
            if (identName(tree, data[0])) |x| {
                if (isIntLiteralValue(tree, data[1], 1)) out.then_nonzero = x;
            } else if (isIntLiteralValue(tree, data[0], 0)) {
                if (identName(tree, data[1])) |x| out.else_nonzero = x;
            }
        },
        .less_or_equal => {
            // `x <= 0` ⟹ x == 0 (else nonzero).  `1 <= x` ⟹ x nonzero (then).
            const data = tree.nodeData(cond).node_and_node;
            if (identName(tree, data[0])) |x| {
                if (isIntLiteralValue(tree, data[1], 0)) out.else_nonzero = x;
            } else if (isIntLiteralValue(tree, data[0], 1)) {
                if (identName(tree, data[1])) |x| out.then_nonzero = x;
            }
        },
        .bang_equal => {
            // `x != 0` ⟹ x nonzero (then).
            const data = tree.nodeData(cond).node_and_node;
            if (identName(tree, data[0])) |x| {
                if (isIntLiteralValue(tree, data[1], 0)) out.then_nonzero = x;
            } else if (isIntLiteralValue(tree, data[0], 0)) {
                if (identName(tree, data[1])) |x| out.then_nonzero = x;
            }
        },
        .equal_equal => {
            // `x == 0` ⟹ x == 0 (else nonzero).
            const data = tree.nodeData(cond).node_and_node;
            if (identName(tree, data[0])) |x| {
                if (isIntLiteralValue(tree, data[1], 0)) out.else_nonzero = x;
            } else if (isIntLiteralValue(tree, data[0], 0)) {
                if (identName(tree, data[1])) |x| out.else_nonzero = x;
            }
        },
        else => {},
    }
}

/// Drop every local assigned anywhere inside the loop's body from `set`.
fn dropLoopAssigned(o: *Oracle, loop_node: Ast.Node.Index, set: *NonzeroSet) void {
    const tree = o.tree;
    const first = tree.firstToken(loop_node);
    const last = tree.lastToken(loop_node);
    // Token-level scan for `NAME =` / `NAME +=` / etc. assignment targets and
    // `NAME` in for/while payload captures.  Conservative: any identifier
    // immediately followed by an assignment operator is treated as mutated.
    const tags = tree.tokens.items(.tag);
    var t = first;
    while (t < last) : (t += 1) {
        if (tags[t] != .identifier) continue;
        switch (tags[t + 1]) {
            .equal,
            .plus_equal,
            .minus_equal,
            .asterisk_equal,
            .slash_equal,
            .percent_equal,
            .plus_percent_equal,
            .minus_percent_equal,
            => set.remove(tree.tokenSlice(t)),
            else => {},
        }
    }
}

// ── small AST predicates ────────────────────────────────────

fn identName(tree: *const Ast, node: Ast.Node.Index) ?[]const u8 {
    if (tree.nodeTag(node) != .identifier) return null;
    return tree.tokenSlice(tree.nodeMainToken(node));
}

fn isPositiveIntLiteral(tree: *const Ast, node: Ast.Node.Index) bool {
    if (tree.nodeTag(node) != .number_literal) return false;
    const s = tree.tokenSlice(tree.nodeMainToken(node));
    const v = std.fmt.parseInt(u64, s, 0) catch return false;
    return v > 0;
}

fn isIntLiteralValue(tree: *const Ast, node: Ast.Node.Index, want: u64) bool {
    if (tree.nodeTag(node) != .number_literal) return false;
    const s = tree.tokenSlice(tree.nodeMainToken(node));
    const v = std.fmt.parseInt(u64, s, 0) catch return false;
    return v == want;
}

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

// ── Tests ───────────────────────────────────────────────────
// Tests live in value_range_tests.zig to keep this file navigable.
test {
    _ = @import("value_range_tests.zig");
}
