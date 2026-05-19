//! Transfer functions per StmtKind.  Each takes an AbstractState and a
//! Stmt, mutates the state to reflect the statement's effect, and may
//! emit zero or more Problems.
//!
//! Design rule: never abort on unknown shapes — `.lowering_gap` and
//! `.unknown` are conservative-fall-through.  Layer 2 should never make
//! the developer's life worse than no checker; false negatives on
//! exotic syntax are preferred over false positives.

const std = @import("std");
const problem_mod = @import("problem.zig");
const cfg = @import("cfg.zig");
const state_mod = @import("abstract_state.zig");

const Problem = problem_mod.Problem;
const Severity = problem_mod.Severity;
const Pos = problem_mod.Pos;

const Stmt = cfg.Stmt;
const StmtKind = cfg.StmtKind;
const ExprKind = cfg.ExprKind;
const LocalInfo = cfg.LocalInfo;

const AbstractState = state_mod.AbstractState;
const Origin = state_mod.Origin;
const ArenaId = state_mod.ArenaId;
const ArenaState = state_mod.ArenaState;
const LocalId = state_mod.LocalId;

pub const Ctx = struct {
    gpa: std.mem.Allocator,
    locals: []const LocalInfo,
    /// Counter for minting fresh ArenaIds at arena_init sites.  One per
    /// function — distinct arena_init sites get distinct IDs.
    next_arena: *u32,
    /// Counter for minting fresh AstIds at ast_init sites.  Parallel
    /// to next_arena.  Each `var tree = Ast.parse(...)` site gets a
    /// distinct AstId so that NodeIndex values tagged with that ID
    /// can be cross-checked against the destination Ast at use sites.
    next_ast: *u32,
    /// Where to push problems.
    problems: *std.ArrayListUnmanaged(Problem),
    /// Source file path for diagnostics.
    path: []const u8,
};

/// Mutate `state` to reflect the effect of `stmt`.  Emit any problems
/// (use-after-kill, missing-annotation issues) to `ctx.problems`.
pub fn transfer(ctx: Ctx, state: *AbstractState, stmt: Stmt) !void {
    switch (stmt.kind) {
        .decl => |d| try transferDecl(ctx, state, d, stmt.pos),
        .assign => |a| try transferAssign(ctx, state, a, stmt.pos),
        .arena_kill => |k| try transferArenaKill(ctx, state, k, stmt.pos),
        .thread_join => try transferThreadJoin(ctx, state, stmt.pos),
        .ret => |r| try transferRet(ctx, state, r, stmt.pos),
        .use => |u| try transferUse(ctx, state, u, stmt.pos),
        .ast_takes_check => |c| try transferAstTakesCheck(ctx, state, c, stmt.pos),
        .lowering_gap => |g| try transferGap(ctx, state, g, stmt.pos),
    }
}

fn transferAstTakesCheck(
    ctx: Ctx,
    state: *AbstractState,
    c: @TypeOf(@as(StmtKind, undefined).ast_takes_check),
    pos: cfg.SrcPos,
) !void {
    const src_origin = state.locals.get(c.source_local) orelse return;
    const val_origin = state.locals.get(c.value_local) orelse return;
    // We can only validate when BOTH sides are tagged.  If the source
    // isn't .ast(aid_src) or the value isn't .ast_node(aid_val), one
    // side's identity is unknown and we can't conclude mismatch.
    const aid_src: state_mod.AstId = switch (src_origin) {
        .ast => |a| a,
        else => return,
    };
    const aid_val: state_mod.AstId = switch (val_origin) {
        .ast_node => |a| a,
        else => return,
    };
    if (aid_src != aid_val) {
        try report(ctx, pos, .@"error",
            "`{s}` is a NodeIndex from a different Ast than `{s}` (invariant #1: NodeIndex must only flow back into its source Ast)",
            .{
                ctx.locals[@intFromEnum(c.value_local)].name,
                ctx.locals[@intFromEnum(c.source_local)].name,
            });
    }
}

fn transferDecl(
    ctx: Ctx,
    state: *AbstractState,
    d: @TypeOf(@as(StmtKind, undefined).decl),
    pos: cfg.SrcPos,
) !void {
    const origin = try originOfInit(ctx, state, d.init_kind, pos);
    try state.locals.put(ctx.gpa, d.local, origin);
}

fn transferAssign(
    ctx: Ctx,
    state: *AbstractState,
    a: @TypeOf(@as(StmtKind, undefined).assign),
    pos: cfg.SrcPos,
) !void {
    const origin = try originOfInit(ctx, state, a.rhs_kind, pos);
    try state.locals.put(ctx.gpa, a.target, origin);
}

fn transferArenaKill(
    ctx: Ctx,
    state: *AbstractState,
    k: @TypeOf(@as(StmtKind, undefined).arena_kill),
    pos: cfg.SrcPos,
) !void {
    // The local was bound to an arena_init somewhere; its origin tells
    // us which ArenaId died.
    const origin = state.locals.get(k.arena_local) orelse return;
    switch (origin) {
        .arena => |aid| {
            try state.arenas.put(ctx.gpa, aid, .{
                .state = .dead,
                .killed_at = pos.byte,
            });
        },
        else => {}, // not an arena local — receiver was misclassified
    }
}

fn transferThreadJoin(
    ctx: Ctx,
    state: *AbstractState,
    pos: cfg.SrcPos,
) !void {
    _ = ctx;
    _ = pos;
    state.thread = .joined;
}

fn transferRet(
    ctx: Ctx,
    state: *AbstractState,
    r: @TypeOf(@as(StmtKind, undefined).ret),
    pos: cfg.SrcPos,
) !void {
    // Only borrowed-shape return types can leak a borrowed origin.
    // Value-typed returns MOVE the value (and any arena it owns) to
    // the caller — that's idiomatic, not a bug.  Skip the check.
    if (!r.is_borrowed_return_type) return;

    const origin = try originOfInit(ctx, state, r.value_kind, pos);
    switch (origin) {
        .arena => |aid| {
            // Function-local arena that's about to die at exit — flag.
            if (state.arenas.contains(aid)) {
                try report(ctx, pos, .@"error",
                    "returning a value borrowed from a function-local arena (escapes its lifetime)", .{});
            }
        },
        else => {},
    }
}

fn transferUse(
    ctx: Ctx,
    state: *AbstractState,
    u: @TypeOf(@as(StmtKind, undefined).use),
    pos: cfg.SrcPos,
) !void {
    const origin = state.locals.get(u.local) orelse return;
    try checkOriginAlive(ctx, state, origin, pos, ctx.locals[@intFromEnum(u.local)].name);
}

fn transferGap(
    ctx: Ctx,
    state: *AbstractState,
    g: @TypeOf(@as(StmtKind, undefined).lowering_gap),
    pos: cfg.SrcPos,
) !void {
    _ = g;
    _ = pos;
    _ = ctx;
    // Conservative: collapse every local's origin to .plain — we don't
    // know what the gap statement did to them.  Arena liveness is
    // preserved (gaps shouldn't kill arenas — if they did, we'd model
    // them properly in cfg.zig).
    var it = state.locals.iterator();
    while (it.next()) |entry| entry.value_ptr.* = .plain;
}

/// Map an ExprKind (RHS classification) to the Origin it produces.
/// Emits a fresh ArenaId for arena_init.  copy_of follows through to
/// the source local's current origin.
fn originOfInit(
    ctx: Ctx,
    state: *const AbstractState,
    kind: ExprKind,
    pos: cfg.SrcPos,
) !Origin {
    _ = pos;
    return switch (kind) {
        .plain => .plain,
        .owned => .plain,
        .arena_init => blk: {
            const aid: ArenaId = @enumFromInt(ctx.next_arena.*);
            ctx.next_arena.* += 1;
            // Register the new arena as live immediately so we can
            // detect kills against it later.
            // The arena map is on AbstractState which is *const here —
            // caller (transferDecl) puts the result origin into a
            // local AND we need to register liveness.  Workaround:
            // caller registers in state.arenas after this call.
            // For now, we register here via const cast — bounded
            // because the only caller is transferDecl which already
            // owns a mutable state.
            const mut_state: *AbstractState = @constCast(state);
            try mut_state.arenas.put(ctx.gpa, aid, .{ .state = .live });
            break :blk .{ .arena = aid };
        },
        .borrowed_from => |src_local| state.locals.get(src_local) orelse .plain,
        .copy_of => |src_local| state.locals.get(src_local) orelse .plain,
        .ast_init => blk: {
            const aid = ctx.next_ast.*;
            ctx.next_ast.* += 1;
            break :blk .{ .ast = @enumFromInt(aid) };
        },
        .node_index_of => |src_local| blk: {
            // Look up the source arg's Ast identity.  Only locals
            // tagged `.ast(aid)` propagate a real ast_node tag.
            // Other origins (.plain, .arena, etc.) mean we lost the
            // Ast connection somewhere — return .plain so callers
            // can't get false-positive AstId matches downstream.
            const src_origin = state.locals.get(src_local) orelse break :blk .plain;
            switch (src_origin) {
                .ast => |aid| break :blk .{ .ast_node = aid },
                else => break :blk .plain,
            }
        },
        .unknown => .plain,
    };
}

/// Verify that the named origin is still live at the use point.  Emit
/// a problem if not.
fn checkOriginAlive(
    ctx: Ctx,
    state: *const AbstractState,
    origin: Origin,
    pos: cfg.SrcPos,
    local_name: []const u8,
) !void {
    switch (origin) {
        .arena => |aid| {
            const st = state.arenas.get(aid) orelse return;
            if (st.state == .dead) {
                try report(ctx, pos, .@"error",
                    "`{s}` borrows from an arena that was deinit'd at byte {?}",
                    .{ local_name, st.killed_at });
            }
        },
        else => {}, // other origin classes don't have liveness yet
    }
}

fn report(
    ctx: Ctx,
    pos: cfg.SrcPos,
    severity: Severity,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const msg = try std.fmt.allocPrint(ctx.gpa, fmt, args);
    try ctx.problems.append(ctx.gpa, .{
        .rule_id = "ez/escape-check",
        .severity = severity,
        .start = .{ .line = pos.line, .column = pos.column, .byte = pos.byte },
        .end = .{ .line = pos.line, .column = pos.column + 1, .byte = pos.byte + 1 },
        .message = msg,
    });
}
