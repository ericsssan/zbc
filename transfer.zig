//! Transfer functions per StmtKind.  Each takes an AbstractState and a
//! Stmt, mutates the state to reflect the statement's effect, and may
//! emit Problems.
//!
//! Design rule: never abort on unknown shapes — `.lowering_gap` and
//! `.unknown` are conservative-fall-through.  False negatives on
//! exotic syntax are preferred over false positives.

const std = @import("std");
const problem_mod = @import("problem.zig");
const cfg = @import("cfg.zig");
const state_mod = @import("abstract_state.zig");
const config_mod = @import("config.zig");

const Problem = problem_mod.Problem;
const Severity = problem_mod.Severity;

const Stmt = cfg.Stmt;
const StmtKind = cfg.StmtKind;
const ExprKind = cfg.ExprKind;
const LocalInfo = cfg.LocalInfo;

const AbstractState = state_mod.AbstractState;
const Origin = state_mod.Origin;
const LocalId = state_mod.LocalId;

pub const Ctx = struct {
    gpa: std.mem.Allocator,
    locals: []const LocalInfo,
    /// Where to push problems.
    problems: *std.ArrayListUnmanaged(Problem),
    /// Source file path for diagnostics.
    path: []const u8,
    /// Invariant gating.  Some checks run inside transfer (arena_escape
    /// fires from transferRet, not from a dedicated Stmt) — those
    /// consult the config to honor Config.enabled.
    config: *const config_mod.Config = &config_mod.Default,
};

/// Mutate `state` to reflect the effect of `stmt`.  Emit any problems
/// to `ctx.problems`.
pub fn transfer(ctx: Ctx, state: *AbstractState, stmt: Stmt) !void {
    switch (stmt.kind) {
        .decl => |d| try transferDecl(ctx, state, d, stmt.pos),
        .assign => |a| try transferAssign(ctx, state, a, stmt.pos),
        .arena_kill => |k| try transferArenaKill(ctx, state, k, stmt.pos),
        .heap_free => |f| try transferHeapFree(ctx, state, f, stmt.pos, stmt.end_pos),
        .ret => |r| try transferRet(ctx, state, r, stmt.pos, stmt.end_pos),
        .use => |u| try transferUse(ctx, state, u, stmt.pos, stmt.end_pos),
        .pointer_write => |p| {
            if (state.locals.get(p.target)) |origin| {
                if (origin == .undef) try state.locals.put(ctx.gpa, p.target, .plain);
            }
        },
        .composite_escape => |c| try transferCompositeEscape(ctx, state, c, stmt.pos, stmt.end_pos),
        .field_assign => |a| try transferFieldAssign(ctx, state, a, stmt.pos),
        .field_heap_free => |f| try transferFieldHeapFree(ctx, state, f, stmt.pos, stmt.end_pos),
        .field_use => |u| try transferFieldUse(ctx, state, u, stmt.pos, stmt.end_pos),
        .lowering_gap => |g| try transferGap(ctx, state, g, stmt.pos),
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
    const origin = state.locals.get(k.arena_local) orelse return;
    switch (origin) {
        .arena => |aid| {
            try state.arenas.put(ctx.gpa, aid, .{
                .state = .dead,
                .killed_at = pos.byte,
            });
        },
        else => {},
    }
}

fn transferHeapFree(
    ctx: Ctx,
    state: *AbstractState,
    f: @TypeOf(@as(StmtKind, undefined).heap_free),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    const origin = state.locals.get(f.freed_local) orelse return;
    switch (origin) {
        .heap => |hid| {
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                if (config_mod.isEnabled(ctx.config, .heap_double_free)) {
                    const name = ctx.locals[@intFromEnum(f.freed_local)].name;
                    try report(ctx, pos, end_pos, .@"error",
                        "double-free of `{s}` (previously freed at byte {?})",
                        .{ name, st.killed_at });
                }
                return;
            }
            try state.heaps.put(ctx.gpa, hid, .{
                .state = .dead,
                .killed_at = pos.byte,
            });
        },
        else => {},
    }
}

fn transferRet(
    ctx: Ctx,
    state: *AbstractState,
    r: @TypeOf(@as(StmtKind, undefined).ret),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    // Only borrowed-shape return types can leak a borrowed origin.
    // Value-typed returns MOVE the value (and any arena it owns) to
    // the caller — that's idiomatic, not a bug.
    const origin = try originOfInit(ctx, state, r.value_kind, pos);

    // Undefined-return check: not gated on return type — returning
    // garbage is wrong for value types and pointers alike.
    //
    // EXCEPTION: literal `return undefined;` — the author explicitly
    // typed the keyword as the return value, almost always as a
    // comptime-gated sentinel for paths the caller is guaranteed not
    // to use (bindgen stubs, comptime-disabled features).  The real
    // bug class — undef leaking through a variable — still fires
    // because that path produces .undef via an identifier expr, which
    // doesn't set is_literal_undef.
    if (origin == .undef and !r.is_literal_undef and
        config_mod.isEnabled(ctx.config, .use_undefined))
    {
        try report(ctx, pos, end_pos, .@"error",
            "returning a value that is still `undefined`", .{});
        return;
    }

    // Stack escape isn't gated on return type — a value-shape return
    // can still embed a pointer to a stack local (e.g. `return .{
    // .p = &x }`).  Unlike arenas (which can move), stack storage
    // always dies with the frame, so any .stack origin reaching ret
    // is wrong regardless of the outer return type.
    if (origin == .stack and config_mod.isEnabled(ctx.config, .stack_escape)) {
        const name = ctx.locals[@intFromEnum(origin.stack)].name;
        if (r.is_borrowed_return_type) {
            try report(ctx, pos, end_pos, .@"error",
                "returning a pointer to a function-local stack variable `{s}` (escapes its frame)", .{name});
        } else {
            try report(ctx, pos, end_pos, .@"error",
                "returning a value that holds a pointer to function-local stack variable `{s}` (escapes its frame)", .{name});
        }
        return;
    }

    // Composite-borrow returns: the embedded local is a borrow
    // regardless of the outer return type, so apply escape checks
    // unconditionally.  Direct borrow-shape returns (`return &x`,
    // `return arena.text()`) still go through the existing
    // is_borrowed_return_type gate.
    const is_composite = r.value_kind == .composite_borrow;
    const apply_check = r.is_borrowed_return_type or is_composite;
    if (!apply_check) return;
    switch (origin) {
        .arena, .arena_borrow => |aid| {
            if (!config_mod.isEnabled(ctx.config, .arena_escape)) return;
            if (state.arenas.contains(aid)) {
                if (is_composite) {
                    try report(ctx, pos, end_pos, .@"error",
                        "returning a value that holds a borrow from function-local arena (escapes its lifetime)", .{});
                } else {
                    try report(ctx, pos, end_pos, .@"error",
                        "returning a value borrowed from a function-local arena (escapes its lifetime)", .{});
                }
            }
        },
        .heap => |hid| {
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                try report(ctx, pos, end_pos, .@"error",
                    "returning a heap pointer after free (freed at byte {?})",
                    .{st.killed_at});
            }
        },
        else => {},
    }
}

fn transferFieldAssign(
    ctx: Ctx,
    state: *AbstractState,
    a: @TypeOf(@as(StmtKind, undefined).field_assign),
    pos: cfg.SrcPos,
) !void {
    const origin = try originOfInit(ctx, state, a.rhs_kind, pos);
    const key: state_mod.FieldKey = .{ .parent = a.parent, .name = a.name };
    try state.fields.putContext(ctx.gpa, key, origin, .{});

    // Field assignment initializes the parent (partially).  Clear
    // the parent's .undef so `var x = undefined; x.field = val;
    // return x;` doesn't fire spuriously — common Zig idiom.
    if (state.locals.get(a.parent)) |parent_origin| {
        if (parent_origin == .undef) {
            try state.locals.put(ctx.gpa, a.parent, .plain);
        }
    }
}

fn transferFieldHeapFree(
    ctx: Ctx,
    state: *AbstractState,
    f: @TypeOf(@as(StmtKind, undefined).field_heap_free),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    const key: state_mod.FieldKey = .{ .parent = f.parent, .name = f.name };
    const origin = state.fields.getContext(key, .{}) orelse return;
    switch (origin) {
        .heap => |hid| {
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                if (config_mod.isEnabled(ctx.config, .heap_double_free)) {
                    const parent_name = ctx.locals[@intFromEnum(f.parent)].name;
                    try report(ctx, pos, end_pos, .@"error",
                        "double-free of `{s}.{s}` (previously freed at byte {?})",
                        .{ parent_name, f.name, st.killed_at });
                }
                return;
            }
            try state.heaps.put(ctx.gpa, hid, .{
                .state = .dead,
                .killed_at = pos.byte,
            });
        },
        else => {},
    }
}

fn transferFieldUse(
    ctx: Ctx,
    state: *AbstractState,
    u: @TypeOf(@as(StmtKind, undefined).field_use),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    const key: state_mod.FieldKey = .{ .parent = u.parent, .name = u.name };
    const origin = state.fields.getContext(key, .{}) orelse return;
    const parent_name = ctx.locals[@intFromEnum(u.parent)].name;
    switch (origin) {
        .arena, .arena_borrow => |aid| {
            if (!config_mod.isEnabled(ctx.config, .arena_use_after_kill)) return;
            const st = state.arenas.get(aid) orelse return;
            if (st.state == .dead) {
                try report(ctx, pos, end_pos, .@"error",
                    "`{s}.{s}` borrows from an arena that was deinit'd at byte {?}",
                    .{ parent_name, u.name, st.killed_at });
            }
        },
        .heap => |hid| {
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                try report(ctx, pos, end_pos, .@"error",
                    "use of `{s}.{s}` after free (freed at byte {?})",
                    .{ parent_name, u.name, st.killed_at });
            }
        },
        .undef => {
            if (!config_mod.isEnabled(ctx.config, .use_undefined)) return;
            try report(ctx, pos, end_pos, .@"error",
                "use of `{s}.{s}` while still `undefined`", .{ parent_name, u.name });
        },
        else => {},
    }
}

/// Composite-escape check: fires the same escape diagnostics as
/// transferRet would for a value-shape composite return embedding
/// this local.  Used for the SECOND, third, ... borrow in a
/// multi-borrow composite — the first is handled by the surrounding
/// .ret's value_kind.
fn transferCompositeEscape(
    ctx: Ctx,
    state: *AbstractState,
    c: @TypeOf(@as(StmtKind, undefined).composite_escape),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    _ = state;
    // Walker only emits this stmt for `&local` / `array[..]`
    // patterns — those are stack borrows by construction.  Don't
    // consult state.locals: the address-of-write rule already
    // collapsed the local's origin to .plain before we get here.
    if (!config_mod.isEnabled(ctx.config, .stack_escape)) return;
    const name = ctx.locals[@intFromEnum(c.local)].name;
    try report(ctx, pos, end_pos, .@"error",
        "returning a value that holds a pointer to function-local stack variable `{s}` (escapes its frame)", .{name});
}

fn transferUse(
    ctx: Ctx,
    state: *AbstractState,
    u: @TypeOf(@as(StmtKind, undefined).use),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    const origin = state.locals.get(u.local) orelse return;
    // Method-call on a still-undef local: not a read of garbage,
    // it's the conventional init pattern (`var x: T = undefined;
    // x.decodeInternal(...);`).  Treat as a write that clears
    // .undef → .plain, suppressing the spurious use_undefined.
    // For .heap / .arena / .stack origins the call IS a real
    // use — fall through to the normal liveness check.
    if (u.from_method_call and origin == .undef) {
        try state.locals.put(ctx.gpa, u.local, .plain);
        return;
    }
    try checkOriginAlive(ctx, state, origin, pos, end_pos, ctx.locals[@intFromEnum(u.local)].name);
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
    // Conservative: collapse .undef → .plain since an unknown stmt
    // may have written through a passed pointer to initialize the
    // local.  But PRESERVE resource origins (.heap, .arena,
    // .arena_borrow, .stack_ref) — an unknown call can't free a
    // tracked allocation or kill an arena unless it matches a free /
    // arena-kill pattern (in which case cfg lowers it as the proper
    // op, not a gap).  Without this preservation, a single
    // `foo(args)` between `alloc(args)` and `free(args)` wipes the
    // .heap origin and defeats double-free / use-after-free tracking
    // for the rest of the function.
    var it = state.locals.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == .undef) entry.value_ptr.* = .plain;
    }
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
        .arena_init => |aid| blk: {
            // OVERWRITE to .live on every visit — the decl represents
            // a fresh resource at this call site.  Inside a loop,
            // back-edges propagate dead state from a prior iteration's
            // free back to the body's start; without this reset, the
            // fresh allocation would inherit that stale dead state and
            // spurious UAF would fire on later uses.
            const mut_state: *AbstractState = @constCast(state);
            try mut_state.arenas.put(ctx.gpa, aid, .{ .state = .live });
            break :blk .{ .arena = aid };
        },
        .stack_ref => |src_local| .{ .stack = src_local },
        .composite_borrow => |src_local| state.locals.get(src_local) orelse .plain,
        .heap_alloc => |hid| blk: {
            const mut_state: *AbstractState = @constCast(state);
            try mut_state.heaps.put(ctx.gpa, hid, .{ .state = .live });
            break :blk .{ .heap = hid };
        },
        .undef => .undef,
        .borrowed_from => |src_local| state.locals.get(src_local) orelse .plain,
        .copy_of => |src_local| blk: {
            const src_origin = state.locals.get(src_local) orelse break :blk .plain;
            // A copy / view of an .arena (the arena itself) yields a
            // BORROW, not a second reference to the arena identity.
            // Without this, `dep.deinit()` on a derived list would
            // kill the underlying arena.
            if (src_origin == .arena) break :blk .{ .arena_borrow = src_origin.arena };
            break :blk src_origin;
        },
        .field_copy_of => |fc| blk: {
            const key: state_mod.FieldKey = .{ .parent = fc.parent, .name = fc.name };
            break :blk state.fields.getContext(key, .{}) orelse .plain;
        },
        .unknown => .plain,
    };
}

/// Verify that the named origin is still live at the use point.
fn checkOriginAlive(
    ctx: Ctx,
    state: *const AbstractState,
    origin: Origin,
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
    local_name: []const u8,
) !void {
    switch (origin) {
        .arena, .arena_borrow => |aid| {
            if (!config_mod.isEnabled(ctx.config, .arena_use_after_kill)) return;
            const st = state.arenas.get(aid) orelse return;
            if (st.state == .dead) {
                try report(ctx, pos, end_pos, .@"error",
                    "`{s}` borrows from an arena that was deinit'd at byte {?}",
                    .{ local_name, st.killed_at });
            }
        },
        .heap => |hid| {
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                try report(ctx, pos, end_pos, .@"error",
                    "use of `{s}` after free (freed at byte {?})",
                    .{ local_name, st.killed_at });
            }
        },
        .undef => {
            if (!config_mod.isEnabled(ctx.config, .use_undefined)) return;
            try report(ctx, pos, end_pos, .@"error",
                "use of `{s}` while still `undefined`", .{local_name});
        },
        else => {},
    }
}

fn report(
    ctx: Ctx,
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
    severity: Severity,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const msg = try std.fmt.allocPrint(ctx.gpa, fmt, args);
    const real_end: cfg.SrcPos = if (end_pos.byte > pos.byte)
        end_pos
    else
        .{ .line = pos.line, .column = pos.column + 1, .byte = pos.byte + 1 };
    try ctx.problems.append(ctx.gpa, .{
        .rule_id = "zbc/escape-check",
        .severity = severity,
        .start = .{ .line = pos.line, .column = pos.column, .byte = pos.byte },
        .end = .{ .line = real_end.line, .column = real_end.column, .byte = real_end.byte },
        .message = msg,
    });
}
