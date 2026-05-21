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
        .arena_kill => |k| try transferArenaKill(ctx, state, k, stmt.pos, stmt.end_pos),
        .heap_free => |f| try transferHeapFree(ctx, state, f, stmt.pos, stmt.end_pos),
        .ret => |r| try transferRet(ctx, state, r, stmt.pos, stmt.end_pos),
        .use => |u| try transferUse(ctx, state, u, stmt.pos, stmt.end_pos),
        .pointer_write => |p| {
            if (state.locals.get(p.target)) |origin| {
                if (origin == .undef) try state.locals.put(ctx.gpa, p.target, .plain);
            }
        },
        .reset_capture => |r| {
            try state.locals.put(ctx.gpa, r.local, .plain);
            // Also clear any tracked FIELD origins for this local —
            // `for (bins) |bin| ctx.allocator.free(bin.path);` frees
            // `bin.path` once per iteration; without clearing the
            // field, iter N+1 sees iter N's freed state and reports
            // a spurious double-free of `bin.path`.
            var i: usize = 0;
            while (i < state.fields.count()) {
                const key = state.fields.keys()[i];
                if (key.parent == r.local) {
                    state.fields.swapRemoveAt(i);
                } else {
                    i += 1;
                }
            }
        },
        .composite_escape => |c| try transferCompositeEscape(ctx, state, c, stmt.pos, stmt.end_pos),
        .field_assign => |a| try transferFieldAssign(ctx, state, a, stmt.pos),
        .field_heap_free => |f| try transferFieldHeapFree(ctx, state, f, stmt.pos, stmt.end_pos),
        .field_use => |u| try transferFieldUse(ctx, state, u, stmt.pos, stmt.end_pos),
        .out_param_write => |w| try transferOutParamWrite(ctx, state, w, stmt.pos, stmt.end_pos),
        .interior_pointer_destroy => |i| try transferInteriorPointerDestroy(ctx, state, i, stmt.pos, stmt.end_pos),
        .leak_warning => |l| try transferLeakWarning(ctx, l, stmt.pos, stmt.end_pos),
        .partial_union_write => |p| try transferPartialUnionWrite(ctx, p, stmt.pos, stmt.end_pos),
        .lowering_gap => |g| try transferGap(ctx, state, g, stmt.pos),
    }
}

fn transferLeakWarning(
    ctx: Ctx,
    l: @TypeOf(@as(StmtKind, undefined).leak_warning),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    if (!config_mod.isEnabled(ctx.config, .heap_leak)) return;
    try report(ctx, "heap-leak", pos, end_pos, .@"error",
        "destructor for `{s}` does not free `self` — instances allocated by the type's heap-creator leak (no `allocator.destroy(self)` reachable from this destructor)",
        .{l.type_name});
}

fn transferPartialUnionWrite(
    ctx: Ctx,
    p: @TypeOf(@as(StmtKind, undefined).partial_union_write),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    if (!config_mod.isEnabled(ctx.config, .partial_union_write)) return;
    try report(ctx, "partial-union-write", pos, end_pos, .@"error",
        "tagged-union literal writes the `.{s}` tag before evaluating its payload; an early-exit (`try` / `catch return`) in the payload leaves the LHS with the new tag and stale/garbage payload bytes — hoist the fallible expression into a local first",
        .{p.tag_name});
}

fn transferInteriorPointerDestroy(
    ctx: Ctx,
    state: *AbstractState,
    i: @TypeOf(@as(StmtKind, undefined).interior_pointer_destroy),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    _ = state;
    if (!config_mod.isEnabled(ctx.config, .interior_pointer_destroy)) return;
    const receiver_name = ctx.locals[@intFromEnum(i.receiver)].name;
    const container_name = ctx.locals[@intFromEnum(i.container)].name;
    try report(ctx, "interior-pointer-destroy", pos, end_pos, .@"error",
        "destroying `{s}` — an interior pointer into `{s}` — is undefined behavior under typical allocators (the pointer wasn't returned by allocator.create)",
        .{ receiver_name, container_name });
}

fn transferDecl(
    ctx: Ctx,
    state: *AbstractState,
    d: @TypeOf(@as(StmtKind, undefined).decl),
    pos: cfg.SrcPos,
) !void {
    const origin = try originOfInit(ctx, state, d.init_kind, pos);
    try state.locals.put(ctx.gpa, d.local, origin);
    // Clear any stale field state for this local — a fresh decl
    // (e.g. `const source = ...` inside a loop body) creates a new
    // instance; prior-iteration field tracking for the same LocalId
    // is a back-edge artifact that would spuriously fire double-free
    // / UAF on the new instance.
    var i: usize = 0;
    while (i < state.fields.count()) {
        const key = state.fields.keys()[i];
        if (key.parent == d.local) {
            state.fields.swapRemoveAt(i);
        } else {
            i += 1;
        }
    }
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
    end_pos: cfg.SrcPos,
) !void {
    const origin = state.locals.get(k.arena_local) orelse return;
    switch (origin) {
        .arena => |aid| {
            try state.arenas.put(ctx.gpa, aid, .{
                .state = .dead,
                .killed_at = killSiteOf(pos, end_pos),
            });
        },
        else => {},
    }
}

/// Separator between a parent local name and its field path in
/// diagnostic messages.  Field paths starting with `[` (subscript
/// like "[0].field") want no dot — `arr[0].field` not
/// `arr.[0].field`.  Field paths starting with an ident want a `.`
/// for readability — `obj.field` not `objfield`.
fn pathSep(name: []const u8) []const u8 {
    if (name.len > 0 and name[0] == '[') return "";
    return ".";
}

fn killSiteOf(pos: cfg.SrcPos, end_pos: cfg.SrcPos) state_mod.KillSite {
    return .{
        .line = pos.line,
        .column = pos.column,
        .byte = pos.byte,
        .end_line = end_pos.line,
        .end_column = end_pos.column,
        .end_byte = end_pos.byte,
    };
}

fn transferHeapFree(
    ctx: Ctx,
    state: *AbstractState,
    f: @TypeOf(@as(StmtKind, undefined).heap_free),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    if (state.locals.get(f.freed_local)) |origin| {
        switch (origin) {
            .heap => |hid| {
                const st = state.heaps.get(hid) orelse return;
                if (st.state == .dead) {
                    if (config_mod.isEnabled(ctx.config, .heap_double_free)) {
                        const name = ctx.locals[@intFromEnum(f.freed_local)].name;
                        try reportWithNote(ctx, "heap-double-free", pos, end_pos, .@"error",
                            "double-free of `{s}`",
                            .{name},
                            if (st.killed_at) |ks|
                                .{ .site = ks, .label = "first freed here" }
                            else
                                null);
                    }
                    return;
                }
                // Allocator-mismatch check.  Only fire when BOTH
                // sides resolve to a known local AND those locals
                // differ.  Same-local: definitely-same allocator;
                // either-side-null: unknown, no fire.  Different
                // locals: possible mismatch (might be aliased via
                // `var a2 = a;` but we accept that conservative FP
                // class — the user can rebind or skip the check).
                if (st.allocator_local != null and f.allocator_local != null and
                    st.allocator_local.? != f.allocator_local.?)
                {
                    if (config_mod.isEnabled(ctx.config, .allocator_mismatch)) {
                        const freed_name = ctx.locals[@intFromEnum(f.freed_local)].name;
                        const alloc_alloc = ctx.locals[@intFromEnum(st.allocator_local.?)].name;
                        const free_alloc = ctx.locals[@intFromEnum(f.allocator_local.?)].name;
                        try report(ctx, "allocator-mismatch", pos, end_pos, .@"error",
                            "`{s}` was allocated by `{s}` but freed by `{s}` — allocators must match",
                            .{ freed_name, alloc_alloc, free_alloc });
                    }
                    return;
                }
                try state.heaps.put(ctx.gpa, hid, .{
                    .state = .dead,
                    .killed_at = killSiteOf(pos, end_pos),
                    .allocator_local = st.allocator_local,
                });
                return;
            },
            .plain, .undef => {
                // Fall through to fallback below — plain/undef
                // means we have no tracked heap id, but the @takes
                // annotation says callee took ownership, so any
                // subsequent use of this local is UB.
            },
            else => return, // .arena, .arena_borrow, .stack — not a free target
        }
    }
    // Inter-procedural fallback: local has no tracked .heap origin
    // (e.g. it's a `*T` parameter whose allocation happened in the
    // caller).  The @takes ownership annotation tells us the callee
    // freed it; record via fallback_hid so subsequent uses fire UAF.
    try state.heaps.put(ctx.gpa, f.fallback_hid, .{
        .state = .dead,
        .killed_at = killSiteOf(pos, end_pos),
        .is_inter_procedural = true,
    });
    try state.locals.put(ctx.gpa, f.freed_local, .{ .heap = f.fallback_hid });
}

fn transferRet(
    ctx: Ctx,
    state: *AbstractState,
    r: @TypeOf(@as(StmtKind, undefined).ret),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    try transferRetValueChecks(ctx, state, r, pos, end_pos);
    try transferRetOutParamDanglingHeaps(ctx, state, pos, end_pos);
}

/// At function exit, scan `state.out_param_writes` for entries
/// whose recorded HeapId is now dead.  Fires when a value written
/// through a `*T` parameter is freed (typically via `defer`) before
/// the function returns — the caller's pointee dangles.  Closes the
/// oven-sh/bun#30151-shape gap:
///
///     defer buf.deinit();
///     out.* = buf.slice();      // at write time buf is live
///     return;                    // at return defer fires → buf dead
fn transferRetOutParamDanglingHeaps(
    ctx: Ctx,
    state: *AbstractState,
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
    for (state.out_param_writes.keys(), state.out_param_writes.values()) |out_local, hid| {
        const st = state.heaps.get(hid) orelse continue;
        if (st.state != .dead) continue;
        const out_name = ctx.locals[@intFromEnum(out_local)].name;
        try reportWithNote(ctx, "heap-use-after-free", pos, end_pos, .@"error",
            "value written through `{s}` was freed before return — caller's pointee dangles",
            .{out_name},
            if (st.killed_at) |ks|
                .{ .site = ks, .label = "value freed here" }
            else
                null);
    }
}

fn transferRetValueChecks(
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
        try report(ctx, "use-undefined", pos, end_pos, .@"error",
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
            try report(ctx, "stack-escape", pos, end_pos, .@"error",
                "returning a pointer to a function-local stack variable `{s}` (escapes its frame)", .{name});
        } else {
            try report(ctx, "stack-escape", pos, end_pos, .@"error",
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
                    try report(ctx, "arena-escape", pos, end_pos, .@"error",
                        "returning a value that holds a borrow from function-local arena (escapes its lifetime)", .{});
                } else {
                    try report(ctx, "arena-escape", pos, end_pos, .@"error",
                        "returning a value borrowed from a function-local arena (escapes its lifetime)", .{});
                }
            }
        },
        .heap => |hid| {
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                try reportWithNote(ctx, "heap-use-after-free", pos, end_pos, .@"error",
                    "returning a heap pointer after free", .{},
                    if (st.killed_at) |ks|
                        .{ .site = ks, .label = "value freed here" }
                    else
                        null);
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
    if (state.fields.getContext(key, .{})) |origin| {
        switch (origin) {
            .heap => |hid| {
                const st = state.heaps.get(hid) orelse return;
                if (st.state == .dead) {
                    if (config_mod.isEnabled(ctx.config, .heap_double_free)) {
                        const parent_name = ctx.locals[@intFromEnum(f.parent)].name;
                        try reportWithNote(ctx, "heap-double-free", pos, end_pos, .@"error",
                            "double-free of `{s}{s}{s}`",
                            .{ parent_name, pathSep(f.name), f.name },
                            if (st.killed_at) |ks|
                                .{ .site = ks, .label = "first freed here" }
                            else
                                null);
                    }
                    return;
                }
                try state.heaps.put(ctx.gpa, hid, .{
                    .state = .dead,
                    .killed_at = killSiteOf(pos, end_pos),
                });
                return;
            },
            else => {},
        }
    }
    // Inter-procedural fallback: field had no prior tracked alloc
    // (e.g. it was allocated by the caller before passing `*T` in).
    // Use the cfg-minted fallback_hid to record the free so later
    // .field_use reads on the same field flag UAF.
    try state.heaps.put(ctx.gpa, f.fallback_hid, .{
        .state = .dead,
        .killed_at = killSiteOf(pos, end_pos),
        .is_inter_procedural = true,
    });
    try state.fields.putContext(ctx.gpa, key, .{ .heap = f.fallback_hid }, .{});
}

fn transferFieldUse(
    ctx: Ctx,
    state: *AbstractState,
    u: @TypeOf(@as(StmtKind, undefined).field_use),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    // Parent-liveness check, gated on inter-procedural origin:
    // `h.x` after `h` was freed via a @takes-ownership call IS a
    // UAF regardless of whether `h.x` itself was tracked.  Only
    // fire when the parent's freed state came from the
    // inter-procedural fallback — regular alloc+free pairs already
    // track their own field state, and would otherwise cascade
    // back-edge FPs across loop iterations.
    if (state.locals.get(u.parent)) |parent_origin| switch (parent_origin) {
        .heap => |hid| {
            const st = state.heaps.get(hid);
            if (st) |s| if (s.state == .dead and s.is_inter_procedural) {
                if (config_mod.isEnabled(ctx.config, .heap_use_after_free)) {
                    const parent_name = ctx.locals[@intFromEnum(u.parent)].name;
                    try reportWithNote(ctx, "heap-use-after-free", pos, end_pos, .@"error",
                        "use of `{s}` after free", .{parent_name},
                        if (s.killed_at) |ks|
                            .{ .site = ks, .label = "value freed here" }
                        else
                            null);
                }
                return;
            };
        },
        else => {},
    };
    const key: state_mod.FieldKey = .{ .parent = u.parent, .name = u.name };
    const origin = state.fields.getContext(key, .{}) orelse return;
    const parent_name = ctx.locals[@intFromEnum(u.parent)].name;
    switch (origin) {
        .arena, .arena_borrow => |aid| {
            if (!config_mod.isEnabled(ctx.config, .arena_use_after_kill)) return;
            const st = state.arenas.get(aid) orelse return;
            if (st.state == .dead) {
                try reportWithNote(ctx, "arena-use-after-kill", pos, end_pos, .@"error",
                    "`{s}{s}{s}` borrows from an arena that was deinit'd",
                    .{ parent_name, pathSep(u.name), u.name },
                    if (st.killed_at) |ks|
                        .{ .site = ks, .label = "arena deinit'd here" }
                    else
                        null);
            }
        },
        .heap => |hid| {
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                try reportWithNote(ctx, "heap-use-after-free", pos, end_pos, .@"error",
                    "use of `{s}{s}{s}` after free",
                    .{ parent_name, pathSep(u.name), u.name },
                    if (st.killed_at) |ks|
                        .{ .site = ks, .label = "value freed here" }
                    else
                        null);
            }
        },
        .undef => {
            if (!config_mod.isEnabled(ctx.config, .use_undefined)) return;
            try report(ctx, "use-undefined", pos, end_pos, .@"error",
                "use of `{s}{s}{s}` while still `undefined`",
                .{ parent_name, pathSep(u.name), u.name });
        },
        .stack => |owner_id| {
            // Field borrows from a stack owner — mirrors the .stack
            // arm in checkOriginAlive.  When the field carries an
            // owner-borrow origin (set via classifyExpr's @borrowed-
            // field route, or via struct-literal unpack of a
            // borrowed-field read), a kill of the owner invalidates
            // this read.
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const owner_origin = state.locals.get(owner_id) orelse return;
            switch (owner_origin) {
                .heap => |hid| {
                    const st = state.heaps.get(hid) orelse return;
                    if (st.state == .dead) {
                        try reportWithNote(ctx, "heap-use-after-free", pos, end_pos, .@"error",
                            "use of `{s}{s}{s}` (borrow from `{s}`) after free",
                            .{ parent_name, pathSep(u.name), u.name, ctx.locals[@intFromEnum(owner_id)].name },
                            if (st.killed_at) |ks|
                                .{ .site = ks, .label = "value freed here" }
                            else
                                null);
                    }
                },
                else => {},
            }
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
    try report(ctx, "stack-escape", pos, end_pos, .@"error",
        "returning a value that holds a pointer to function-local stack variable `{s}` (escapes its frame)", .{name});
}

/// Write-through-pointer escape check.  `out.* = X` (or
/// `out.field = X` where `out` is `*T`) makes whatever `X`'s
/// origin is reachable from caller-owned storage.  If that origin
/// is a function-local arena / stack reference, the lifetime
/// ends with this frame — surface the same arena-escape /
/// stack-escape diagnostics that fire at `return`.
///
/// Heap origins are left alone here: heap allocations are
/// owned-and-transferable, so writing one to caller-storage is
/// legitimate (the canonical out-param return-allocator pattern).
/// The case where a heap allocation is freed via `defer` BEFORE
/// the function returns — and the write therefore leaves a
/// dangling caller pointer — needs a deferred check at fn exit
/// that this pass doesn't do yet.
fn transferOutParamWrite(
    ctx: Ctx,
    state: *AbstractState,
    w: @TypeOf(@as(StmtKind, undefined).out_param_write),
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
) !void {
    const origin = try originOfInit(ctx, state, w.value_kind, pos);
    const out_name = ctx.locals[@intFromEnum(w.out)].name;
    switch (origin) {
        .stack => |src_local| {
            // `out.field = &local` / `out.* = &local` — unambiguous
            // stack-frame escape regardless of out's pointee type.
            if (!config_mod.isEnabled(ctx.config, .stack_escape)) return;
            const src_name = ctx.locals[@intFromEnum(src_local)].name;
            try report(ctx, "stack-escape", pos, end_pos, .@"error",
                "writing a pointer to function-local stack variable `{s}` through `{s}` (escapes its frame)",
                .{ src_name, out_name });
        },
        .heap => |hid| {
            // Record the write for the deferred check at fn exit
            // (transferRet).  At write time the heap is live, so
            // it's not yet an escape — but if a defer subsequently
            // frees it, the caller's pointee dangles on return.
            // Last-write-wins per out-param.
            try state.out_param_writes.put(ctx.gpa, w.out, hid);
        },
        .arena, .arena_borrow => |aid| {
            // Arena-shaped value written to caller storage.  Only a
            // stack-allocated arena (`var a = ArenaAllocator.init(...)`)
            // dies with the frame — heap-allocated arenas
            // (`var a = gpa.create(ArenaAllocator)`) carry their
            // descriptor on the heap and survive the function.
            // Tracked via `ArenaState.is_heap_allocated`.
            if (!config_mod.isEnabled(ctx.config, .arena_escape)) return;
            const st = state.arenas.get(aid) orelse return;
            if (st.is_heap_allocated) return;
            try report(ctx, "arena-escape", pos, end_pos, .@"error",
                "writing a value borrowed from a function-local arena through `{s}` (escapes its lifetime)",
                .{out_name});
        },
        else => {},
    }
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
        .arena_init => |info| blk: {
            // OVERWRITE to .live on every visit — the decl represents
            // a fresh resource at this call site.  Inside a loop,
            // back-edges propagate dead state from a prior iteration's
            // free back to the body's start; without this reset, the
            // fresh allocation would inherit that stale dead state and
            // spurious UAF would fire on later uses.
            const mut_state: *AbstractState = @constCast(state);
            try mut_state.arenas.put(ctx.gpa, info.id, .{
                .state = .live,
                .is_heap_allocated = info.is_heap_allocated,
            });
            break :blk .{ .arena = info.id };
        },
        .stack_ref => |src_local| .{ .stack = src_local },
        .composite_borrow => |src_local| state.locals.get(src_local) orelse .plain,
        .heap_alloc => |info| blk: {
            const mut_state: *AbstractState = @constCast(state);
            try mut_state.heaps.put(ctx.gpa, info.id, .{
                .state = .live,
                .allocator_local = info.allocator_local,
            });
            break :blk .{ .heap = info.id };
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
                try reportWithNote(ctx, "arena-use-after-kill", pos, end_pos, .@"error",
                    "`{s}` borrows from an arena that was deinit'd",
                    .{local_name},
                    if (st.killed_at) |ks|
                        .{ .site = ks, .label = "arena deinit'd here" }
                    else
                        null);
            }
        },
        .heap => |hid| {
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const st = state.heaps.get(hid) orelse return;
            if (st.state == .dead) {
                try reportWithNote(ctx, "heap-use-after-free", pos, end_pos, .@"error",
                    "use of `{s}` after free",
                    .{local_name},
                    if (st.killed_at) |ks|
                        .{ .site = ks, .label = "value freed here" }
                    else
                        null);
            }
        },
        .undef => {
            if (!config_mod.isEnabled(ctx.config, .use_undefined)) return;
            try report(ctx, "use-undefined", pos, end_pos, .@"error",
                "use of `{s}` while still `undefined`", .{local_name});
        },
        .stack => |owner_id| {
            // Stack-borrow liveness — the borrow inherits the owner
            // local's death.  Today this fires when `owner` was the
            // target of an inter-procedural @takes-ownership call
            // (transferHeapFree's fallback path rewrites
            // state.locals[owner] to .heap(fake_dead)), so a borrow
            // taken via `&owner.field` then used after `owner.die()`
            // surfaces as UAF on the borrow itself.  Stack-frame
            // death across return is still handled by transferRet.
            if (!config_mod.isEnabled(ctx.config, .heap_use_after_free)) return;
            const owner_origin = state.locals.get(owner_id) orelse return;
            switch (owner_origin) {
                .heap => |hid| {
                    const st = state.heaps.get(hid) orelse return;
                    if (st.state == .dead) {
                        try reportWithNote(ctx, "heap-use-after-free", pos, end_pos, .@"error",
                            "use of `{s}` (borrow from `{s}`) after free",
                            .{ local_name, ctx.locals[@intFromEnum(owner_id)].name },
                            if (st.killed_at) |ks|
                                .{ .site = ks, .label = "value freed here" }
                            else
                                null);
                    }
                },
                else => {},
            }
        },
        else => {},
    }
}

fn report(
    ctx: Ctx,
    rule_id: []const u8,
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
    severity: Severity,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    try reportWithNote(ctx, rule_id, pos, end_pos, severity, fmt, args, null);
}

fn reportWithNote(
    ctx: Ctx,
    rule_id: []const u8,
    pos: cfg.SrcPos,
    end_pos: cfg.SrcPos,
    severity: Severity,
    comptime fmt: []const u8,
    args: anytype,
    kill_site: ?struct { site: state_mod.KillSite, label: []const u8 },
) !void {
    const msg = try std.fmt.allocPrint(ctx.gpa, fmt, args);
    const real_end: cfg.SrcPos = if (end_pos.byte > pos.byte)
        end_pos
    else
        .{ .line = pos.line, .column = pos.column + 1, .byte = pos.byte + 1 };
    var notes: []problem_mod.Note = &.{};
    if (kill_site) |ks| {
        notes = try ctx.gpa.alloc(problem_mod.Note, 1);
        const label = try ctx.gpa.dupe(u8, ks.label);
        notes[0] = .{
            .start = .{ .line = ks.site.line, .column = ks.site.column, .byte = ks.site.byte },
            .end = .{ .line = ks.site.end_line, .column = ks.site.end_column, .byte = ks.site.end_byte },
            .label = label,
        };
    }
    try ctx.problems.append(ctx.gpa, .{
        .rule_id = rule_id,
        .severity = severity,
        .start = .{ .line = pos.line, .column = pos.column, .byte = pos.byte },
        .end = .{ .line = real_end.line, .column = real_end.column, .byte = real_end.byte },
        .message = msg,
        .notes = notes,
    });
}
