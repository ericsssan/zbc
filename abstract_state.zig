//! Layer 2 abstract state types per docs/borrow_checker_design.md.
//!
//! Escape-analysis shape (not borrow-checking): each value carries an
//! `Origin` tagging where its lifetime is bound; the state tracks which
//! arenas are still live and which thread we're in.  Use-validity is
//! a lookup, not a borrow-graph traversal.
//!
//! Algorithm (week 4): standard worklist fixed-point over a CFG, with
//! `join` conservatively combining states at merge points.

const std = @import("std");

// ── Identity tokens ────────────────────────────────────────

/// Local-variable slot id, function-scoped.
pub const LocalId = enum(u32) { _ };

/// Identifies a particular allocator/arena at its construction site.
/// Two distinct ArenaIds == two distinct lifetimes; they never compare equal.
pub const ArenaId = enum(u32) { _ };

/// Identifies a particular `Ast` (or Ast-holder) at construction time.
/// Used to tag NodeIndex origins so we catch cross-Ast usage.
pub const AstId = enum(u32) { _ };

/// Identifies a particular analysis pass (scope-resolve, cfg-build, etc.).
/// Used to tag ScopeId/SymbolId origins so a downstream pass can't reuse
/// a previous pass's IDs.
pub const PassId = enum(u32) { _ };

/// CFG block identifier — see cfg.zig.
pub const BlockId = enum(u32) { _ };

// ── Origin ─────────────────────────────────────────────────

/// What a value's lifetime is bound to.  The lookup-key for use-validity:
/// "is this origin still live at the use point?"
pub const Origin = union(enum) {
    /// No lifetime constraint — plain primitives, comptime consts, ints.
    plain,
    /// Pointer/slice into an arena's bump memory.  Use is invalid once
    /// the arena is dead.
    arena: ArenaId,
    /// NodeIndex tagged with the Ast it came from.  Use as an arg to an
    /// Ast method must check Ast identity.
    ast_node: AstId,
    /// ScopeId / SymbolId from a particular pass.  Use in a different
    /// pass is invalid.
    pass: PassId,
    /// Multiple origins (e.g. struct of borrows).  Conservative: any
    /// constituent dying makes the composite invalid.
    composite: []const Origin,

    pub fn eql(a: Origin, b: Origin) bool {
        if (@as(@typeInfo(Origin).@"union".tag_type.?, a) != @as(@typeInfo(Origin).@"union".tag_type.?, b)) return false;
        return switch (a) {
            .plain => true,
            .arena => |x| x == b.arena,
            .ast_node => |x| x == b.ast_node,
            .pass => |x| x == b.pass,
            .composite => |xs| blk: {
                const ys = b.composite;
                if (xs.len != ys.len) break :blk false;
                for (xs, ys) |xi, yi| if (!xi.eql(yi)) break :blk false;
                break :blk true;
            },
        };
    }
};

// ── ArenaState ─────────────────────────────────────────────

pub const ArenaState = struct {
    state: enum { live, dead },
    /// When dead, the source position of the kill site — used in diagnostics.
    killed_at: ?u32 = null,
};

// ── ThreadContext ──────────────────────────────────────────

pub const ThreadContext = enum {
    /// Main thread; worker-arena borrows are unreadable.
    main,
    /// Worker thread; main-arena borrows are unreadable.
    worker,
    /// Post-join; both arenas readable.
    joined,
};

// ── AbstractState ──────────────────────────────────────────

pub const AbstractState = struct {
    /// Per-local origin tracking.
    locals: std.AutoArrayHashMapUnmanaged(LocalId, Origin) = .empty,

    /// Per-arena liveness.  Killed arenas remain in the map (with .dead)
    /// so we can surface "use-after-kill at L; killed at K" diagnostics.
    arenas: std.AutoArrayHashMapUnmanaged(ArenaId, ArenaState) = .empty,

    /// Current thread context.
    thread: ThreadContext = .main,

    pub fn deinit(self: *AbstractState, gpa: std.mem.Allocator) void {
        self.locals.deinit(gpa);
        self.arenas.deinit(gpa);
    }

    pub fn clone(self: *const AbstractState, gpa: std.mem.Allocator) !AbstractState {
        var out: AbstractState = .{ .thread = self.thread };
        try out.locals.ensureTotalCapacity(gpa, self.locals.count());
        for (self.locals.keys(), self.locals.values()) |k, v| {
            out.locals.putAssumeCapacity(k, v);
        }
        try out.arenas.ensureTotalCapacity(gpa, self.arenas.count());
        for (self.arenas.keys(), self.arenas.values()) |k, v| {
            out.arenas.putAssumeCapacity(k, v);
        }
        return out;
    }
};

pub const JoinResult = enum { unchanged, changed };

/// Conservative CFG-merge join — see design doc §join.
///   - Locals: same origin → keep; different → collapse to .plain
///   - Arenas: dead on either side → dead on merge
///   - Thread: must match (CFG should never join across thread bounds)
pub fn join(
    self: *AbstractState,
    other: *const AbstractState,
    gpa: std.mem.Allocator,
) !JoinResult {
    var changed = false;

    for (other.locals.keys(), other.locals.values()) |local, other_val| {
        const gop = try self.locals.getOrPut(gpa, local);
        if (!gop.found_existing) {
            gop.value_ptr.* = other_val;
            changed = true;
            continue;
        }
        if (!gop.value_ptr.eql(other_val)) {
            gop.value_ptr.* = .plain;
            changed = true;
        }
    }

    for (other.arenas.keys(), other.arenas.values()) |arena, other_state| {
        const gop = try self.arenas.getOrPut(gpa, arena);
        if (!gop.found_existing) {
            gop.value_ptr.* = other_state;
            changed = true;
            continue;
        }
        if (gop.value_ptr.state == .live and other_state.state == .dead) {
            gop.value_ptr.* = other_state;
            changed = true;
        }
    }

    // Thread mismatch isn't error here — it just signals a thread-join
    // point.  We collapse to .joined and let downstream interpretation
    // decide if that's legal.
    if (self.thread != other.thread) {
        self.thread = .joined;
        changed = true;
    }

    return if (changed) .changed else .unchanged;
}

// ── Tests ──────────────────────────────────────────────────

test "Origin.eql arena-vs-arena" {
    const a: ArenaId = @enumFromInt(1);
    const b: ArenaId = @enumFromInt(2);
    try std.testing.expect(Origin.eql(.{ .arena = a }, .{ .arena = a }));
    try std.testing.expect(!Origin.eql(.{ .arena = a }, .{ .arena = b }));
    try std.testing.expect(!Origin.eql(.{ .arena = a }, .plain));
}

test "join: same locals unchanged" {
    const gpa = std.testing.allocator;
    var lhs: AbstractState = .{};
    defer lhs.deinit(gpa);
    var rhs: AbstractState = .{};
    defer rhs.deinit(gpa);
    const l: LocalId = @enumFromInt(0);
    const a: ArenaId = @enumFromInt(0);
    try lhs.locals.put(gpa, l, .{ .arena = a });
    try rhs.locals.put(gpa, l, .{ .arena = a });
    const result = try join(&lhs, &rhs, gpa);
    try std.testing.expectEqual(JoinResult.unchanged, result);
    try std.testing.expect(Origin.eql(lhs.locals.get(l).?, .{ .arena = a }));
}

test "join: differing locals collapse to plain" {
    const gpa = std.testing.allocator;
    var lhs: AbstractState = .{};
    defer lhs.deinit(gpa);
    var rhs: AbstractState = .{};
    defer rhs.deinit(gpa);
    const l: LocalId = @enumFromInt(0);
    try lhs.locals.put(gpa, l, .{ .arena = @enumFromInt(1) });
    try rhs.locals.put(gpa, l, .{ .arena = @enumFromInt(2) });
    const result = try join(&lhs, &rhs, gpa);
    try std.testing.expectEqual(JoinResult.changed, result);
    try std.testing.expect(Origin.eql(lhs.locals.get(l).?, .plain));
}

test "join: dead-on-either-side wins for arenas" {
    const gpa = std.testing.allocator;
    var lhs: AbstractState = .{};
    defer lhs.deinit(gpa);
    var rhs: AbstractState = .{};
    defer rhs.deinit(gpa);
    const a: ArenaId = @enumFromInt(0);
    try lhs.arenas.put(gpa, a, .{ .state = .live });
    try rhs.arenas.put(gpa, a, .{ .state = .dead, .killed_at = 42 });
    const result = try join(&lhs, &rhs, gpa);
    try std.testing.expectEqual(JoinResult.changed, result);
    try std.testing.expect(lhs.arenas.get(a).?.state == .dead);
    try std.testing.expectEqual(@as(?u32, 42), lhs.arenas.get(a).?.killed_at);
}

test "join: thread mismatch collapses to joined" {
    const gpa = std.testing.allocator;
    var lhs: AbstractState = .{ .thread = .main };
    defer lhs.deinit(gpa);
    var rhs: AbstractState = .{ .thread = .worker };
    defer rhs.deinit(gpa);
    const result = try join(&lhs, &rhs, gpa);
    try std.testing.expectEqual(JoinResult.changed, result);
    try std.testing.expectEqual(ThreadContext.joined, lhs.thread);
}
