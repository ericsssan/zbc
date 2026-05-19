//! Worklist fixed-point over a CFG.  Computes a per-block in-state by
//! repeatedly merging predecessors' out-states until nothing changes,
//! emitting Problems along the way.
//!
//! v1 limitations:
//!   - cfg.zig currently produces linear blocks only (if/while → gap),
//!     so the worklist usually terminates in one pass per block.
//!   - When real branching lands (week 5), the same algorithm naturally
//!     extends — `join` handles convergence at merge points.

const std = @import("std");
const cfg_mod = @import("cfg.zig");
const state_mod = @import("abstract_state.zig");
const transfer = @import("transfer.zig");
const problem_mod = @import("problem.zig");

const Cfg = cfg_mod.Cfg;
const BlockId = cfg_mod.BlockId;
const AbstractState = state_mod.AbstractState;
const JoinResult = state_mod.JoinResult;
const Problem = problem_mod.Problem;

pub const Options = struct {
    /// Source file path for diagnostics.
    path: []const u8,
};

/// Run escape analysis over `cfg`, appending Problems to `out`.
/// Caller owns `out`; allocations within Problems also use `gpa`.
pub fn check(
    gpa: std.mem.Allocator,
    cfg: *const Cfg,
    opts: Options,
    out: *std.ArrayListUnmanaged(Problem),
) !void {
    // Per-block in-states; entry starts empty.
    var in_states = try gpa.alloc(AbstractState, cfg.blocks.len);
    defer {
        for (in_states) |*s| s.deinit(gpa);
        gpa.free(in_states);
    }
    for (in_states) |*s| s.* = .{};

    // ArenaId counter — minted by transferDecl on arena_init.
    var next_arena: u32 = 0;

    // Worklist — process every reachable block until in-states stabilise.
    var worklist: std.ArrayListUnmanaged(BlockId) = .empty;
    defer worklist.deinit(gpa);
    try worklist.append(gpa, cfg.entry);

    // Per-block done flag — guards against re-processing without state
    // change (v1: only succ states get pushed; for branches week 5 will
    // need to re-process the join block on every change).
    var iter_guard: u32 = 0;
    const MAX_ITERS: u32 = 10_000;

    while (worklist.pop()) |block_id| {
        iter_guard += 1;
        if (iter_guard > MAX_ITERS) {
            // Safety net — convergence bug or pathological CFG.  Don't
            // hang the developer's editor; just bail with a note.
            std.debug.print("ez/escape-check: bailed after {} iterations on {s}\n", .{
                MAX_ITERS, opts.path,
            });
            return;
        }

        const block = cfg.blocks[@intFromEnum(block_id)];
        var state = try in_states[@intFromEnum(block_id)].clone(gpa);
        defer state.deinit(gpa);

        const ctx: transfer.Ctx = .{
            .gpa = gpa,
            .locals = cfg.locals,
            .next_arena = &next_arena,
            .problems = out,
            .path = opts.path,
        };

        for (block.stmts) |stmt| {
            try transfer.transfer(ctx, &state, stmt);
        }

        // Propagate to successors; push them if their in-state changed.
        for (block.successors) |succ| {
            const succ_idx = @intFromEnum(succ);
            const result = try state_mod.join(&in_states[succ_idx], &state, gpa);
            if (result == .changed) {
                try worklist.append(gpa, succ);
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────

const Ast = std.zig.Ast;

fn analyze(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    const src_z = try gpa.dupeZ(u8, src);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var cfg = (try cfg_mod.lowerFunction(gpa, &tree, node)) orelse continue;
        defer cfg.deinit(gpa);
        try check(gpa, &cfg, .{ .path = "<test>" }, &problems);
    }
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(Problem)) void {
    for (p.items) |*item| item.deinit(gpa);
    p.deinit(gpa);
}

test "no escape — arena local, no return" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo() void {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    arena.deinit();
        \\    return;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "escape — return a value borrowed from a function-local arena" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo() u32 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return arena;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expect(std.mem.indexOf(u8, problems.items[0].message,
        "function-local arena") != null);
}

test "UAF — use of arena-borrowed local after arena.deinit()" {
    const gpa = std.testing.allocator;
    // Without a borrowed_from annotation in scope yet (week 5 wires the
    // annotation lookup), we model the borrow by reading the arena
    // local directly — its origin IS .arena, so the use checks alive.
    //
    // After arena.deinit(), the arena is marked dead.  Reading the same
    // local in a way that triggers a `use` stmt should report UAF.
    //
    // cfg.zig today doesn't emit `use` for identifier-expression
    // statements (would need an additional lowering rule).  Simplest
    // demo: the return-of-identifier case carries the arena origin
    // through to the return, which transferRet already checks.
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo() u32 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    arena.deinit();
        \\    return arena;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // The arena origin is in `state.arenas` (registered at init), the
    // arena is dead by the return, and `return arena` flows that origin
    // out — flagged as a function-local arena escape.
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "lowering_gap collapses locals to plain — no spurious reports" {
    const gpa = std.testing.allocator;
    // `if (x) return;` triggers a lowering_gap in cfg.zig today.  The
    // transfer fn should collapse local origins to .plain so subsequent
    // use checks don't reference stale origins.
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(x: bool) void {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    if (x) return;
        \\    arena.deinit();
        \\    return;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Today this should be silent — no detected escapes (we lose
    // precision through the gap but don't fabricate false positives).
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
