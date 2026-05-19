//! Worklist fixed-point over a CFG.  Computes a per-block in-state by
//! repeatedly merging predecessors' out-states until nothing changes,
//! emitting Problems along the way.
//!
//! v1 limitations:
//!   - cfg.zig models if/else and while branching; for/switch/try still
//!     lower as `.lowering_gap` (conservative collapse of locals to .plain).
//!   - When more branching constructs land, the same algorithm naturally
//!     extends — `join` handles convergence at merge points.

const std = @import("std");
const cfg_mod = @import("cfg.zig");
const state_mod = @import("abstract_state.zig");
const transfer = @import("transfer.zig");
const problem_mod = @import("problem.zig");
const annotations = @import("annotations.zig");
const imports_mod = @import("imports.zig");
const remote_resolver_mod = @import("remote_resolver.zig");

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
    // AstId counter — minted by originOfInit on ast_init (Ast.parse(...)).
    var next_ast: u32 = 0;

    // Worklist — process every reachable block until in-states stabilise.
    var worklist: std.ArrayListUnmanaged(BlockId) = .empty;
    defer worklist.deinit(gpa);
    try worklist.append(gpa, cfg.entry);

    // Per-block done flag — guards against re-processing without state
    // change.  Successor blocks only get re-pushed when their joined
    // in-state actually moved.
    var iter_guard: u32 = 0;
    // Generous safety net.  Genuine pathological CFGs (heavily nested
    // loops + many locals) can take O(blocks · locals · arenas)
    // iterations to stabilize; 200k handles real-codebase functions
    // we've seen (~600 blocks × hundreds of locals).  Smaller bound
    // bails on real code; lots higher risks editor-hang on a real bug.
    const MAX_ITERS: u32 = 200_000;

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
            .next_ast = &next_ast,
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
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);

    var db = try annotations.build(gpa, &tree);
    defer db.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var cfg = (try cfg_mod.lowerFunction(gpa, &tree, node, &db)) orelse continue;
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

test "escape — return slice borrowed from a function-local arena" {
    const gpa = std.testing.allocator;
    // The return TYPE must be borrowed-shape ([]const u8 here).
    // Value-typed returns (struct, primitive) MOVE the value to the
    // caller and don't need this check.
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 {
        \\        _ = self; return "";
        \\    }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return arena.text();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expect(std.mem.indexOf(u8, problems.items[0].message,
        "function-local arena") != null);
}

test "value-typed return owning an arena is OK (move, not borrow)" {
    const gpa = std.testing.allocator;
    // Common Zig pattern: `init()` returns a struct value that owns
    // its arena.  Caller takes ownership; no escape.  Without the
    // return-type gate this used to false-positive on every init() fn.
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Self = struct { a: u32 };
        \\pub fn init() Self {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return .{ .a = 0 };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "defer arena.deinit() kills arena before fallthrough — clean" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo() void {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    defer arena.deinit();
        \\    return;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "defer arena.deinit() catches return-of-borrowed-from-dying-arena" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn slice(self: *const Arena) []const u8 {
        \\        _ = self; return "";
        \\    }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    defer arena.deinit();
        \\    return arena.slice();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Defer replays arena.deinit() before return; return checks slice()'s
    // returned origin (.arena via annotation), arena is dead → flag.
    try std.testing.expect(problems.items.len >= 1);
}

test "annotated callee: borrow propagates through call, escapes via return" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn slice(self: *const Arena) []const u8 {
        \\        _ = self; return "";
        \\    }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return arena.slice();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // arena.slice() carries `arena`'s origin (an ArenaId from the
    // function-local arena_init), and `return` checks that the returned
    // origin doesn't reference a function-local arena.  Should flag.
    try std.testing.expect(problems.items.len >= 1);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "switch-case UAF: kill in one case, use after merge" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn slice(self: *const Arena) []const u8 {
        \\        _ = self; return "";
        \\    }
        \\};
        \\pub fn maybe(tag: u32) []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    switch (tag) {
        \\        0 => arena.deinit(),
        \\        else => {},
        \\    }
        \\    return arena.slice();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
}

test "for-loop UAF: kill inside loop body, use after loop" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn slice(self: *const Arena) []const u8 {
        \\        _ = self; return "";
        \\    }
        \\};
        \\pub fn maybe(items: []const u32) []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    for (items) |_| {
        \\        arena.deinit();
        \\    }
        \\    return arena.slice();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Body's arena_kill back-edges to header, and header forwards the
    // dead state into merge.  Without for-loop modeling, this used to
    // be a lowering_gap that silenced the check.
    try std.testing.expect(problems.items.len >= 1);
}

test "branch-specific UAF: kill in one if-branch, use after merge" {
    const gpa = std.testing.allocator;
    // The arena is killed in one branch of an if-statement.  After the
    // merge, the arena is .dead on the joined state (dead-on-either-side
    // wins in join).  Returning a borrow against it then escapes.
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn slice(self: *const Arena) []const u8 {
        \\        _ = self; return "";
        \\    }
        \\};
        \\pub fn maybe(cond: bool) []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    if (cond) arena.deinit();
        \\    return arena.slice();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // With real branching, the if-branch's arena_kill propagates through
    // the merge join; the return sees a dead-or-alive arena.  Without
    // branching support this would have been a lowering_gap, locals
    // collapsed to .plain, and no escape detected.
    try std.testing.expect(problems.items.len >= 1);
}

test "invariant #1: NodeIndex from Ast A flowing into Ast B is flagged (phase 26)" {
    // Two trees parsed separately get distinct AstIds.  A NodeIndex
    // from tree_a, passed to a `@takes node_index_of(t)` fn alongside
    // tree_b, must be flagged.  Uses `try` (not `catch`) so classifyExpr
    // unwraps to the inner Ast.parse() call and ast_init fires.
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() !void {
        \\    var tree_a = try Ast.parse();
        \\    var tree_b = try Ast.parse();
        \\    const node = rootNode(tree_a);
        \\    inspect(tree_b, node);
        \\    return;
        \\}
        \\const Ast = struct {
        \\    pub fn parse() !Ast { return .{}; }
        \\};
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(ast)
        \\pub fn rootNode(ast: Ast) NodeIndex { _ = ast; return 0; }
        \\/// @takes node_index_of(t)
        \\pub fn inspect(t: Ast, n: NodeIndex) void { _ = t; _ = n; }
        \\
    );
    defer freeProblems(gpa, &problems);

    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "invariant #1") != null) {
            found = true;
        }
    }
    try std.testing.expect(found);
}

test "invariant #1: matching Ast on both args — no false positive" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() !void {
        \\    var tree = try Ast.parse();
        \\    const node = rootNode(tree);
        \\    inspect(tree, node);
        \\    return;
        \\}
        \\const Ast = struct {
        \\    pub fn parse() !Ast { return .{}; }
        \\};
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(ast)
        \\pub fn rootNode(ast: Ast) NodeIndex { _ = ast; return 0; }
        \\/// @takes node_index_of(t)
        \\pub fn inspect(t: Ast, n: NodeIndex) void { _ = t; _ = n; }
        \\
    );
    defer freeProblems(gpa, &problems);

    for (problems.items) |p| {
        try std.testing.expect(std.mem.indexOf(u8, p.message, "invariant #1") == null);
    }
}

/// Cross-file test helper: writes `main_src` and `import_src` to a
/// fresh tmp dir as foo.zig and lib.zig respectively, then runs
/// the full Layer-2 pipeline against foo.zig with cross-file
/// resolution enabled.  Returns the collected problems (caller frees).
fn analyzeCrossFile(
    gpa: std.mem.Allocator,
    main_src: []const u8,
    import_src: []const u8,
) !std.ArrayListUnmanaged(Problem) {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data = import_src });
    try tmp.dir.writeFile(tio, .{ .sub_path = "foo.zig", .data = main_src });

    // tmp.dir is std.Io.Dir which doesn't expose realpathAlloc.
    // std.fs realpath APIs are also in flux on 0.17.  Sidestep:
    // use the relative path; resolver + readFileAlloc handle relatives
    // fine since cwd doesn't change during the test.
    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const foo_path = try std.fs.path.join(gpa, &.{ base_dir, "foo.zig" });
    defer gpa.free(foo_path);

    // Pipeline: read foo.zig, parse, build local DB + imports map,
    // set up sweep-wide cache, lower each fn with remote context,
    // run check on each CFG.
    const src_bytes = try std.Io.Dir.cwd().readFileAlloc(
        tio,
        foo_path,
        gpa,
        std.Io.Limit.limited(1 * 1024 * 1024),
    );
    defer gpa.free(src_bytes);
    const src_z = try gpa.dupeSentinel(u8, src_bytes, 0);
    defer gpa.free(src_z);
    var tree = try std.zig.Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);

    var db = try annotations.build(gpa, &tree);
    defer db.deinit(gpa);
    var imap = try imports_mod.build(gpa, &tree);
    defer imap.deinit(gpa);

    var rcache = remote_resolver_mod.Cache.init(gpa, tio);
    defer rcache.deinit();

    const remote_ctx = cfg_mod.RemoteCtx{
        .imap = &imap,
        .base_dir = base_dir,
        .cache = &rcache,
    };

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: std.zig.Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var cfg = (try cfg_mod.lowerFunctionWithRemote(gpa, &tree, node, &db, &remote_ctx)) orelse continue;
        defer cfg.deinit(gpa);
        try check(gpa, &cfg, .{ .path = foo_path }, &problems);
    }
    return problems;
}

test "invariant #1 fires through CROSS-FILE @takes lookup (phase 28)" {
    // foo.zig defines tree_a + tree_b and calls lib.inspect(tree_b, node)
    // where node came from rootNode(tree_a).  inspect's @takes
    // annotation lives in lib.zig — must be resolved via the remote
    // cache for the check to fire.
    const gpa = std.testing.allocator;
    var problems = try analyzeCrossFile(gpa,
        // foo.zig
        \\const lib = @import("lib.zig");
        \\const Ast = lib.Ast;
        \\const NodeIndex = lib.NodeIndex;
        \\pub fn foo() !void {
        \\    var tree_a = try Ast.parse();
        \\    var tree_b = try Ast.parse();
        \\    const node = lib.rootNode(tree_a);
        \\    lib.inspect(tree_b, node);
        \\    return;
        \\}
        \\
        ,
        // lib.zig
        \\pub const Ast = struct { pub fn parse() !Ast { return .{}; } };
        \\pub const NodeIndex = u32;
        \\/// @returns node_index_of(ast)
        \\pub fn rootNode(ast: Ast) NodeIndex { _ = ast; return 0; }
        \\/// @takes node_index_of(t)
        \\pub fn inspect(t: Ast, n: NodeIndex) void { _ = t; _ = n; }
        \\
    );
    defer freeProblems(gpa, &problems);

    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "invariant #1") != null) found = true;
    }
    try std.testing.expect(found);
}

test "invariant #1 fires at var-decl init position (phase 27)" {
    // `const t = inspect(tree_b, node);` — the call is in init
    // position, NOT statement position.  Pre-phase-27 emitTakesChecks
    // only fired from lowerCallStmt; this case was silent despite
    // the same logical violation.  Phase 27 broadens to init position
    // so this now flags.
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() !void {
        \\    var tree_a = try Ast.parse();
        \\    var tree_b = try Ast.parse();
        \\    const node = rootNode(tree_a);
        \\    const t = inspect(tree_b, node);
        \\    _ = t;
        \\    return;
        \\}
        \\const Ast = struct { pub fn parse() !Ast { return .{}; } };
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(ast)
        \\pub fn rootNode(ast: Ast) NodeIndex { _ = ast; return 0; }
        \\/// @takes node_index_of(t)
        \\pub fn inspect(t: Ast, n: NodeIndex) u32 { _ = t; _ = n; return 0; }
        \\
    );
    defer freeProblems(gpa, &problems);

    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "invariant #1") != null) found = true;
    }
    try std.testing.expect(found);
}

test "invariant #1 fires at return position (phase 27)" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() !u32 {
        \\    var tree_a = try Ast.parse();
        \\    var tree_b = try Ast.parse();
        \\    const node = rootNode(tree_a);
        \\    return inspect(tree_b, node);
        \\}
        \\const Ast = struct { pub fn parse() !Ast { return .{}; } };
        \\const NodeIndex = u32;
        \\/// @returns node_index_of(ast)
        \\pub fn rootNode(ast: Ast) NodeIndex { _ = ast; return 0; }
        \\/// @takes node_index_of(t)
        \\pub fn inspect(t: Ast, n: NodeIndex) u32 { _ = t; _ = n; return 0; }
        \\
    );
    defer freeProblems(gpa, &problems);

    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "invariant #1") != null) found = true;
    }
    try std.testing.expect(found);
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
