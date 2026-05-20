//! Worklist fixed-point over a CFG.  Computes a per-block in-state by
//! repeatedly merging predecessors' out-states until nothing changes,
//! emitting Problems along the way.

const std = @import("std");
const cfg_mod = @import("cfg.zig");
const state_mod = @import("abstract_state.zig");
const transfer = @import("transfer.zig");
const problem_mod = @import("problem.zig");
const annotations = @import("annotations.zig");
const imports_mod = @import("imports.zig");
const remote_resolver_mod = @import("remote_resolver.zig");
const config_mod = @import("config.zig");

const Cfg = cfg_mod.Cfg;
const BlockId = cfg_mod.BlockId;
const AbstractState = state_mod.AbstractState;
const JoinResult = state_mod.JoinResult;
const Problem = problem_mod.Problem;

pub const Options = struct {
    path: []const u8,
    config: *const config_mod.Config = &config_mod.Default,
};

pub fn check(
    gpa: std.mem.Allocator,
    cfg: *const Cfg,
    opts: Options,
    out: *std.ArrayListUnmanaged(Problem),
) !void {
    var in_states = try gpa.alloc(AbstractState, cfg.blocks.len);
    defer {
        for (in_states) |*s| s.deinit(gpa);
        gpa.free(in_states);
    }
    for (in_states) |*s| s.* = .{};

    // Pass 1 — converge the per-block in-states without reporting.
    // Worklist visits aren't predecessor-first, so during convergence
    // a block can be transferred from a stale in-state and emit
    // spurious problems that later iterations would refine away.
    // Discard pass 1's problems entirely; we only trust the FINAL
    // in-states.
    var scratch: std.ArrayListUnmanaged(Problem) = .empty;
    defer {
        for (scratch.items) |*p| p.deinit(gpa);
        scratch.deinit(gpa);
    }

    var worklist: std.ArrayListUnmanaged(BlockId) = .empty;
    defer worklist.deinit(gpa);
    try worklist.append(gpa, cfg.entry);

    var iter_guard: u32 = 0;
    const MAX_ITERS: u32 = 200_000;

    while (worklist.pop()) |block_id| {
        iter_guard += 1;
        if (iter_guard > MAX_ITERS) {
            std.debug.print("zbc/escape-check: bailed after {} iterations on {s}\n", .{
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
            .problems = &scratch,
            .path = opts.path,
            .config = opts.config,
        };

        for (block.stmts) |stmt| {
            try transfer.transfer(ctx, &state, stmt);
        }

        for (block.successors) |succ| {
            const succ_idx = @intFromEnum(succ);
            const result = try state_mod.join(&in_states[succ_idx], &state, gpa);
            if (result == .changed) {
                try worklist.append(gpa, succ);
            }
        }
    }

    // Pass 2 — replay every block from its fixed-point in-state with
    // reporting enabled.  Unreachable blocks have empty in-state and
    // emit nothing because their stmt list either references no locals
    // or all lookups miss.
    for (cfg.blocks, 0..) |block, i| {
        var state = try in_states[i].clone(gpa);
        defer state.deinit(gpa);

        const ctx: transfer.Ctx = .{
            .gpa = gpa,
            .locals = cfg.locals,
            .problems = out,
            .path = opts.path,
            .config = opts.config,
        };

        for (block.stmts) |stmt| {
            try transfer.transfer(ctx, &state, stmt);
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
    try std.testing.expect(problems.items.len >= 1);
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

test "branch-specific UAF: kill in one if-branch, use after merge" {
    const gpa = std.testing.allocator;
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
    try std.testing.expect(problems.items.len >= 1);
}

test "stack_escape: return &local is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() *const u32 {
        \\    var x: u32 = 7;
        \\    return &x;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "stack variable") != null) found = true;
    }
    try std.testing.expect(found);
}

test "stack_escape: return &local propagated through copy" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() *const u32 {
        \\    var x: u32 = 7;
        \\    const p = &x;
        \\    return p;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "stack variable") != null) found = true;
    }
    try std.testing.expect(found);
}

test "R7 inference: multi-stmt delegator `var x = c.text(); return x;` fires" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\pub fn wrap_multi(c: *const Ctx) []const u8 {
        \\    const x = c.text();
        \\    return x;
        \\}
        \\pub fn caller() []const u8 {
        \\    var local = Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return wrap_multi(&local);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "R7 inference: wrapper-of-wrapper across source order via fixed-point" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\// wrap_outer is defined BEFORE wrap_inner in source order —
        \\// requires fixed-point iteration to resolve wrap_inner first.
        \\pub fn wrap_outer(c: *const Ctx) []const u8 {
        \\    return wrap_inner(c);
        \\}
        \\pub fn wrap_inner(c: *const Ctx) []const u8 {
        \\    return c.text();
        \\}
        \\pub fn caller() []const u8 {
        \\    var local = Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return wrap_outer(&local);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "R7 inference: namespace-style delegator wrap fires escape" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\// Namespace-style call: Ctx.text(c) instead of c.text().
        \\pub fn wrap_ns(c: *const Ctx) []const u8 {
        \\    return Ctx.text(c);
        \\}
        \\pub fn caller() []const u8 {
        \\    var local_ctx = Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return wrap_ns(&local_ctx);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "R7 inference: delegator wrap fires escape on local-arena caller" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\pub fn wrap(c: *const Ctx) []const u8 {
        \\    return c.text();
        \\}
        \\pub fn callerEscape() []const u8 {
        \\    var local_ctx = Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return wrap(&local_ctx);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "arena_escape: composite via direct arena_local.method() is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Wrapper = struct { s: []const u8 };
        \\/// @returns borrowed_from(self)
        \\pub fn arenaText(self: *std.heap.ArenaAllocator) []const u8 { _ = self; return ""; }
        \\pub fn foo() Wrapper {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return Wrapper{ .s = arena.arenaText() };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "borrow from function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "arena_escape: composite via chained field-access then method is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 { _ = self; return ""; }
        \\};
        \\const Wrapper = struct { s: []const u8 };
        \\const Outer = struct { inner: std.heap.ArenaAllocator, a: Arena };
        \\pub fn foo() Wrapper {
        \\    var o = Outer{ .inner = std.heap.ArenaAllocator.init(undefined), .a = .{} };
        \\    return Wrapper{ .s = o.a.text() };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Walker matches `<local> ( . <id> )* . <method> (` — so
    // `o.a.text()` fires once we recognize the field chain before
    // the method call.
    var fired = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) fired = true;
    }
    try std.testing.expect(fired);
}

test "arena_escape: composite — bare arena in composite is treated as move (no fire)" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Self = struct { arena: std.heap.ArenaAllocator };
        \\pub fn init() Self {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return Self{ .arena = arena };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Move pattern — should NOT fire.  This was the false-positive
    // risk we explicitly designed around in option E.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "arena_escape: @returns owns_locals suppresses composite-borrow check" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 { _ = self; return ""; }
        \\};
        \\const Wrapper = struct { s: []const u8 };
        \\const Holder = struct { arena: std.heap.ArenaAllocator };
        \\/// @returns owns_locals
        \\pub fn foo() Wrapper {
        \\    var h = Holder{ .arena = std.heap.ArenaAllocator.init(undefined) };
        \\    var a = Arena{};
        \\    _ = h;
        \\    return Wrapper{ .s = a.text() };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Annotation suppresses any composite-borrow finding.
    var any_arena = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "borrow from function-local arena") != null) any_arena = true;
    }
    try std.testing.expect(!any_arena);
}

test "stack_escape: composite — return .{ .p = &local } is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const Wrapper = struct { p: *const u32 };
        \\pub fn foo() Wrapper {
        \\    var x: u32 = 7;
        \\    return .{ .p = &x };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "stack variable `x`") != null) found = true;
    }
    try std.testing.expect(found);
}

test "stack_escape: composite — return .{ .s = local_array[0..] } is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() struct { s: []const u8 } {
        \\    var buf: [16]u8 = undefined;
        \\    return .{ .s = buf[0..] };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "stack variable `buf`") != null) found = true;
    }
    try std.testing.expect(found);
}

test "stack_escape: plain value return is OK" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() u32 {
        \\    var x: u32 = 7;
        \\    return x;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "use_undefined: return undefined directly is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() u32 {
        \\    return undefined;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "undefined") != null) found = true;
    }
    try std.testing.expect(found);
}

test "use_undefined: return local that was set to undefined" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() u32 {
        \\    var x: u32 = undefined;
        \\    return x;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "undefined") != null) found = true;
    }
    try std.testing.expect(found);
}

test "use_undefined: reassign before return clears undef" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn foo() u32 {
        \\    var x: u32 = undefined;
        \\    x = 7;
        \\    return x;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "heap_double_free: free same pointer twice is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(gpa_: std.mem.Allocator) void {
        \\    const p = gpa_.alloc(u8, 16);
        \\    gpa_.free(p);
        \\    gpa_.free(p);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "double-free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "heap_double_free: single free is clean" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(gpa_: std.mem.Allocator) void {
        \\    const p = gpa_.alloc(u8, 16);
        \\    gpa_.free(p);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "heap_use_after_free: return after free is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(gpa_: std.mem.Allocator) []u8 {
        \\    const p = gpa_.alloc(u8, 16);
        \\    gpa_.free(p);
        \\    return p;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "heap_use_after_free: return without freeing is OK (ownership transfer)" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(gpa_: std.mem.Allocator) []u8 {
        \\    return gpa_.alloc(u8, 16);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "heap_use_after_free: composite — return .{ .p = freed_buf } is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Wrapper = struct { ptr: []u8 };
        \\pub fn foo(gpa_: std.mem.Allocator) !Wrapper {
        \\    var buf = try gpa_.alloc(u8, 16);
        \\    gpa_.free(buf);
        \\    return .{ .ptr = buf };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "heap_use_after_free: composite with live alloc is clean (ownership transfer)" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Wrapper = struct { ptr: []u8 };
        \\pub fn foo(gpa_: std.mem.Allocator) !Wrapper {
        \\    const buf = try gpa_.alloc(u8, 16);
        \\    return .{ .ptr = buf };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "heap_double_free: catch-form alloc is tracked" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(gpa_: std.mem.Allocator) void {
        \\    const p = gpa_.alloc(u8, 16) catch return;
        \\    gpa_.free(p);
        \\    gpa_.free(p);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "double-free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "heap_double_free: branch-specific double-free caught by join" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(gpa_: std.mem.Allocator, cond: bool) void {
        \\    const p = gpa_.alloc(u8, 16);
        \\    if (cond) gpa_.free(p);
        \\    gpa_.free(p);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "double-free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "heap_use_after_free: read after free in arbitrary call args is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn consume(b: []u8) void { _ = b; }
        \\pub fn foo(gpa_: std.mem.Allocator) void {
        \\    const p = gpa_.alloc(u8, 16);
        \\    gpa_.free(p);
        \\    consume(p);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "heap_use_after_free: assign rhs read of freed pointer is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\pub fn foo(gpa_: std.mem.Allocator) void {
        \\    var p = gpa_.alloc(u8, 16);
        \\    gpa_.free(p);
        \\    var q: []u8 = undefined;
        \\    q = p;
        \\    _ = q;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "arena_use_after_kill: read after deinit in call arg is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 { _ = self; return ""; }
        \\};
        \\pub fn consume(s: []const u8) void { _ = s; }
        \\pub fn foo() void {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    const s = arena.text();
        \\    arena.deinit();
        \\    consume(s);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "deinit'd") != null) found = true;
    }
    try std.testing.expect(found);
}

test "use_undefined: read undef in call arg is flagged" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn consume(x: u32) void { _ = x; }
        \\pub fn foo() void {
        \\    var x: u32 = undefined;
        \\    consume(x);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    var found = false;
    for (problems.items) |p| {
        if (std.mem.indexOf(u8, p.message, "still `undefined`") != null) found = true;
    }
    try std.testing.expect(found);
}

test "use_undefined: assign before use clears undef" {
    const gpa = std.testing.allocator;
    var problems = try analyze(gpa,
        \\pub fn consume(x: u32) void { _ = x; }
        \\pub fn foo() void {
        \\    var x: u32 = undefined;
        \\    x = 7;
        \\    consume(x);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "lowering_gap collapses locals to plain — no spurious reports" {
    const gpa = std.testing.allocator;
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
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test {
    _ = imports_mod;
    _ = remote_resolver_mod;
}
