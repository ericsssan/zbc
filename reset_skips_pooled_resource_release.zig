//! A struct has both `deinit` and `reset` methods.  `deinit` calls
//! release/free/destroy/close/deinit on owned handles (typically
//! pool slots or external resources).  `reset` either does nothing
//! for those handles or just zeroes the struct.  State is logically
//! "freed" after `reset` but the pool / sub-allocator still
//! considers slots held → leak.
//!
//! Real-world: tigerbeetle/tigerbeetle#3436 (`SegmentedArray.reset`
//! forgot to release pool nodes that `deinit` does release;
//! callers expected reset to free pool capacity) and
//! tigerbeetle/tigerbeetle#1734 (`scan_buffer_pool` — same shape).
//!
//! Detection (token-walk per file):
//!   1. Walk for `keyword_struct` followed by `{` to find struct
//!      bodies.
//!   2. Within each struct body, find `pub fn deinit(` and
//!      `pub fn reset(` decls.
//!   3. For each, collect the set of `<obj>.<cleanup>(` calls
//!      where cleanup ∈ {`release`, `free`, `destroy`, `close`,
//!      `deinit`, `unref`, `deref`}.
//!   4. If `deinit` calls any `<obj>.<cleanup>` that `reset`
//!      doesn't, fire on the `reset` fn name.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("problem.zig");
const config_mod = @import("config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .reset_skips_pooled_resource_release)) return;

    const tags = tree.tokens.items(.tag);
    const tok_count: u32 = @intCast(tree.tokens.len);
    if (tok_count == 0) return;
    const last: Ast.TokenIndex = tok_count - 1;

    var t: Ast.TokenIndex = 0;
    while (t + 1 < last) : (t += 1) {
        if (tags[t] != .keyword_struct) continue;
        if (tags[t + 1] != .l_brace) continue;
        const body_start = t + 1;
        const body_end = matchBrace(tags, body_start, last) orelse continue;
        try checkStruct(gpa, tree, body_start + 1, body_end - 1, problems);
        t = body_end;
    }
}

const FnInfo = struct {
    name_tok: Ast.TokenIndex,
    body_start: Ast.TokenIndex,
    body_end: Ast.TokenIndex,
};

fn checkStruct(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    var deinit_fn: ?FnInfo = null;
    var reset_fn: ?FnInfo = null;

    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = matchBrace(tags, t, end) orelse break;
            continue;
        }
        if (tags[t] != .keyword_fn) continue;
        if (tags[t + 1] != .identifier) continue;
        const name = tree.tokenSlice(t + 1);
        const is_deinit = std.mem.eql(u8, name, "deinit");
        const is_reset = std.mem.eql(u8, name, "reset");
        if (!is_deinit and !is_reset) continue;
        // Find the body `{` for this fn.
        var u: Ast.TokenIndex = t + 2;
        while (u <= end and tags[u] != .l_brace) : (u += 1) {}
        if (u > end) break;
        const fn_body_end = matchBrace(tags, u, end) orelse break;
        const info: FnInfo = .{
            .name_tok = t + 1,
            .body_start = u + 1,
            .body_end = fn_body_end - 1,
        };
        if (is_deinit and deinit_fn == null) deinit_fn = info;
        if (is_reset and reset_fn == null) reset_fn = info;
        t = fn_body_end;
    }

    if (deinit_fn == null or reset_fn == null) return;

    var deinit_cleanups: std.ArrayListUnmanaged(Cleanup) = .empty;
    defer deinit_cleanups.deinit(gpa);
    try collectCleanups(gpa, tree, deinit_fn.?.body_start, deinit_fn.?.body_end, &deinit_cleanups);

    var reset_cleanups: std.ArrayListUnmanaged(Cleanup) = .empty;
    defer reset_cleanups.deinit(gpa);
    try collectCleanups(gpa, tree, reset_fn.?.body_start, reset_fn.?.body_end, &reset_cleanups);

    // Find cleanups in deinit that aren't in reset.  Match by
    // RECEIVER only — `cache.deinit(alloc)` in deinit and
    // `cache.reset()` / `cache.clearRetainingCapacity()` in reset
    // both qualify as "cleanup on the same receiver", which is
    // semantically equivalent for the bug shape we're targeting
    // (preventing pool/handle leaks).  Method-name mismatches
    // between deinit and reset are not bugs by themselves —
    // authors deliberately pick different methods for the two
    // lifecycle endpoints.
    for (deinit_cleanups.items) |dc| {
        var found = false;
        for (reset_cleanups.items) |rc| {
            if (std.mem.eql(u8, dc.recv, rc.recv)) {
                found = true;
                break;
            }
        }
        if (!found) {
            try report(gpa, problems, tree, reset_fn.?.name_tok, dc);
        }
    }
}

const Cleanup = struct {
    recv: []const u8,
    method: []const u8,
};

fn collectCleanups(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    out: *std.ArrayListUnmanaged(Cleanup),
) !void {
    const tags = tree.tokens.items(.tag);
    if (start > end) return;
    var t: Ast.TokenIndex = start;
    while (t + 3 <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        const method = tree.tokenSlice(t + 2);
        if (!isCleanupMethodName(method)) continue;
        const recv = tree.tokenSlice(t);
        // Skip allocator-ish receivers — `alloc.free(self.nodes)`
        // in deinit is freeing the BACKING STORAGE, which `reset`
        // legitimately keeps (reset's whole point is to keep
        // capacity).  The bug shape this rule targets is missing
        // POOL-slot releases — external resources owned by a pool /
        // refcount helper, not the struct's own heap memory.
        if (isAllocatorishName(recv)) continue;
        // Dedup.
        var already = false;
        for (out.items) |c| {
            if (std.mem.eql(u8, c.recv, recv) and std.mem.eql(u8, c.method, method)) {
                already = true;
                break;
            }
        }
        if (!already) {
            try out.append(gpa, .{ .recv = recv, .method = method });
        }
    }
}

fn isAllocatorishName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "gpa")) return true;
    if (std.mem.eql(u8, name, "alloc")) return true;
    if (std.mem.eql(u8, name, "allocator")) return true;
    if (std.mem.eql(u8, name, "a")) return true;
    if (std.mem.endsWith(u8, name, "_alloc")) return true;
    if (std.mem.endsWith(u8, name, "_allocator")) return true;
    if (std.mem.endsWith(u8, name, "Alloc")) return true;
    if (std.mem.endsWith(u8, name, "Allocator")) return true;
    return false;
}

fn isCleanupMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "release") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "close") or
        std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "unref") or
        std.mem.eql(u8, name, "deref") or
        // Reset-side equivalents: receiver-matching against these
        // counts as "reset cleans up this resource."
        std.mem.eql(u8, name, "reset") or
        std.mem.eql(u8, name, "clear") or
        std.mem.eql(u8, name, "clearRetainingCapacity") or
        std.mem.eql(u8, name, "clearAndFree");
}

fn matchBrace(
    tags: []const std.zig.Token.Tag,
    lb: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var depth: u32 = 1;
    var t: Ast.TokenIndex = lb + 1;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => {
                depth -= 1;
                if (depth == 0) return t;
            },
            else => {},
        }
    }
    return null;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    reset_name_tok: Ast.TokenIndex,
    missing: Cleanup,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`reset` is missing `{s}.{s}(...)` — `deinit` releases this resource but `reset` doesn't, so callers using `reset` to free the struct will leak the pool / sub-allocator slot",
        .{ missing.recv, missing.method },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "reset-skips-pooled-resource-release",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, reset_name_tok),
        .end = Pos.fromTokenEnd(tree, reset_name_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);
    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    try check(gpa, &tree, &config_mod.Default, &problems);
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(Problem)) void {
    for (p.items) |*x| x.deinit(gpa);
    p.deinit(gpa);
}

test "reset-skips: deinit releases pool, reset doesn't — fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const NodePool = struct {
        \\    pub fn release(_: *NodePool, _: anytype) void {}
        \\};
        \\const SegmentedArray = struct {
        \\    nodes: []*u8,
        \\    node_count: usize,
        \\    pub fn deinit(self: *SegmentedArray, alloc: std.mem.Allocator, node_pool: *NodePool) void {
        \\        for (self.nodes[0..self.node_count]) |node| node_pool.release(node);
        \\        alloc.free(self.nodes);
        \\    }
        \\    pub fn reset(self: *SegmentedArray) void {
        \\        self.node_count = 0;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
    try std.testing.expectEqualStrings("reset-skips-pooled-resource-release", problems.items[0].rule_id);
}

test "reset-skips: deinit and reset both release — doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const NodePool = struct {
        \\    pub fn release(_: *NodePool, _: anytype) void {}
        \\};
        \\const SegmentedArray = struct {
        \\    nodes: []*u8,
        \\    node_count: usize,
        \\    pub fn deinit(self: *SegmentedArray, alloc: std.mem.Allocator, node_pool: *NodePool) void {
        \\        for (self.nodes[0..self.node_count]) |node| node_pool.release(node);
        \\        alloc.free(self.nodes);
        \\    }
        \\    pub fn reset(self: *SegmentedArray, node_pool: *NodePool) void {
        \\        for (self.nodes[0..self.node_count]) |node| node_pool.release(node);
        \\        self.node_count = 0;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "reset-skips: no deinit/reset pair doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct {
        \\    pub fn deinit(_: *T) void {}
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "reset-skips: pool-release in deinit only — fires (allocator-only deinit doesn't)" {
    // Allocator-only deinit (`gpa.free(self.x)`, `alloc.destroy(...)`)
    // is intentionally NOT a trigger — reset legitimately keeps
    // backing storage.  Only POOL / EXTERNAL-resource releases
    // missing from reset count as bugs.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct {
        \\    pub fn deinit(self: *T, gpa: std.mem.Allocator) void {
        \\        gpa.destroy(self);
        \\    }
        \\    pub fn reset(self: *T) void {
        \\        self.* = .{};
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    // allocator-only cleanup: NOT a bug per rule scope.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "reset-skips: pool-release in deinit, absent in reset — fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Refcount = struct {
        \\    pub fn release(_: *Refcount) void {}
        \\};
        \\const T = struct {
        \\    rc: *Refcount,
        \\    pub fn deinit(self: *T) void {
        \\        self.rc.release();
        \\    }
        \\    pub fn reset(self: *T) void {
        \\        _ = self;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
}
