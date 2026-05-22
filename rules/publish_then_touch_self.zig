//! Publish-then-touch-self detector — `<thing>.<publish>(this);`
//! (or `(self)`) where `<publish>` dispatches onto a concurrent
//! queue / thread pool / cross-thread channel, followed by any
//! further use of `this`/`self` in the same scope.  The consumer
//! thread may have already freed `this` before the second access
//! lands → cross-thread UAF.
//!
//! Real-world: oven-sh/bun#29128 (RuntimeTranspilerStore —
//! `transpiler_store.queue.push(this); ... transpiler_store.<field>`
//! after `this` was potentially freed by the worker), #31177
//! (mimalloc TLS slot race), #30185 (cross-thread Strong<> copy
//! in lambda capture).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Find call `<chain>.<publish-method>(<arg>)` where
//!      <arg> is bare `this` or `self`, and either:
//!        a. the receiver chain contains a "concurrency" token
//!           (`queue`, `pool`, `thread`, `cross_thread`,
//!           `concurrent`, `dispatch`), OR
//!        b. the method name contains "Concurrent" / "Thread" /
//!           "cross" / matches a known concurrent-dispatch name
//!           (`enqueueTaskConcurrent`, `postToMain`, etc.)
//!   3. After the publish, scan for any use of `this`/`self` in
//!      the same fn body at the same lexical depth.
//!   4. Fire on the first such use.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .publish_then_touch_self)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var t: Ast.TokenIndex = first;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        // Pattern: `.<method>(this)` or `.<method>(self)` — method
        // is preceded by `.` (chained call).
        if (tags[t] != .identifier) continue;
        if (t == 0 or tags[t - 1] != .period) continue;
        const method = tree.tokenSlice(t);
        if (tags[t + 1] != .l_paren) continue;
        // First arg must be bare `this` or `self`, then `)`.
        if (tags[t + 2] != .identifier) continue;
        const arg = tree.tokenSlice(t + 2);
        if (!std.mem.eql(u8, arg, "this") and !std.mem.eql(u8, arg, "self")) continue;
        if (tags[t + 3] != .r_paren) continue;
        // Concurrency check: method name OR chain receiver suggests
        // concurrent dispatch.
        const chain_start = walkBackChain(tags, t);
        if (!isConcurrentDispatch(tree, method, chain_start, t)) continue;
        // Find next use of `arg` (this/self) in the same scope.
        const sc = findStmtSemicolon(tags, t + 4, last) orelse continue;
        const use_tok = findIdentUseSameScope(tree, sc + 1, last, arg) orelse {
            t = sc;
            continue;
        };
        try report(gpa, problems, tree, t, use_tok, method, arg);
        t = sc;
    }
}

/// Walk backward from the `.method` to find the chain's start token.
/// Returns the first token of the chain (the leftmost identifier).
fn walkBackChain(tags: []const std.zig.Token.Tag, method_tok: Ast.TokenIndex) Ast.TokenIndex {
    // method_tok is at the .method's identifier; method_tok-1 is `.`.
    // Walk back through `.<ident>` segments.
    var t: Ast.TokenIndex = method_tok;
    while (t >= 2 and tags[t - 1] == .period and tags[t - 2] == .identifier) {
        t -= 2;
    }
    return t;
}

/// True iff the call's method name OR receiver chain suggests
/// concurrent / cross-thread dispatch (ownership transfer, not
/// observation).
fn isConcurrentDispatch(
    tree: *const Ast,
    method: []const u8,
    chain_start: Ast.TokenIndex,
    method_tok: Ast.TokenIndex,
) bool {
    // Observer-method blocklist: even on a concurrent-chain
    // receiver, these methods don't transfer ownership.
    if (isObserverMethod(method)) return false;
    // Method-name signal (strong).
    if (containsConcurrencyToken(method)) return true;
    if (isExactConcurrentMethod(method)) return true;
    // Receiver-chain signal: any identifier in the chain matches
    // a concurrency keyword AND the method looks like a publish
    // (push / send / submit) — bare `register`/`tick` on a
    // concurrent chain doesn't count.
    if (!isPublishMethod(method)) return false;
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = chain_start;
    while (t < method_tok) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const seg = tree.tokenSlice(t);
        if (isConcurrencyChainToken(seg)) return true;
    }
    return false;
}

fn isObserverMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "register") or
        std.mem.eql(u8, name, "unregister") or
        std.mem.eql(u8, name, "subscribe") or
        std.mem.eql(u8, name, "unsubscribe") or
        std.mem.eql(u8, name, "observe") or
        std.mem.eql(u8, name, "tick") or
        std.mem.eql(u8, name, "step");
}

fn isPublishMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "push") or
        std.mem.eql(u8, name, "send") or
        std.mem.eql(u8, name, "submit") or
        std.mem.eql(u8, name, "enqueue") or
        std.mem.eql(u8, name, "post") or
        std.mem.eql(u8, name, "schedule") or
        std.mem.eql(u8, name, "dispatch");
}

fn containsConcurrencyToken(name: []const u8) bool {
    // Only `Concurrent` as a suffix is a reliable signal of
    // ownership transfer (`enqueueTaskConcurrent`,
    // `postConcurrent`).  `Thread` / `Cross` / `Async` are too
    // loose — `toThreadSafe` (a synchronous converter), `register`
    // on a `ThreadPool` (an observer, not a publisher), and many
    // async helpers don't transfer ownership.
    return std.mem.endsWith(u8, name, "Concurrent");
}

fn isExactConcurrentMethod(name: []const u8) bool {
    // Narrow allowlist of methods that conventionally PUBLISH
    // (transfer ownership of) their argument to a different
    // thread / queue / pool.  Excludes:
    //   - `register` / `unregister` / `subscribe` — observation,
    //     not transfer.
    //   - `dispatch` — too generic; many synchronous "dispatch
    //     to handler" patterns use this name.
    //   - `spawn` — typically a constructor, not a transfer
    //     of an existing `this`.
    return std.mem.eql(u8, name, "postToMain") or
        std.mem.eql(u8, name, "postTask") or
        std.mem.eql(u8, name, "scheduleTask") or
        std.mem.eql(u8, name, "enqueueTaskConcurrent") or
        std.mem.eql(u8, name, "submitConcurrent");
}

fn isConcurrencyChainToken(name: []const u8) bool {
    return std.mem.eql(u8, name, "queue") or
        std.mem.eql(u8, name, "pool") or
        std.mem.eql(u8, name, "thread") or
        std.mem.eql(u8, name, "cross_thread") or
        std.mem.eql(u8, name, "concurrent") or
        std.mem.eql(u8, name, "dispatcher") or
        std.mem.eql(u8, name, "scheduler") or
        std.mem.eql(u8, name, "work_pool") or
        std.mem.eql(u8, name, "workPool") or
        std.mem.eql(u8, name, "thread_pool") or
        std.mem.eql(u8, name, "threadPool");
}

/// Find the next bare identifier matching `name` in the same scope.
fn findIdentUseSameScope(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    name: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var depth: u32 = 0;
    var t: Ast.TokenIndex = start;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => if (depth == 0) return null else {
                depth -= 1;
            },
            .identifier => if (std.mem.eql(u8, tree.tokenSlice(t), name)) return t,
            else => {},
        }
    }
    return null;
}

fn findStmtSemicolon(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var paren: u32 = 0;
    var brace: u32 = 0;
    var bracket: u32 = 0;
    var t: Ast.TokenIndex = start;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_paren => paren += 1,
            .r_paren => if (paren > 0) {
                paren -= 1;
            },
            .l_brace => brace += 1,
            .r_brace => if (brace > 0) {
                brace -= 1;
            },
            .l_bracket => bracket += 1,
            .r_bracket => if (bracket > 0) {
                bracket -= 1;
            },
            .semicolon => if (paren == 0 and brace == 0 and bracket == 0) return t,
            else => {},
        }
    }
    return null;
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

fn skipNestedFn(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
) Ast.TokenIndex {
    var t: Ast.TokenIndex = start;
    while (t <= last and tags[t] != .l_brace) : (t += 1) {}
    if (t > last) return last;
    return matchBrace(tags, t, last) orelse last;
}

fn returnsType(tree: *const Ast, fn_decl: Ast.Node.Index) bool {
    var buf: [1]Ast.Node.Index = undefined;
    const fp = fnProto(tree, &buf, fn_decl) orelse return false;
    const rt = fp.ast.return_type.unwrap() orelse return false;
    const first = tree.firstToken(rt);
    const last = tree.lastToken(rt);
    if (first != last) return false;
    return tree.tokens.items(.tag)[first] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(first), "type");
}

fn fnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) ?Ast.full.FnProto {
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

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    publish_tok: Ast.TokenIndex,
    use_tok: Ast.TokenIndex,
    method: []const u8,
    arg: []const u8,
) !void {
    _ = publish_tok;
    const msg = try std.fmt.allocPrint(
        gpa,
        "use of `{s}` after `.{s}({s})` published it to a concurrent queue / thread pool — the consumer may have freed `{s}` before this access lands.  Hoist any post-publish reads into locals BEFORE the publish call",
        .{ arg, method, arg, arg },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "publish-then-touch-self",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, use_tok),
        .end = Pos.fromTokenEnd(tree, use_tok),
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

test "publish-then-touch-self: queue.push(this) then this.field fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Self = struct {
        \\    vm: usize,
        \\    pub fn dispatch(this: *Self, store: anytype) void {
        \\        store.queue.push(this);
        \\        _ = this.vm;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("publish-then-touch-self", problems.items[0].rule_id);
}

test "publish-then-touch-self: Concurrent-named method also caught" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Self = struct {
        \\    x: u32,
        \\    pub fn work(self: *Self, loop: anytype) void {
        \\        loop.enqueueTaskConcurrent(self);
        \\        _ = self.x;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "publish-then-touch-self: hoisted reads before publish doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Self = struct {
        \\    vm: usize,
        \\    pub fn dispatch(this: *Self, store: anytype) void {
        \\        const vm = this.vm;
        \\        _ = vm;
        \\        store.queue.push(this);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "publish-then-touch-self: non-concurrent receiver/method doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Self = struct {
        \\    x: u32,
        \\    pub fn work(self: *Self, list: anytype) void {
        \\        list.append(self);
        \\        _ = self.x;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "publish-then-touch-self: thread_pool.dispatch(this) caught" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Self = struct {
        \\    x: u32,
        \\    pub fn work(this: *Self, ctx: anytype) void {
        \\        ctx.thread_pool.dispatch(this);
        \\        _ = this.x;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
