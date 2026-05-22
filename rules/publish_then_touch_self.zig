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
const file_cache_mod = @import("../file_cache.zig");

const lexer = @import("../lexer.zig");
const query = @import("../query.zig");
const scope = @import("../scope.zig");
const receiver = @import("../receiver.zig");
const testing = @import("../testing.zig");
const findStmtSemicolon = lexer.findStmtSemicolon;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const Atom = query.Atom;

// `.<method>(<this|self>)` — preceded by `.` so it's a method call
// on a chain.  Capture slots: $0 = method, $1 = arg (this|self).
const publish_call = &[_]Atom{
    .{ .tok = .period },
    .{ .capture = 0 },
    .{ .tok = .l_paren },
    .{ .pred_at = .{ .slot = 1, .pred = receiver.isSelfReceiverName } },
    .{ .tok = .r_paren },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .publish_then_touch_self)) return;
    _ = cache;
    try lexer.forEachFnBody(gpa, tree, problems, checkBody);
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

    const calls = try query.findAllInBody(gpa, tree, publish_call, first, last);
    defer gpa.free(calls);
    for (calls) |m| {
        const method_tok = m.captures[0].?;
        const method = tree.tokenSlice(method_tok);
        const arg = m.captureText(tree, 1).?;
        // Concurrency check: method name OR chain receiver suggests
        // concurrent dispatch.
        const chain_start = walkBackChain(tags, method_tok);
        if (!isConcurrentDispatch(tree, method, chain_start, method_tok)) continue;
        // Find next use of `arg` (this/self) in the same scope.
        const sc = findStmtSemicolon(tags, m.end + 1, last) orelse continue;
        const use_tok = scope.findIdentUseInEnclosingScope(tree, sc + 1, last, arg) orelse continue;
        try report(gpa, problems, tree, use_tok, method, arg);
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

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    use_tok: Ast.TokenIndex,
    method: []const u8,
    arg: []const u8,
) !void {
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
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

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
