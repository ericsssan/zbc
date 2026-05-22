//! Arena-slice-into-heap-container detector — a slice allocated
//! through a function-local arena's allocator is passed as data
//! into a container call whose allocator is NOT the arena.  When
//! the arena dies at fn exit (via `defer <A>.deinit()`), the
//! container is left holding a dangling slice into freed memory.
//!
//! Real-world shape:
//!   var arena = std.heap.ArenaAllocator.init(self.gpa);
//!   defer arena.deinit();
//!   const arena_alloc = arena.allocator();
//!   const tokens = try tokenize(arena_alloc, input);  // arena-owned
//!   try self.token_cache.appendSlice(self.gpa, tokens); // ← stored into
//!                                                       //   heap container
//!
//! Complements zbc's existing `arena_escape` rule (caught via
//! return) and `arena_use_after_kill` (caught via post-deinit
//! read).  This rule catches the third escape path: STORE into a
//! longer-lived container during the arena's lifetime.
//!
//! Rewritten via local.zig (binding-origin tracker) + query.zig
//! (token-pattern matcher).  The three binding-collection passes
//! (arena vars, alloc handles, arena-allocated slices) are now
//! one-shot iterations over `local.build`'s output, with RHS
//! patterns expressed declaratively.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const local = @import("../local.zig");
const query = @import("../query.zig");
const problem_mod = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const Atom = query.Atom;
const R = "slice-of-arena-into-heap";

// ── Patterns ────────────────────────────────────────────────

// `ArenaAllocator.init(...)` — appears somewhere in the binding's
// RHS (we don't care about the prefix `std.heap.` etc.).
const arena_init_pattern = &[_]Atom{
    .{ .text = "ArenaAllocator" },
    .{ .tok = .period },
    .{ .text = "init" },
    .paren_args,
};

// `<recv>.allocator()` — exact match (no chain after).  $0 = receiver.
const allocator_call_exact = &[_]Atom{
    .{ .capture = 0 },
    .{ .tok = .period },
    .{ .text = "allocator" },
    .{ .tok = .l_paren },
    .{ .tok = .r_paren },
};

// `<arena>.allocator().<allocMethod>(...)` — inline form.
// $0 = arena name.
const inline_arena_alloc = &[_]Atom{
    .{ .capture = 0 },
    .{ .tok = .period },
    .{ .text = "allocator" },
    .{ .tok = .l_paren },
    .{ .tok = .r_paren },
    .{ .tok = .period },
    .{ .pred = isAllocMethodName },
    .paren_args,
};

// Store call: `<recv>.<storeMethod>(...)`.
const store_call = &[_]Atom{
    .{ .capture = 0 },
    .{ .tok = .period },
    .{ .capture = 1 },
    .{ .tok = .l_paren },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .slice_of_arena_into_heap)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkBody(gpa, tree, fn_entry.proto, fn_entry.body, problems);
    }
}

const ArenaVar = struct {
    name: []const u8,
    init_token: Ast.TokenIndex,
};

const AllocHandle = struct {
    name: []const u8,
    arena_name: []const u8,
};

const ArenaSlice = struct {
    name: []const u8,
    arena_name: []const u8,
    name_token: Ast.TokenIndex,
};

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    proto: Ast.full.FnProto,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    var bindings = try local.build(gpa, tree, proto, body);
    defer bindings.deinit();

    // ── Pass 1: arena vars ─────────────────────────────────
    // Binding whose RHS contains `ArenaAllocator.init(`.
    var arenas: std.ArrayListUnmanaged(ArenaVar) = .empty;
    defer arenas.deinit(gpa);
    for (bindings.items) |b| {
        if (b.origin == .param) continue;
        if (!query.anyMatchAnywhere(tree, arena_init_pattern, b.rhs_first, b.rhs_last, null)) continue;
        try arenas.append(gpa, .{ .name = b.name, .init_token = b.name_token });
    }
    if (arenas.items.len == 0) return;

    // ── Pass 2: alloc handles ──────────────────────────────
    // Binding whose RHS is EXACTLY `<arena>.allocator()` (no chain).
    var handles: std.ArrayListUnmanaged(AllocHandle) = .empty;
    defer handles.deinit(gpa);
    for (bindings.items) |b| {
        if (b.origin == .param) continue;
        // Peel a leading `try` if present (matchExact starts at rhs_first).
        const start = peelTry(tree, b);
        const m = query.matchExact(tree, allocator_call_exact, start, b.rhs_last, null) orelse continue;
        const arena_name = m.captureText(tree, 0).?;
        if (findArena(arenas.items, arena_name) == null) continue;
        try handles.append(gpa, .{ .name = b.name, .arena_name = arena_name });
    }

    // ── Pass 3: arena-allocated slices ─────────────────────
    // Binding whose RHS is `[try] <H>.<allocMethod>(...)` OR
    // `[try] <arena>.allocator().<allocMethod>(...)`.
    var slices: std.ArrayListUnmanaged(ArenaSlice) = .empty;
    defer slices.deinit(gpa);
    for (bindings.items) |b| {
        if (b.origin == .param) continue;
        const start = peelTry(tree, b);
        // Shape A: <handle>.<allocMethod>(...)
        const call = b.asCall();
        if (call != null and call.?.method != null and isAllocMethodName(call.?.method.?)) {
            if (findHandle(handles.items, call.?.receiver)) |h| {
                try slices.append(gpa, .{
                    .name = b.name,
                    .arena_name = h.arena_name,
                    .name_token = b.name_token,
                });
                continue;
            }
        }
        // Shape B: <arena>.allocator().<allocMethod>(...)
        if (query.matchPrefix(tree, inline_arena_alloc, start, b.rhs_last, null)) |m| {
            const arena_name = m.captureText(tree, 0).?;
            if (findArena(arenas.items, arena_name)) |a| {
                try slices.append(gpa, .{
                    .name = b.name,
                    .arena_name = a.name,
                    .name_token = b.name_token,
                });
            }
        }
    }
    if (slices.items.len == 0) return;

    // ── Pass 4: store calls ────────────────────────────────
    // For each `<recv>.<storeMethod>(...)` in the body, where recv
    // is NOT an arena/handle, scan the args (after the first) for
    // any identifier matching a known slice.
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    const calls = try query.findAllInBody(gpa, tree, store_call, first, last);
    defer gpa.free(calls);
    const tags = tree.tokens.items(.tag);

    for (calls) |c| {
        const method_tok = c.captures[1].?;
        if (!isStoreMethodName(tree.tokenSlice(method_tok))) continue;
        const recv_name = c.captureText(tree, 0).?;
        if (findArena(arenas.items, recv_name) != null) continue;
        if (findHandle(handles.items, recv_name) != null) continue;
        // Find the call's matching `)` to bound the args.
        const lp = method_tok + 1; // l_paren is right after method
        const rp = lexer.matchParen(tags, lp, last) orelse continue;
        // Split args at top-level commas.
        var args: std.ArrayListUnmanaged(Arg) = .empty;
        defer args.deinit(gpa);
        collectTopLevelArgs(gpa, tags, lp + 1, rp, &args) catch continue;
        if (args.items.len < 2) continue;
        // First arg must not be the arena's allocator.
        if (firstArgIsArenaAllocator(tree, args.items[0].start, args.items[0].end, arenas.items, handles.items)) continue;
        // Scan later args for a slice name.
        var i: usize = 1;
        while (i < args.items.len) : (i += 1) {
            const arg = args.items[i];
            var u: Ast.TokenIndex = arg.start;
            while (u <= arg.end) : (u += 1) {
                if (tags[u] != .identifier) continue;
                const s = findSlice(slices.items, tree.tokenSlice(u)) orelse continue;
                try report(gpa, problems, tree, method_tok, u, s);
                break;
            }
        }
    }
}

fn peelTry(tree: *const Ast, b: local.Binding) Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (b.rhs_first <= b.rhs_last and tags[b.rhs_first] == .keyword_try) {
        return b.rhs_first + 1;
    }
    return b.rhs_first;
}

fn isAllocMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "alloc") or
        std.mem.eql(u8, name, "allocSentinel") or
        std.mem.eql(u8, name, "dupe") or
        std.mem.eql(u8, name, "dupeZ") or
        std.mem.eql(u8, name, "create") or
        std.mem.eql(u8, name, "allocPrint") or
        std.mem.eql(u8, name, "allocPrintZ") or
        std.mem.eql(u8, name, "allocPrintSentinel");
}

fn isStoreMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "append") or
        std.mem.eql(u8, name, "appendSlice") or
        std.mem.eql(u8, name, "appendNTimes") or
        std.mem.eql(u8, name, "insert") or
        std.mem.eql(u8, name, "insertSlice") or
        std.mem.eql(u8, name, "put") or
        std.mem.eql(u8, name, "putAssumeCapacity") or
        std.mem.eql(u8, name, "putNoClobber") or
        std.mem.eql(u8, name, "addOne") or
        std.mem.eql(u8, name, "addManyAsSlice");
}

fn findArena(arenas: []const ArenaVar, name: []const u8) ?ArenaVar {
    for (arenas) |a| if (std.mem.eql(u8, a.name, name)) return a;
    return null;
}

fn findHandle(handles: []const AllocHandle, name: []const u8) ?AllocHandle {
    for (handles) |h| if (std.mem.eql(u8, h.name, name)) return h;
    return null;
}

fn findSlice(slices: []const ArenaSlice, name: []const u8) ?ArenaSlice {
    for (slices) |s| if (std.mem.eql(u8, s.name, name)) return s;
    return null;
}

const Arg = struct { start: Ast.TokenIndex, end: Ast.TokenIndex };

/// Split a call's args at top-level commas — used to inspect each
/// arg of a store call independently.  `[start, end)` is the range
/// between the `(` and `)` (exclusive of both).
fn collectTopLevelArgs(
    gpa: std.mem.Allocator,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    out: *std.ArrayListUnmanaged(Arg),
) !void {
    if (start >= end) return;
    var paren: u32 = 0;
    var brace: u32 = 0;
    var bracket: u32 = 0;
    var arg_start: Ast.TokenIndex = start;
    var t: Ast.TokenIndex = start;
    while (t < end) : (t += 1) {
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
            .comma => if (paren == 0 and brace == 0 and bracket == 0) {
                try out.append(gpa, .{ .start = arg_start, .end = t - 1 });
                arg_start = t + 1;
            },
            else => {},
        }
    }
    if (end > 0 and arg_start <= end - 1) {
        try out.append(gpa, .{ .start = arg_start, .end = end - 1 });
    }
}

fn firstArgIsArenaAllocator(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    arenas: []const ArenaVar,
    handles: []const AllocHandle,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    if (tags[start] != .identifier) return false;
    const name = tree.tokenSlice(start);
    if (start == end and findHandle(handles, name) != null) return true;
    if (end >= start + 4 and
        tags[start + 1] == .period and
        tags[start + 2] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(start + 2), "allocator") and
        tags[start + 3] == .l_paren and
        tags[start + 4] == .r_paren)
    {
        if (findArena(arenas, name) != null) return true;
    }
    return false;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    method_tok: Ast.TokenIndex,
    arg_tok: Ast.TokenIndex,
    s: ArenaSlice,
) !void {
    const method = tree.tokenSlice(method_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}` (allocated through arena `{s}`) is being stored via `.{s}(...)` into a container whose allocator is NOT the arena — when `{s}` is deinit'd at scope exit, the container will hold a dangling slice",
        .{ s.name, s.arena_name, method, s.arena_name },
    );
    errdefer gpa.free(msg);

    const note_label = try std.fmt.allocPrint(
        gpa,
        "allocated through arena `{s}` here",
        .{s.arena_name},
    );
    errdefer gpa.free(note_label);

    var notes = try gpa.alloc(problem_mod.Note, 1);
    errdefer gpa.free(notes);
    notes[0] = .{
        .start = Pos.fromTokenStart(tree, s.name_token),
        .end = Pos.fromTokenEnd(tree, s.name_token),
        .label = note_label,
    };

    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, arg_tok),
        .end = Pos.fromTokenEnd(tree, arg_tok),
        .message = msg,
        .notes = notes,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "arena slice stored into heap container fires" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\const Self = struct {
        \\    gpa: std.mem.Allocator,
        \\    cache: std.ArrayList(u8),
        \\    pub fn parse(self: *Self) !void {
        \\        var arena = std.heap.ArenaAllocator.init(self.gpa);
        \\        defer arena.deinit();
        \\        const arena_alloc = arena.allocator();
        \\        const tokens = try arena_alloc.alloc(u8, 16);
        \\        try self.cache.appendSlice(self.gpa, tokens);
        \\    }
        \\};
    );
}

test "stored into ARENA sub-container doesn't fire" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\pub fn ok(gpa: std.mem.Allocator) !void {
        \\    var arena = std.heap.ArenaAllocator.init(gpa);
        \\    defer arena.deinit();
        \\    const arena_alloc = arena.allocator();
        \\    const tokens = try arena_alloc.alloc(u8, 16);
        \\    var sub_list = std.ArrayList(u8).empty;
        \\    try sub_list.appendSlice(arena_alloc, tokens);
        \\}
    );
}

test "inline arena.allocator() form caught" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\const Self = struct {
        \\    gpa: std.mem.Allocator,
        \\    cache: std.ArrayList(u8),
        \\    pub fn parse(self: *Self) !void {
        \\        var arena = std.heap.ArenaAllocator.init(self.gpa);
        \\        defer arena.deinit();
        \\        const tokens = try arena.allocator().alloc(u8, 16);
        \\        try self.cache.appendSlice(self.gpa, tokens);
        \\    }
        \\};
    );
}

test "no arena in fn → no work" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\pub fn ok(gpa: std.mem.Allocator) !void {
        \\    const tokens = try gpa.alloc(u8, 16);
        \\    var cache = std.ArrayList(u8).empty;
        \\    try cache.appendSlice(gpa, tokens);
        \\}
    );
}

test "dupe through arena handle counts as alloc method" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\const Self = struct {
        \\    gpa: std.mem.Allocator,
        \\    names: std.ArrayList([]const u8),
        \\    pub fn parse(self: *Self, input: []const u8) !void {
        \\        var arena = std.heap.ArenaAllocator.init(self.gpa);
        \\        defer arena.deinit();
        \\        const a = arena.allocator();
        \\        const dup = try a.dupe(u8, input);
        \\        try self.names.append(self.gpa, dup);
        \\    }
        \\};
    );
}
