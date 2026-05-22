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
//!   // arena.deinit() fires at scope exit → self.token_cache now
//!   // holds dangling slices.
//!
//! Complements zbc's existing `arena_escape` rule (caught via
//! return) and `arena_use_after_kill` (caught via post-deinit
//! read).  This rule catches the third escape path: STORE into a
//! longer-lived container during the arena's lifetime.
//!
//! Detection (purely syntactic, per-fn token walk; four passes):
//!   1. Find local arena vars: `var <A> = std.heap.ArenaAllocator.init(`
//!      bindings.  Skip fns with no arena.
//!   2. Find allocator handles: `const <H> = <A>.allocator();` —
//!      `<H>` is then treated as an alias for `<A>.allocator()`.
//!   3. Find arena-allocated slice bindings: `const <X> = [try]
//!      <H>.<alloc-method>(...)` OR `const <X> = [try]
//!      <A>.allocator().<alloc-method>(...)`.
//!   4. Find store calls `<C>.<store-method>(<arg0>, ..., <argN>)`
//!      where:
//!        - `<store-method>` is in the container-store allowlist,
//!        - `<arg0>` is the allocator slot and is NOT the arena
//!          allocator (not `<H>`, not `<A>.allocator()`),
//!        - any later arg is one of the arena-allocated `<X>`s.
//!      Fire at the call site.

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
    if (!config_mod.isEnabled(config, .slice_of_arena_into_heap)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
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
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var arenas: std.ArrayListUnmanaged(ArenaVar) = .empty;
    defer arenas.deinit(gpa);
    try collectArenaVars(gpa, tree, first, last, &arenas);
    if (arenas.items.len == 0) return;

    var handles: std.ArrayListUnmanaged(AllocHandle) = .empty;
    defer handles.deinit(gpa);
    try collectAllocHandles(gpa, tree, first, last, arenas.items, &handles);

    var slices: std.ArrayListUnmanaged(ArenaSlice) = .empty;
    defer slices.deinit(gpa);
    try collectArenaSlices(gpa, tree, first, last, arenas.items, handles.items, &slices);
    if (slices.items.len == 0) return;

    try findStores(gpa, tree, first, last, arenas.items, handles.items, slices.items, problems);
}

/// Walk for `var <A> = std.heap.ArenaAllocator.init(` (or `: T = .init(`
/// shorthand, or chained construction).  We accept any binding whose
/// RHS source-text contains `ArenaAllocator.init(` — the same heuristic
/// the existing config uses (`arena_init_patterns`).
fn collectArenaVars(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    out: *std.ArrayListUnmanaged(ArenaVar),
) !void {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;
        // Walk to `=`.
        var after_name: Ast.TokenIndex = t + 2;
        if (after_name <= last and tags[after_name] == .colon) {
            var d: u32 = 0;
            while (after_name <= last) : (after_name += 1) {
                switch (tags[after_name]) {
                    .l_paren, .l_brace, .l_bracket => d += 1,
                    .r_paren, .r_brace, .r_bracket => if (d > 0) {
                        d -= 1;
                    },
                    .equal => if (d == 0) break,
                    else => {},
                }
            }
        }
        if (after_name > last or tags[after_name] != .equal) continue;
        const sc = findStmtSemicolon(tags, after_name + 1, last) orelse continue;
        // Match `ArenaAllocator . init (` token sequence anywhere
        // in the RHS.
        var u: Ast.TokenIndex = after_name + 1;
        var found = false;
        while (u + 3 <= sc) : (u += 1) {
            if (tags[u] != .identifier) continue;
            if (!std.mem.eql(u8, tree.tokenSlice(u), "ArenaAllocator")) continue;
            if (tags[u + 1] != .period) continue;
            if (tags[u + 2] != .identifier) continue;
            if (tags[u + 3] != .l_paren) continue;
            if (std.mem.eql(u8, tree.tokenSlice(u + 2), "init")) {
                found = true;
                break;
            }
        }
        if (!found) continue;
        try out.append(gpa, .{
            .name = tree.tokenSlice(t + 1),
            .init_token = t + 1,
        });
    }
}

/// Walk for `const <H> = <A>.allocator();` where `<A>` ∈ arena_vars.
fn collectAllocHandles(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    arenas: []const ArenaVar,
    out: *std.ArrayListUnmanaged(AllocHandle),
) !void {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 6 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        var after_name: Ast.TokenIndex = t + 2;
        if (after_name <= last and tags[after_name] == .colon) {
            var d: u32 = 0;
            while (after_name <= last) : (after_name += 1) {
                switch (tags[after_name]) {
                    .l_paren, .l_brace, .l_bracket => d += 1,
                    .r_paren, .r_brace, .r_bracket => if (d > 0) {
                        d -= 1;
                    },
                    .equal => if (d == 0) break,
                    else => {},
                }
            }
        }
        if (after_name > last or tags[after_name] != .equal) continue;
        const rhs = after_name + 1;
        if (rhs + 4 > last) continue;
        if (tags[rhs] != .identifier) continue;
        if (tags[rhs + 1] != .period) continue;
        if (tags[rhs + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(rhs + 2), "allocator")) continue;
        if (tags[rhs + 3] != .l_paren) continue;
        if (tags[rhs + 4] != .r_paren) continue;
        const recv = tree.tokenSlice(rhs);
        if (findArena(arenas, recv) == null) continue;
        try out.append(gpa, .{
            .name = tree.tokenSlice(t + 1),
            .arena_name = recv,
        });
    }
}

/// Walk for `const <X> = [try] <H>.<alloc-method>(...)` where `<H>`
/// is an alloc handle, OR `const <X> = [try] <A>.allocator().<alloc-method>(...)`
/// inline form.
fn collectArenaSlices(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    arenas: []const ArenaVar,
    handles: []const AllocHandle,
    out: *std.ArrayListUnmanaged(ArenaSlice),
) !void {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        var after_name: Ast.TokenIndex = t + 2;
        if (after_name <= last and tags[after_name] == .colon) {
            var d: u32 = 0;
            while (after_name <= last) : (after_name += 1) {
                switch (tags[after_name]) {
                    .l_paren, .l_brace, .l_bracket => d += 1,
                    .r_paren, .r_brace, .r_bracket => if (d > 0) {
                        d -= 1;
                    },
                    .equal => if (d == 0) break,
                    else => {},
                }
            }
        }
        if (after_name > last or tags[after_name] != .equal) continue;
        var rhs: Ast.TokenIndex = after_name + 1;
        if (rhs <= last and tags[rhs] == .keyword_try) rhs += 1;
        if (rhs + 3 > last) continue;
        const arena_name = matchAllocCall(tree, rhs, last, arenas, handles) orelse continue;
        try out.append(gpa, .{
            .name = tree.tokenSlice(t + 1),
            .arena_name = arena_name,
            .name_token = t + 1,
        });
    }
}

/// Recognize either `<H>.<alloc-method>(` or
/// `<A>.allocator().<alloc-method>(`.  Returns the arena name on
/// match, null otherwise.
fn matchAllocCall(
    tree: *const Ast,
    rhs: Ast.TokenIndex,
    last: Ast.TokenIndex,
    arenas: []const ArenaVar,
    handles: []const AllocHandle,
) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (tags[rhs] != .identifier) return null;
    // Shape A: `<H>.<method>(`
    if (rhs + 3 <= last and tags[rhs + 1] == .period and
        tags[rhs + 2] == .identifier and tags[rhs + 3] == .l_paren)
    {
        const m = tree.tokenSlice(rhs + 2);
        if (isAllocMethodName(m)) {
            const recv = tree.tokenSlice(rhs);
            if (findHandle(handles, recv)) |h| return h.arena_name;
        }
    }
    // Shape B: `<A>.allocator().<method>(`
    if (rhs + 6 <= last and
        tags[rhs + 1] == .period and
        tags[rhs + 2] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(rhs + 2), "allocator") and
        tags[rhs + 3] == .l_paren and
        tags[rhs + 4] == .r_paren and
        tags[rhs + 5] == .period and
        tags[rhs + 6] == .identifier and
        rhs + 7 <= last and tags[rhs + 7] == .l_paren)
    {
        const m = tree.tokenSlice(rhs + 6);
        if (isAllocMethodName(m)) {
            const recv = tree.tokenSlice(rhs);
            if (findArena(arenas, recv)) |a| return a.name;
        }
    }
    return null;
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
    for (arenas) |a| {
        if (std.mem.eql(u8, a.name, name)) return a;
    }
    return null;
}

fn findHandle(handles: []const AllocHandle, name: []const u8) ?AllocHandle {
    for (handles) |h| {
        if (std.mem.eql(u8, h.name, name)) return h;
    }
    return null;
}

fn findSlice(slices: []const ArenaSlice, name: []const u8) ?ArenaSlice {
    for (slices) |s| {
        if (std.mem.eql(u8, s.name, name)) return s;
    }
    return null;
}

/// Walk for store calls and fire on each match.
fn findStores(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    arenas: []const ArenaVar,
    handles: []const AllocHandle,
    slices: []const ArenaSlice,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        const method = tree.tokenSlice(t + 2);
        if (!isStoreMethodName(method)) continue;
        const recv_name = tree.tokenSlice(t);
        // Receiver must NOT be an arena var or its handle — storing
        // into a same-arena sub-container is fine.
        if (findArena(arenas, recv_name) != null) continue;
        if (findHandle(handles, recv_name) != null) continue;
        // Find the matching close-paren and inspect args.
        const cp = matchParen(tags, t + 3, last) orelse continue;
        var args_buf: std.ArrayListUnmanaged(Arg) = .empty;
        defer args_buf.deinit(gpa);
        collectTopLevelArgs(gpa, tags, t + 4, cp, &args_buf) catch continue;
        const args = args_buf.items;
        if (args.len < 2) continue;
        // First arg should be a non-arena allocator.  If it IS the
        // arena's allocator (`<A>.allocator()` or `<H>`), this is a
        // sub-container of the arena — skip.
        if (firstArgIsArenaAllocator(tree, args[0].start, args[0].end, arenas, handles)) continue;
        // Scan the remaining args for an arena-allocated slice.
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            // Look for any identifier in the arg that matches a known
            // arena slice name.
            var u: Ast.TokenIndex = arg.start;
            while (u <= arg.end) : (u += 1) {
                if (tags[u] != .identifier) continue;
                const s = findSlice(slices, tree.tokenSlice(u)) orelse continue;
                try report(gpa, problems, tree, t + 2, u, s);
                break;
            }
        }
        t = cp;
    }
}

const Arg = struct { start: Ast.TokenIndex, end: Ast.TokenIndex };

/// Split a call's args at top-level commas, appending one Arg per
/// argument into `out`.  Caller owns `out` (and must `deinit` it).
/// Returns an error on allocation failure.
fn collectTopLevelArgs(
    gpa: std.mem.Allocator,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    out: *std.ArrayListUnmanaged(Arg),
) !void {
    if (start > end) return;
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

/// True if the arg at `[start, end]` is `<A>.allocator()` (with `<A>`
/// in arenas) or just `<H>` (an alloc handle).
fn firstArgIsArenaAllocator(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    arenas: []const ArenaVar,
    handles: []const AllocHandle,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    // Trim leading whitespace tokens? Tokens don't include whitespace.
    if (tags[start] != .identifier) return false;
    const name = tree.tokenSlice(start);
    // Shape: bare `<H>`.
    if (start == end and findHandle(handles, name) != null) return true;
    // Shape: `<A>.allocator()`.
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

fn matchParen(
    tags: []const std.zig.Token.Tag,
    lp: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var depth: u32 = 1;
    var t: Ast.TokenIndex = lp + 1;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_paren => depth += 1,
            .r_paren => {
                depth -= 1;
                if (depth == 0) return t;
            },
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
        .rule_id = "slice-of-arena-into-heap",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, arg_tok),
        .end = Pos.fromTokenEnd(tree, arg_tok),
        .message = msg,
        .notes = notes,
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

test "slice-of-arena-into-heap: arena slice stored into heap container fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
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
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("slice-of-arena-into-heap", problems.items[0].rule_id);
}

test "slice-of-arena-into-heap: stored into ARENA sub-container doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(gpa: std.mem.Allocator) !void {
        \\    var arena = std.heap.ArenaAllocator.init(gpa);
        \\    defer arena.deinit();
        \\    const arena_alloc = arena.allocator();
        \\    const tokens = try arena_alloc.alloc(u8, 16);
        \\    var sub_list = std.ArrayList(u8).empty;
        \\    try sub_list.appendSlice(arena_alloc, tokens);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "slice-of-arena-into-heap: inline arena.allocator() form caught" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
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
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "slice-of-arena-into-heap: no arena in fn → no work" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(gpa: std.mem.Allocator) !void {
        \\    const tokens = try gpa.alloc(u8, 16);
        \\    var cache = std.ArrayList(u8).empty;
        \\    try cache.appendSlice(gpa, tokens);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "slice-of-arena-into-heap: dupe through arena handle counts as alloc method" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
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
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
