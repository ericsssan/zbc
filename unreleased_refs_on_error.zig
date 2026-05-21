//! hexops/mach (sysgpu/vulkan.zig:1887) detector — `<obj>.<addref>()`
//! calls inside a loop body acquire refcounted references, followed
//! by a later `try` in the same fn with no `errdefer` containing a
//! `.release()` / `.deref()` cleanup.  On the try's error path every
//! reference taken in the loop leaks.
//!
//! Real-world: `PipelineLayout.init` calls
//! `layout.manager.reference()` inside a per-bind-group loop, then
//! `try vkd.createPipelineLayout(...)` and `try allocator.create(...)`
//! follow.  The only errdefer (`allocator.free(group_layouts)`)
//! reclaims the slice memory but never releases the refs.  Any
//! failure of the post-loop tries leaks N BindGroupLayout refs —
//! these accumulate every time a pipeline create races a device
//! error, and eventually OOMs the GPU descriptor pool.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. For each non-type-builder fn whose body contains at least
//!      one `try` keyword (proxy for "returns error union").
//!   2. Walk tokens to find every `for (…)` / `while (…)` loop with
//!      a block body.
//!   3. Inside the loop body, find any `<chain>.<method>(` call where
//!      `method ∈ {reference, retain, addRef, addref}`.
//!   4. After the loop's closing brace, find the next `try` keyword
//!      in the same fn body.
//!   5. Scan the WHOLE fn body for any `errdefer` containing a
//!      method call whose name ∈ {release, deref, unref, removeRef}.
//!      Any such errdefer suppresses the report — we can't easily
//!      verify the errdefer references the same objects, so we lean
//!      toward zero FPs and trust that any release-class errdefer
//!      means the author thought about the leak.
//!   6. Fire at the addref call site.

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
    if (!config_mod.isEnabled(config, .unreleased_refs_on_error)) return;

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

    // Gate: only fns that actually use `try` (proxy for error union
    // return).  Without a `try` there can't be the post-loop error
    // path this rule fires on.
    if (!hasTokenInRange(tags, first, last, .keyword_try)) return;

    // Cheap pre-pass: any release-class errdefer in this fn body?
    // If so, every loop in it is considered protected and we skip the
    // whole fn.  This is the rule's main precision lever — broader
    // release-method list = fewer fires = lower FP rate.
    if (fnHasReleaseErrdefer(tree, first, last)) return;

    var t: Ast.TokenIndex = first;
    while (t + 4 <= last) : (t += 1) {
        // Skip past nested fns so inner-fn loops aren't double-scanned
        // through the outer.
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_for and tags[t] != .keyword_while) continue;
        if (tags[t + 1] != .l_paren) continue;

        const close_paren = matchParen(tags, t + 1, last) orelse continue;
        // Optional `|capture|` after `)`.
        var body_start: Ast.TokenIndex = close_paren + 1;
        if (body_start <= last and tags[body_start] == .pipe) {
            // Find closing pipe.
            var p: Ast.TokenIndex = body_start + 1;
            while (p <= last and tags[p] != .pipe) : (p += 1) {}
            if (p > last) continue;
            body_start = p + 1;
        }
        if (body_start > last) continue;

        // Support both block-body and inline-body loops.  Inline form
        // (`for (xs) |x| x.reference();`) is the entire loop body up
        // to its statement-terminating `;`.
        const is_block = tags[body_start] == .l_brace;
        const loop_body_end = if (is_block)
            (matchBrace(tags, body_start, last) orelse continue)
        else
            (findStmtSemicolon(tags, body_start, last) orelse continue);
        const scan_start = if (is_block) body_start + 1 else body_start;
        const scan_end = if (is_block) loop_body_end - 1 else loop_body_end;

        // Find an addref method call inside the loop body.
        const addref_tok = findAddrefCallIn(tree, scan_start, scan_end) orelse {
            t = loop_body_end;
            continue;
        };

        // Find next `try` after the loop in the same fn body.
        if (!hasTokenInRange(tags, loop_body_end + 1, last, .keyword_try)) {
            t = loop_body_end;
            continue;
        }

        try report(gpa, problems, tree, addref_tok);
        t = loop_body_end;
    }
}

/// Names of methods that acquire a refcounted reference.  Kept tight
/// to avoid coincidental matches — `ref` alone is excluded (too
/// generic; collides with "borrow a sub-reference" usage like
/// `cmd.ref(buf)` in command-buffer APIs).
fn isAddrefMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "reference") or
        std.mem.eql(u8, name, "retain") or
        std.mem.eql(u8, name, "addRef") or
        std.mem.eql(u8, name, "addref");
}

/// Names of methods that release a refcounted reference.  Broader
/// than addref's list — an errdefer with any of these counts as
/// "author thought about the leak."  Used only to suppress the
/// report, so over-inclusion = under-fire (preferred for precision).
fn isReleaseMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "release") or
        std.mem.eql(u8, name, "deref") or
        std.mem.eql(u8, name, "unref") or
        std.mem.eql(u8, name, "removeRef");
}

/// Scan `[start, end]` for a `<chain>.<method>(` call where `method`
/// is an addref name.  Returns the token index of the method name on
/// hit, or null on miss.
fn findAddrefCallIn(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (end < start or end > tree.tokens.len) return null;
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        if (isAddrefMethodName(tree.tokenSlice(t + 1))) return t + 1;
    }
    return null;
}

/// True iff some `errdefer` in `[start, end]` contains (in its inline
/// or block body) a `.<release-method>(` call.
fn fnHasReleaseErrdefer(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] != .keyword_errdefer) continue;
        // Skip optional `|err|` capture.
        var scan_start: Ast.TokenIndex = t + 1;
        if (scan_start <= end and tags[scan_start] == .pipe) {
            var p: Ast.TokenIndex = scan_start + 1;
            while (p <= end and tags[p] != .pipe) : (p += 1) {}
            if (p > end) return false;
            scan_start = p + 1;
        }
        if (scan_start > end) return false;
        const range_end = if (tags[scan_start] == .l_brace)
            (matchBrace(tags, scan_start, end) orelse end)
        else
            (findStmtSemicolon(tags, scan_start, end) orelse end);
        if (rangeHasReleaseCall(tree, scan_start, range_end)) return true;
        t = range_end;
    }
    return false;
}

fn rangeHasReleaseCall(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        if (isReleaseMethodName(tree.tokenSlice(t + 1))) return true;
    }
    return false;
}

fn hasTokenInRange(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    needle: std.zig.Token.Tag,
) bool {
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] == needle) return true;
    }
    return false;
}

/// Given a token index at `l_paren`, find the matching `r_paren`.
fn matchParen(tags: []const std.zig.Token.Tag, lp: Ast.TokenIndex, last: Ast.TokenIndex) ?Ast.TokenIndex {
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

fn matchBrace(tags: []const std.zig.Token.Tag, lb: Ast.TokenIndex, last: Ast.TokenIndex) ?Ast.TokenIndex {
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

fn findStmtSemicolon(tags: []const std.zig.Token.Tag, start: Ast.TokenIndex, last: Ast.TokenIndex) ?Ast.TokenIndex {
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

fn skipNestedFn(tags: []const std.zig.Token.Tag, start: Ast.TokenIndex, last: Ast.TokenIndex) Ast.TokenIndex {
    // Walk forward until we hit the body `{` and then find its match.
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
) !void {
    const method = tree.tokenSlice(method_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}()` inside this loop acquires a refcounted reference, but the enclosing fn has a later `try` with no `errdefer` calling `.release()` / `.deref()` — every reference taken leaks if that `try` propagates an error",
        .{method},
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "unreleased-refs-on-error",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, method_tok),
        .end = Pos.fromTokenEnd(tree, method_tok),
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

test "unreleased-refs-on-error: loop with .reference() then try without errdefer fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const BindGroupLayout = struct {
        \\    manager: Manager = .{},
        \\    pub const Manager = struct {
        \\        pub fn reference(_: *Manager) void {}
        \\        pub fn release(_: *Manager) void {}
        \\    };
        \\};
        \\pub fn init(allocator: std.mem.Allocator, layouts: []*BindGroupLayout) !*u8 {
        \\    const group_layouts = try allocator.alloc(*BindGroupLayout, layouts.len);
        \\    errdefer allocator.free(group_layouts);
        \\    for (layouts, 0..) |layout, i| {
        \\        layout.manager.reference();
        \\        group_layouts[i] = layout;
        \\    }
        \\    const out = try allocator.create(u8);
        \\    return out;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("unreleased-refs-on-error", problems.items[0].rule_id);
}

test "unreleased-refs-on-error: with errdefer .release() loop is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const BindGroupLayout = struct {
        \\    manager: Manager = .{},
        \\    pub const Manager = struct {
        \\        pub fn reference(_: *Manager) void {}
        \\        pub fn release(_: *Manager) void {}
        \\    };
        \\};
        \\pub fn init(allocator: std.mem.Allocator, layouts: []*BindGroupLayout) !*u8 {
        \\    const group_layouts = try allocator.alloc(*BindGroupLayout, layouts.len);
        \\    errdefer allocator.free(group_layouts);
        \\    var taken: usize = 0;
        \\    errdefer for (group_layouts[0..taken]) |l| l.manager.release();
        \\    for (layouts, 0..) |layout, i| {
        \\        layout.manager.reference();
        \\        group_layouts[i] = layout;
        \\        taken += 1;
        \\    }
        \\    const out = try allocator.create(u8);
        \\    return out;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "unreleased-refs-on-error: no try after loop doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Manager = struct { pub fn reference(_: *Manager) void {} };
        \\pub fn init(items: []*Manager) !void {
        \\    for (items) |m| m.reference();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "unreleased-refs-on-error: non-error-union fn (no try) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Manager = struct { pub fn reference(_: *Manager) void {} };
        \\pub fn init(items: []*Manager) void {
        \\    for (items) |m| m.reference();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "unreleased-refs-on-error: retain (ObjC-style) variant also caught" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Obj = struct {
        \\    pub fn retain(_: *Obj) void {}
        \\    pub fn release(_: *Obj) void {}
        \\};
        \\pub fn build(items: []*Obj) !void {
        \\    for (items) |o| {
        \\        o.retain();
        \\    }
        \\    _ = try makeSomething();
        \\}
        \\fn makeSomething() !u8 { return 0; }
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "unreleased-refs-on-error: errdefer .deref() (Bun-style) also protects" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Obj = struct {
        \\    pub fn retain(_: *Obj) void {}
        \\    pub fn deref(_: *Obj) void {}
        \\};
        \\pub fn build(items: []*Obj) !void {
        \\    for (items) |o| o.retain();
        \\    errdefer for (items) |o| o.deref();
        \\    _ = try makeSomething();
        \\}
        \\fn makeSomething() !u8 { return 0; }
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "unreleased-refs-on-error: comptime type-builder fn skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Manager = struct { pub fn reference(_: *Manager) void {} };
        \\pub fn Wrap(comptime _: type) type {
        \\    return struct {
        \\        pub fn build(items: []*Manager) !void {
        \\            for (items) |m| m.reference();
        \\            _ = try makeSomething();
        \\        }
        \\        fn makeSomething() !u8 { return 0; }
        \\    };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // The inner fn does have the bug — we should fire on it once, but
    // NOT double-count via the outer Wrap fn.
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
