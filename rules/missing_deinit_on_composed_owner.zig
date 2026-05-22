//! Missing-deinit-on-composed-owner detector — a struct `Outer`
//! exposes `pub fn deinit(...)`.  One of its fields has a TYPE
//! that's a struct in the same file ALSO exposing
//! `pub fn deinit`/`close`/`destroy`/`free`/`stop`.  But
//! `Outer.deinit` doesn't call `self.<field>.deinit(...)` (or any
//! cleanup method) — the inner's destructor is never invoked, so
//! the inner's owned non-memory resources (file handles, sockets,
//! mmaps, refs) leak.
//!
//! Real-world: ziglang/zig#22683 (`StackIterator.deinit` forgot
//! to call `it.ma.deinit()` → `/proc/self/mem` file handle
//! leaked; the PR had to ADD `MemoryAccessor.deinit` first,
//! suggesting the pattern is under-detected).  Same family as
//! ziglang/zig#20192 (intermediate `Dir` handles leaked) and
//! ziglang/zig#18651 (Thread.Pool init cleanup gap).
//!
//! Detection (purely syntactic, per-file token walk):
//!   1. Scan the file for `struct { ... }` bodies that contain
//!      `pub fn deinit(`.
//!   2. Within each such struct body, collect the field declarations
//!      `<name>: <type-tokens>,` where the first identifier of
//!      `<type-tokens>` (after optional `?`/`*`) is the type's name.
//!   3. Also collect the set of struct types in the file that have
//!      a `pub fn deinit`.
//!   4. For each field whose type name is in the "has-deinit" set
//!      AND the outer deinit's body doesn't call `<self>.<field>.<cleanup>(`,
//!      fire.

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
    if (!config_mod.isEnabled(config, .missing_deinit_on_composed_owner)) return;

    const tags = tree.tokens.items(.tag);
    const tok_count: u32 = @intCast(tree.tokens.len);
    if (tok_count == 0) return;
    const last: Ast.TokenIndex = tok_count - 1;

    // Pass 1: collect all struct types in the file that have a
    // `pub fn deinit` / `pub fn close` / `pub fn destroy` /
    // `pub fn free` / `pub fn stop` method.  Identified by
    // `const <Name> = struct { ... }` declarations whose body
    // contains a matching fn.
    var struct_with_deinit: std.StringHashMapUnmanaged(void) = .empty;
    defer struct_with_deinit.deinit(gpa);

    var t: Ast.TokenIndex = 0;
    while (t + 5 < last) : (t += 1) {
        if (tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        // Walk past optional `: type` and find `=`.
        var eq: Ast.TokenIndex = t + 2;
        while (eq < last and tags[eq] != .equal and tags[eq] != .semicolon) : (eq += 1) {}
        if (eq >= last or tags[eq] != .equal) continue;
        if (eq + 1 > last) continue;
        if (tags[eq + 1] != .keyword_struct) continue;
        if (eq + 2 > last or tags[eq + 2] != .l_brace) continue;
        const body_start = eq + 2;
        const body_end = matchBrace(tags, body_start, last) orelse continue;
        if (structBodyHasCleanupFn(tree, body_start + 1, body_end - 1)) {
            const name = tree.tokenSlice(t + 1);
            try struct_with_deinit.put(gpa, name, {});
        }
        t = body_end;
    }

    // Pass 2: for each struct with a deinit, check its fields
    // against the has-deinit set.
    t = 0;
    while (t + 5 < last) : (t += 1) {
        if (tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        var eq: Ast.TokenIndex = t + 2;
        while (eq < last and tags[eq] != .equal and tags[eq] != .semicolon) : (eq += 1) {}
        if (eq >= last or tags[eq] != .equal) continue;
        if (eq + 1 > last) continue;
        if (tags[eq + 1] != .keyword_struct) continue;
        if (eq + 2 > last or tags[eq + 2] != .l_brace) continue;
        const body_start = eq + 2;
        const body_end = matchBrace(tags, body_start, last) orelse continue;
        const deinit_body = findCleanupFnBody(tree, body_start + 1, body_end - 1, "deinit") orelse {
            t = body_end;
            continue;
        };
        try checkStructFields(gpa, tree, body_start + 1, body_end - 1, deinit_body, &struct_with_deinit, problems);
        t = body_end;
    }
}

const FnBody = struct {
    body_start: Ast.TokenIndex,
    body_end: Ast.TokenIndex,
};

/// True iff the struct body has any `pub fn <cleanup-name>(...)`.
fn structBodyHasCleanupFn(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = matchBrace(tags, t, end) orelse return false;
            continue;
        }
        if (tags[t] != .keyword_fn) continue;
        if (tags[t + 1] != .identifier) continue;
        const name = tree.tokenSlice(t + 1);
        if (isCleanupFnName(name)) return true;
    }
    return false;
}

/// Find the body of a fn named `wanted` inside `[start, end]`.
fn findCleanupFnBody(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    wanted: []const u8,
) ?FnBody {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = matchBrace(tags, t, end) orelse return null;
            continue;
        }
        if (tags[t] != .keyword_fn) continue;
        if (tags[t + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 1), wanted)) continue;
        var u: Ast.TokenIndex = t + 2;
        while (u <= end and tags[u] != .l_brace) : (u += 1) {}
        if (u > end) return null;
        const body_end = matchBrace(tags, u, end) orelse return null;
        return .{ .body_start = u + 1, .body_end = body_end - 1 };
    }
    return null;
}

fn isCleanupFnName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "close") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "stop") or
        std.mem.eql(u8, name, "finalize");
}

/// Walk the struct body (skipping nested braces and fn bodies) for
/// field declarations `<name>: <type-tokens>,` at the struct's
/// top level.
fn checkStructFields(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    deinit_body: FnBody,
    has_deinit: *const std.StringHashMapUnmanaged(void),
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        // Skip nested braces (fn bodies, nested struct types, etc.).
        if (tags[t] == .l_brace) {
            t = matchBrace(tags, t, end) orelse break;
            continue;
        }
        // Skip fn declarations ENTIRELY — including the parameter
        // list `(...)` and the body `{...}`.  Otherwise we'd
        // misread fn parameters (`fn deinit(self: *Outer)`) as
        // struct fields.
        if (tags[t] == .keyword_fn) {
            // Advance past the proto's `(` then its matching `)`,
            // then past the body's `{` matched against `}`.
            var u: Ast.TokenIndex = t + 1;
            // Find the proto's `(`.
            while (u <= end and tags[u] != .l_paren) : (u += 1) {}
            if (u > end) break;
            const cp = matchParen(tags, u, end) orelse break;
            // Find the body's `{` after the proto.
            var b: Ast.TokenIndex = cp + 1;
            while (b <= end and tags[b] != .l_brace) : (b += 1) {}
            if (b > end) {
                t = cp;
                continue;
            }
            const body_close = matchBrace(tags, b, end) orelse break;
            t = body_close;
            continue;
        }
        // Field shape: `<name>: <type-tokens> (= <default>)?,`
        if (tags[t] == .keyword_pub or tags[t] == .keyword_const or
            tags[t] == .keyword_var) continue;
        if (tags[t] != .identifier) continue;
        if (t + 1 > end or tags[t + 1] != .colon) continue;
        // Skip if preceded by something other than `,` or `{`
        // (i.e., this isn't a top-level field).  For first cut be
        // permissive — fields are most identifier-colon sequences
        // at this depth.
        const field_name = tree.tokenSlice(t);
        // Restrict to VALUE-typed fields (peel optional `?` only).
        // Pointer / slice fields are usually borrows in Zig; the
        // distinction between "owned pointer" and "borrowed
        // pointer" is invisible at the type level and treating
        // all pointer fields as owned produces many FPs.  Value-
        // typed fields are the cleanest "I own this" signal.
        var ty: Ast.TokenIndex = t + 2;
        // Peel optional prefix only.
        if (ty <= end and tags[ty] == .question_mark) ty += 1;
        if (ty > end or tags[ty] != .identifier) continue;
        const type_name = tree.tokenSlice(ty);
        if (!has_deinit.contains(type_name)) continue;
        // Field's type has a deinit.  Check the outer deinit body
        // for `<self>.<field>.<cleanup>(`.
        if (!deinitBodyCallsCleanupOnField(tree, deinit_body.body_start, deinit_body.body_end, field_name)) {
            try report(gpa, problems, tree, t, field_name, type_name);
        }
        // Advance past this field's `,` to avoid double-matching
        // the same token if `t` overlaps the next field.
        const sc = findStmtCommaOrSemi(tags, ty, end);
        if (sc) |s| t = s;
    }
}

/// True iff `[start, end]` contains a call shape `<X>.<field>.<cleanup>(`.
/// Receiver `<X>` is wildcarded — any single identifier (typically
/// `self` / `this` / the receiver name).
fn deinitBodyCallsCleanupOnField(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    field: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t + 5 <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), field)) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        if (tags[t + 5] != .l_paren) continue;
        if (isCleanupFnName(tree.tokenSlice(t + 4))) return true;
    }
    return false;
}

fn findStmtCommaOrSemi(
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
            .comma, .semicolon => if (paren == 0 and brace == 0 and bracket == 0) return t,
            else => {},
        }
    }
    return null;
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
    field_tok: Ast.TokenIndex,
    field_name: []const u8,
    type_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "field `{s}: {s}` has a `deinit`-exposing type, but the outer struct's `deinit` doesn't call `<self>.{s}.deinit(...)` — the inner's owned non-memory resources (file handles, sockets, refs, mmaps) leak",
        .{ field_name, type_name, field_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "missing-deinit-on-composed-owner",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, field_tok),
        .end = Pos.fromTokenEnd(tree, field_tok),
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

test "missing-deinit-on-composed-owner: outer deinit forgets inner field deinit fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const MemoryAccessor = struct {
        \\    fd: i32,
        \\    pub fn deinit(self: *MemoryAccessor) void { _ = self; }
        \\};
        \\const StackIterator = struct {
        \\    ma: MemoryAccessor,
        \\    pub fn deinit(it: *StackIterator) void {
        \\        _ = it;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
    try std.testing.expectEqualStrings("missing-deinit-on-composed-owner", problems.items[0].rule_id);
}

test "missing-deinit-on-composed-owner: outer deinit calls inner deinit — no fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const MemoryAccessor = struct {
        \\    pub fn deinit(self: *MemoryAccessor) void { _ = self; }
        \\};
        \\const StackIterator = struct {
        \\    ma: MemoryAccessor,
        \\    pub fn deinit(it: *StackIterator) void {
        \\        it.ma.deinit();
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-deinit-on-composed-owner: field type has no deinit — no fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Plain = struct { x: u32 };
        \\const Outer = struct {
        \\    p: Plain,
        \\    pub fn deinit(self: *Outer) void { _ = self; }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-deinit-on-composed-owner: pointer field (likely borrow) doesn't fire" {
    // `?*Inner` and `*Inner` are most often borrowed references
    // in Zig (the distinction between owned vs borrowed pointer
    // isn't visible in the type).  Rule restricts to value-typed
    // fields, where ownership is unambiguous.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?*Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        _ = self;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-deinit-on-composed-owner: optional value-typed field (?Inner) fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        _ = self;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
}
