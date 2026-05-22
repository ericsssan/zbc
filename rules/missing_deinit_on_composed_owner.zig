//! Missing-deinit-on-composed-owner detector — a struct `Outer`
//! has a `deinit` method.  One of its value-typed fields has a
//! TYPE that's a struct in the SAME FILE also exposing a cleanup
//! method (`deinit` / `close` / `destroy` / `free` / `stop` /
//! `finalize` / `dispose`).  But `Outer.deinit` doesn't call
//! `<self>.<field>.<cleanup>(...)` — the inner's destructor is
//! never invoked, so the inner's owned non-memory resources (file
//! handles, sockets, mmaps, refs) leak.
//!
//! Real-world: ziglang/zig#22683 (`StackIterator.deinit` forgot
//! `it.ma.deinit()` → `/proc/self/mem` leaked).  Same family as
//! ziglang/zig#20192 (intermediate `Dir` leaked) and
//! ziglang/zig#18651 (Thread.Pool init cleanup gap).
//!
//! Pointer / slice fields are excluded — the "owned pointer" vs
//! "borrowed pointer" distinction is invisible at the type level,
//! and treating all pointer fields as owned produces many FPs.
//! Value-typed (incl. `?T` optional value) fields are the cleanest
//! "I own this" signal.

const std = @import("std");
const Ast = std.zig.Ast;

const fmodel = @import("../model.zig");
const problem = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");

const TokenIndex = std.zig.Ast.TokenIndex;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    if (!config_mod.isEnabled(config, .missing_deinit_on_composed_owner)) return;

    var model = try fmodel.build(gpa, tree);
    defer model.deinit();

    const tags = tree.tokens.items(.tag);

    for (model.types) |outer| {
        if (outer.kind != .struct_) continue;
        const deinit = outer.findMethod("deinit") orelse continue;

        for (outer.fields) |field| {
            // Peel one optional `?` prefix; reject pointer / slice
            // (borrow-y) types.
            var ty: TokenIndex = field.type_first;
            if (tags[ty] == .question_mark) ty += 1;
            if (ty > field.type_last) continue;
            if (tags[ty] != .identifier) continue; // *T / []T / etc.
            const type_name = tree.tokenSlice(ty);

            const inner = model.findType(type_name) orelse continue;
            if (!inner.hasCleanupMethod()) continue;

            // Check the outer deinit's body for any
            // `<X>.<field>.<cleanup>(` call (X wildcarded).
            const b_first = deinit.body_first + 1; // inside the `{`
            const b_last = if (deinit.body_last > 0) deinit.body_last - 1 else deinit.body_last;
            if (deinitCallsCleanupOnField(tree, b_first, b_last, field.name)) continue;

            try report(gpa, problems, tree, field.name_token, field.name, type_name);
        }
    }
}

/// True iff `[start, end]` contains a call of shape
/// `<X>.<field>.<cleanup-method>(`.
fn deinitCallsCleanupOnField(
    tree: *const Ast,
    start: TokenIndex,
    end: TokenIndex,
    field: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    var t: TokenIndex = start;
    while (t + 5 <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), field)) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        if (tags[t + 5] != .l_paren) continue;
        if (isCleanupName(tree.tokenSlice(t + 4))) return true;
    }
    return false;
}

fn isCleanupName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "close") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "stop") or
        std.mem.eql(u8, name, "finalize") or
        std.mem.eql(u8, name, "dispose");
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(problem.Problem),
    tree: *const Ast,
    field_tok: TokenIndex,
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
        .start = problem.Pos.fromTokenStart(tree, field_tok),
        .end = problem.Pos.fromTokenEnd(tree, field_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

const R = "missing-deinit-on-composed-owner";

test "outer deinit forgets inner field deinit fires" {
    try testing.expectFires(check, R,
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
    );
}

test "outer deinit calls inner deinit — no fire" {
    try testing.expectNoFire(check,
        \\const MemoryAccessor = struct {
        \\    pub fn deinit(self: *MemoryAccessor) void { _ = self; }
        \\};
        \\const StackIterator = struct {
        \\    ma: MemoryAccessor,
        \\    pub fn deinit(it: *StackIterator) void {
        \\        it.ma.deinit();
        \\    }
        \\};
    );
}

test "field type has no deinit — no fire" {
    try testing.expectNoFire(check,
        \\const Plain = struct { x: u32 };
        \\const Outer = struct {
        \\    p: Plain,
        \\    pub fn deinit(self: *Outer) void { _ = self; }
        \\};
    );
}

test "pointer field (likely borrow) doesn't fire" {
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?*Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        _ = self;
        \\    }
        \\};
    );
}

test "optional value-typed field (?Inner) fires" {
    try testing.expectFires(check, R,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        _ = self;
        \\    }
        \\};
    );
}
