//! AST-level (semantic-model) query DSL.
//!
//! Companion to `query.zig` (the token-level pattern matcher).
//! Where query.zig finds token sequences, this finds entities in
//! the FileModel — types, fields, methods — matching predicates.
//!
//! The two compose: rules use mq.findTypes / findFields / findMethods
//! to narrow down WHICH bodies to scan, then use query.* to scan
//! those bodies for token patterns.
//!
//! Example — "outer struct has a deinit, has a value-typed field
//! whose type also has a deinit, but the outer's deinit body
//! doesn't call <self>.<field>.deinit()":
//!
//!     const outers = try mq.findTypes(gpa, &model, .{
//!         .kind = .struct_,
//!         .has_method = .{ .name_eq = "deinit" },
//!     });
//!     defer gpa.free(outers);
//!
//!     for (outers) |outer| {
//!         const deinit = outer.findMethod("deinit").?;
//!         const fields = try mq.findFields(gpa, &model, outer, .{
//!             .value_typed = true,
//!             .type_matches = .{ .has_method = .{ .is_cleanup = true } },
//!         });
//!         defer gpa.free(fields);
//!
//!         for (fields) |field| {
//!             var atoms = [_]Atom{
//!                 .{ .tok = .identifier }, .{ .tok = .period },
//!                 .{ .text = field.name }, .{ .tok = .period },
//!                 .{ .pred = isCleanupMethodPred }, .paren_args,
//!             };
//!             if (!query.anyMatchAnywhere(tree, &atoms,
//!                 deinit.body_first, deinit.body_last, null))
//!             {
//!                 try report(...);
//!             }
//!         }
//!     }

const std = @import("std");
const Ast = std.zig.Ast;

const fmodel = @import("model.zig");
const lexer = @import("lexer.zig");
const query = @import("query.zig");
const receiver = @import("receiver.zig");

const TokenIndex = lexer.TokenIndex;

// ── Predicates ───────────────────────────────────────────────

pub const TypePred = struct {
    /// Kind filter (struct / union / enum / opaque).  null = any.
    kind: ?fmodel.TypeKind = null,
    /// Type name must equal this.
    name_eq: ?[]const u8 = null,
    /// Type name must pass this predicate.
    name_pred: ?*const fn ([]const u8) bool = null,
    /// Type must have at least one method matching this predicate.
    has_method: ?MethodPred = null,
    /// Type must NOT have any method matching this predicate.
    no_method: ?MethodPred = null,
};

pub const FieldPred = struct {
    name_eq: ?[]const u8 = null,
    name_pred: ?*const fn ([]const u8) bool = null,
    /// Field type is a bare identifier (with optional `?` prefix) —
    /// NOT `*T`, `[]T`, `[N]T`, etc.  The conservative "I own this
    /// value" signal.
    value_typed: bool = false,
    /// Field has a `= <default>` initializer.
    has_default: ?bool = null,
    /// The field's type identifier resolves to a TypeInfo in the
    /// same file that matches this predicate.
    type_matches: ?TypePred = null,
};

pub const MethodPred = struct {
    name_eq: ?[]const u8 = null,
    name_pred: ?*const fn ([]const u8) bool = null,
    /// True iff method name is in the canonical cleanup set
    /// (deinit/free/destroy/close/release/finalize/dispose/etc.).
    /// Equivalent to `name_pred = receiver.isCleanupMethodName`.
    is_cleanup: bool = false,
    /// True iff method name is in the canonical acquire set
    /// (reference/retain/addRef/...).
    is_acquire: bool = false,
    /// True iff method name is in the canonical release set.
    is_release: bool = false,
    is_pub: ?bool = null,
    /// True iff method has a self-typed receiver.
    has_receiver: ?bool = null,
};

// ── Predicate matchers ───────────────────────────────────────

fn typeMatches(ti: *const fmodel.TypeInfo, pred: TypePred) bool {
    if (pred.kind) |k| if (ti.kind != k) return false;
    if (pred.name_eq) |n| if (!std.mem.eql(u8, ti.name, n)) return false;
    if (pred.name_pred) |p| if (!p(ti.name)) return false;
    if (pred.has_method) |mp| if (!anyMethodOnType(ti, mp)) return false;
    if (pred.no_method) |mp| if (anyMethodOnType(ti, mp)) return false;
    return true;
}

fn fieldMatches(
    tree: *const Ast,
    model: *const fmodel.FileModel,
    ti_owner: *const fmodel.TypeInfo,
    field: *const fmodel.FieldInfo,
    pred: FieldPred,
) bool {
    _ = ti_owner;
    if (pred.name_eq) |n| if (!std.mem.eql(u8, field.name, n)) return false;
    if (pred.name_pred) |p| if (!p(field.name)) return false;
    if (pred.has_default) |hd| if (field.has_default != hd) return false;
    if (pred.value_typed and !isValueTyped(tree, field)) return false;
    if (pred.type_matches) |tp| {
        const resolved = resolveFieldType(tree, model, field) orelse return false;
        if (!typeMatches(resolved, tp)) return false;
    }
    return true;
}

fn methodMatches(m: *const fmodel.MethodInfo, pred: MethodPred) bool {
    if (pred.name_eq) |n| if (!std.mem.eql(u8, m.name, n)) return false;
    if (pred.name_pred) |p| if (!p(m.name)) return false;
    if (pred.is_cleanup and !receiver.isCleanupMethodName(m.name)) return false;
    if (pred.is_acquire and !receiver.isAcquireMethodName(m.name)) return false;
    if (pred.is_release and !receiver.isReleaseMethodName(m.name)) return false;
    if (pred.is_pub) |p| if (m.is_pub != p) return false;
    if (pred.has_receiver) |hr| {
        const has = m.receiver != null;
        if (has != hr) return false;
    }
    return true;
}

fn anyMethodOnType(ti: *const fmodel.TypeInfo, pred: MethodPred) bool {
    for (ti.methods) |m| if (methodMatches(&m, pred)) return true;
    return false;
}

// ── Finders ──────────────────────────────────────────────────

/// All TypeInfo in `model` matching `pred`.  Caller owns the slice.
pub fn findTypes(
    gpa: std.mem.Allocator,
    model: *const fmodel.FileModel,
    pred: TypePred,
) ![]*const fmodel.TypeInfo {
    var out: std.ArrayListUnmanaged(*const fmodel.TypeInfo) = .empty;
    for (model.types) |*ti| {
        if (typeMatches(ti, pred)) try out.append(gpa, ti);
    }
    return out.toOwnedSlice(gpa);
}

/// All fields of `ti` matching `pred`.  Caller owns the slice.
pub fn findFields(
    gpa: std.mem.Allocator,
    model: *const fmodel.FileModel,
    tree: *const Ast,
    ti: *const fmodel.TypeInfo,
    pred: FieldPred,
) ![]*const fmodel.FieldInfo {
    var out: std.ArrayListUnmanaged(*const fmodel.FieldInfo) = .empty;
    for (ti.fields) |*f| {
        if (fieldMatches(tree, model, ti, f, pred)) try out.append(gpa, f);
    }
    return out.toOwnedSlice(gpa);
}

fn findMethods(
    gpa: std.mem.Allocator,
    ti: *const fmodel.TypeInfo,
    pred: MethodPred,
) ![]*const fmodel.MethodInfo {
    var out: std.ArrayListUnmanaged(*const fmodel.MethodInfo) = .empty;
    for (ti.methods) |*m| {
        if (methodMatches(m, pred)) try out.append(gpa, m);
    }
    return out.toOwnedSlice(gpa);
}

// ── Helpers ──────────────────────────────────────────────────

/// True iff the field's type is a bare identifier (peel one `?`),
/// not a pointer/slice/array — the conservative "I own this" signal.
fn isValueTyped(tree: *const Ast, field: *const fmodel.FieldInfo) bool {
    const tags = tree.tokens.items(.tag);
    var t: TokenIndex = field.type_first;
    if (t > field.type_last) return false;
    if (tags[t] == .question_mark) t += 1;
    if (t > field.type_last) return false;
    return tags[t] == .identifier;
}

/// Resolve a field's type expression to a TypeInfo in `model`, if
/// the type's first identifier-token (after peeling `?`) names a
/// type declared in this file.  Returns null otherwise (e.g.
/// `*T`, `[]T`, foreign types, generics, etc.).
fn resolveFieldType(
    tree: *const Ast,
    model: *const fmodel.FileModel,
    field: *const fmodel.FieldInfo,
) ?*const fmodel.TypeInfo {
    const tags = tree.tokens.items(.tag);
    var t: TokenIndex = field.type_first;
    if (t > field.type_last) return null;
    if (tags[t] == .question_mark) t += 1;
    if (t > field.type_last) return null;
    if (tags[t] != .identifier) return null;
    const name = tree.tokenSlice(t);
    return model.findType(name);
}

/// Like `resolveFieldType`, but uses `model.findTypeInScope` rooted
/// at `owner` — resolves the field's type starting from `owner`'s
/// own NESTED types, then its parent's siblings, etc.  Falls back
/// to the simple findType behavior when `owner` is null.  Used to
/// disambiguate name collisions where the same identifier
/// (`Future`, `State`) names a type in multiple enclosing scopes.
pub fn resolveFieldTypeScoped(
    tree: *const Ast,
    model: *const fmodel.FileModel,
    owner: *const fmodel.TypeInfo,
    field: *const fmodel.FieldInfo,
) ?*const fmodel.TypeInfo {
    const tags = tree.tokens.items(.tag);
    var t: TokenIndex = field.type_first;
    if (t > field.type_last) return null;
    if (tags[t] == .question_mark) t += 1;
    if (t > field.type_last) return null;
    if (tags[t] != .identifier) return null;
    // If the type path is dotted (`Result.Pending.State`), prefer
    // the LEAF type via qualified lookup; falls back to the
    // first-identifier in-scope lookup when the chain doesn't
    // resolve.
    if (t + 2 <= field.type_last and tags[t + 1] == .period and tags[t + 2] == .identifier) {
        if (model.resolveFieldTypeQualifiedTi(owner, field.name)) |ti| return ti;
    }
    const name = tree.tokenSlice(t);
    return model.findTypeInScope(name, owner);
}

// ── Body-pattern integration ─────────────────────────────────

/// True iff the method's body contains a match for `atoms` (skipping
/// nested fns, NOT defer/errdefer).  Composes with query.zig.
pub fn methodBodyContains(
    tree: *const Ast,
    method: *const fmodel.MethodInfo,
    atoms: []const query.Atom,
) bool {
    return query.anyMatchAnywhere(tree, atoms, method.body_first, method.body_last, null);
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

test "findTypes: kind + name filter" {
    const src: [:0]const u8 =
        \\const A = struct {};
        \\const B = union { x: u32 };
        \\const C = enum { a, b };
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try fmodel.build(testing.allocator, &tree);
    defer model.deinit();

    const structs = try findTypes(testing.allocator, &model, .{ .kind = .struct_ });
    defer testing.allocator.free(structs);
    try testing.expectEqual(@as(usize, 1), structs.len);
    try testing.expectEqualStrings("A", structs[0].name);

    const named_b = try findTypes(testing.allocator, &model, .{ .name_eq = "B" });
    defer testing.allocator.free(named_b);
    try testing.expectEqual(@as(usize, 1), named_b.len);
    try testing.expectEqual(fmodel.TypeKind.union_, named_b[0].kind);
}

test "findTypes: has_method + no_method" {
    const src: [:0]const u8 =
        \\const HasDeinit = struct {
        \\    pub fn deinit(self: *HasDeinit) void { _ = self; }
        \\};
        \\const NoDeinit = struct {
        \\    x: u32 = 0,
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try fmodel.build(testing.allocator, &tree);
    defer model.deinit();

    const has = try findTypes(testing.allocator, &model, .{
        .has_method = .{ .name_eq = "deinit" },
    });
    defer testing.allocator.free(has);
    try testing.expectEqual(@as(usize, 1), has.len);
    try testing.expectEqualStrings("HasDeinit", has[0].name);

    const no = try findTypes(testing.allocator, &model, .{
        .kind = .struct_,
        .no_method = .{ .name_eq = "deinit" },
    });
    defer testing.allocator.free(no);
    try testing.expectEqual(@as(usize, 1), no.len);
    try testing.expectEqualStrings("NoDeinit", no[0].name);
}

test "findFields: value_typed includes ?T, excludes *T / []T" {
    const src: [:0]const u8 =
        \\const T = struct {
        \\    a: Inner,
        \\    b: *Inner,
        \\    c: []u8,
        \\    d: ?Inner,
        \\};
        \\const Inner = struct {};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try fmodel.build(testing.allocator, &tree);
    defer model.deinit();

    const ti = model.findType("T").?;
    const vals = try findFields(testing.allocator, &model, &tree, ti, .{ .value_typed = true });
    defer testing.allocator.free(vals);
    try testing.expectEqual(@as(usize, 2), vals.len);
    try testing.expectEqualStrings("a", vals[0].name);
    try testing.expectEqualStrings("d", vals[1].name);
}

test "findFields: type_matches chains to TypePred" {
    const src: [:0]const u8 =
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Plain = struct { x: u32 };
        \\const Outer = struct {
        \\    a: Inner,
        \\    b: Plain,
        \\    c: Inner,
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try fmodel.build(testing.allocator, &tree);
    defer model.deinit();

    const outer = model.findType("Outer").?;
    const cleanup_fields = try findFields(testing.allocator, &model, &tree, outer, .{
        .value_typed = true,
        .type_matches = .{ .has_method = .{ .is_cleanup = true } },
    });
    defer testing.allocator.free(cleanup_fields);
    try testing.expectEqual(@as(usize, 2), cleanup_fields.len);
    try testing.expectEqualStrings("a", cleanup_fields[0].name);
    try testing.expectEqualStrings("c", cleanup_fields[1].name);
}

test "findMethods: is_cleanup classifier" {
    const src: [:0]const u8 =
        \\const T = struct {
        \\    pub fn deinit(self: *T) void { _ = self; }
        \\    pub fn close(self: *T) void { _ = self; }
        \\    pub fn ordinary(self: *T) void { _ = self; }
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try fmodel.build(testing.allocator, &tree);
    defer model.deinit();

    const ti = model.findType("T").?;
    const cleanups = try findMethods(testing.allocator, ti, .{ .is_cleanup = true });
    defer testing.allocator.free(cleanups);
    try testing.expectEqual(@as(usize, 2), cleanups.len);
}

test "methodBodyContains: integrates with query.zig" {
    const src: [:0]const u8 =
        \\const T = struct {
        \\    inner: Inner,
        \\    pub fn deinit(self: *T) void {
        \\        self.inner.deinit();
        \\    }
        \\};
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try fmodel.build(testing.allocator, &tree);
    defer model.deinit();

    const ti = model.findType("T").?;
    const deinit = ti.findMethod("deinit").?;

    // Pattern: `<X>.inner.deinit(`
    const pattern = &[_]query.Atom{
        .{ .tok = .identifier },
        .{ .tok = .period },
        .{ .text = "inner" },
        .{ .tok = .period },
        .{ .text = "deinit" },
        .paren_args,
    };
    try testing.expect(methodBodyContains(&tree, deinit, pattern));

    // Pattern that's not present.
    const absent = &[_]query.Atom{
        .{ .text = "missing_method" },
        .paren_args,
    };
    try testing.expect(!methodBodyContains(&tree, deinit, absent));
}
