//! PR #29853 detector — a type's destructor mentions some
//! same-typed sibling fields but omits others.
//!
//! Algorithm (purely syntactic, two passes over the tree):
//!
//!   1. Build `same_type_groups`: for each container type, group
//!      its fields by exact source-text of their declared type
//!      expression.  Keep groups of size ≥ 2.
//!
//!   2. For each fn whose name is in {deinit, finalize, destroy}
//!      and whose first parameter is `*T` for some T with sibling
//!      groups: scan the body for `<first_param>.<field>` token
//!      patterns and build a "mentioned" set.  For each sibling
//!      group on T, if the mentioned-vs-omitted split is 1..n-1
//!      (some handled, some skipped), fire on each omitted field.
//!
//! Skips groups where ALL fields are mentioned (handled) or NONE
//! are (symmetric omission — could be borrows, value types, or a
//! type with no destruction logic).

const std = @import("std");
const Ast = std.zig.Ast;

const annotations_mod = @import("annotations.zig");
const problem_mod = @import("problem.zig");
const config_mod = @import("config.zig");

const Db = annotations_mod.Db;
const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: *const Db,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .asymmetric_field_free)) return;

    // Build sibling groups per containing type.
    var groups: std.StringHashMapUnmanaged(TypeGroups) = .empty;
    defer freeGroups(gpa, &groups);
    try buildAllGroups(gpa, tree, &groups);

    // Find a usable "root self type" for file-as-struct files
    // (`const Foo = @This();`) so destructors at the root level
    // associate with the right type.
    const root_self_type = findRootSelfTypeName(tree);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        try checkFn(gpa, tree, db, root_self_type, &groups, node, problems);
    }
}

const FieldEntry = struct {
    name: []const u8,
    name_tok: Ast.TokenIndex,
};

const SiblingGroup = struct {
    /// `tree.source` byte range for the type expression (used as
    /// the equality key when grouping).
    type_text: []const u8,
    fields: std.ArrayListUnmanaged(FieldEntry) = .empty,

    fn deinit(self: *SiblingGroup, gpa: std.mem.Allocator) void {
        self.fields.deinit(gpa);
    }
};

const TypeGroups = struct {
    groups: std.ArrayListUnmanaged(SiblingGroup) = .empty,

    fn deinit(self: *TypeGroups, gpa: std.mem.Allocator) void {
        for (self.groups.items) |*g| g.deinit(gpa);
        self.groups.deinit(gpa);
    }
};

fn freeGroups(gpa: std.mem.Allocator, m: *std.StringHashMapUnmanaged(TypeGroups)) void {
    var it = m.valueIterator();
    while (it.next()) |v| v.deinit(gpa);
    m.deinit(gpa);
}

fn buildAllGroups(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    out: *std.StringHashMapUnmanaged(TypeGroups),
) !void {
    const root = tree.containerDeclRoot();
    const root_name = findRootSelfTypeName(tree);
    try walkContainerForGroups(gpa, tree, root.ast.members, root_name, out);
}

fn walkContainerForGroups(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    members: []const Ast.Node.Index,
    containing_type: ?[]const u8,
    out: *std.StringHashMapUnmanaged(TypeGroups),
) std.mem.Allocator.Error!void {
    if (containing_type) |ct| {
        try gatherFieldsForType(gpa, tree, members, ct, out);
    }
    // Recurse into nested struct/union decls.
    for (members) |member| {
        switch (tree.nodeTag(member)) {
            .simple_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .global_var_decl,
            => {
                const vd = tree.fullVarDecl(member) orelse continue;
                const init_node = vd.ast.init_node.unwrap() orelse continue;
                const name_tok = vd.ast.mut_token + 1;
                if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
                const ty_name = tree.tokenSlice(name_tok);
                try descendContainer(gpa, tree, init_node, ty_name, out);
            },
            else => {},
        }
    }
}

fn descendContainer(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    node: Ast.Node.Index,
    ty_name: []const u8,
    out: *std.StringHashMapUnmanaged(TypeGroups),
) std.mem.Allocator.Error!void {
    switch (tree.nodeTag(node)) {
        .container_decl, .container_decl_trailing => {
            try walkContainerForGroups(gpa, tree, tree.containerDecl(node).ast.members, ty_name, out);
        },
        .container_decl_two, .container_decl_two_trailing => {
            var buf: [2]Ast.Node.Index = undefined;
            try walkContainerForGroups(gpa, tree, tree.containerDeclTwo(&buf, node).ast.members, ty_name, out);
        },
        .container_decl_arg, .container_decl_arg_trailing => {
            try walkContainerForGroups(gpa, tree, tree.containerDeclArg(node).ast.members, ty_name, out);
        },
        else => {},
    }
}

fn gatherFieldsForType(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    members: []const Ast.Node.Index,
    ct: []const u8,
    out: *std.StringHashMapUnmanaged(TypeGroups),
) !void {
    // Caller will further filter via Db; this pass just collects.
    // Collect (field_name, type_text) for each field on this type,
    // then bucket by type_text.
    var by_type: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(FieldEntry)) = .empty;
    defer {
        var it = by_type.valueIterator();
        while (it.next()) |v| v.deinit(gpa);
        by_type.deinit(gpa);
    }

    const starts = tree.tokens.items(.start);

    for (members) |member| {
        switch (tree.nodeTag(member)) {
            .container_field_init,
            .container_field_align,
            .container_field,
            => {
                const cf = tree.fullContainerField(member) orelse continue;
                const name_tok = cf.ast.main_token;
                if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
                const field_name = tree.tokenSlice(name_tok);
                const type_expr = cf.ast.type_expr.unwrap() orelse continue;
                const tf = tree.firstToken(type_expr);
                const tl = tree.lastToken(type_expr);
                const start_byte = starts[tf];
                const end_byte = starts[tl] + tree.tokenSlice(tl).len;
                const type_text = tree.source[start_byte..end_byte];
                const gop = try by_type.getOrPut(gpa, type_text);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                try gop.value_ptr.append(gpa, .{ .name = field_name, .name_tok = name_tok });
            },
            else => {},
        }
    }

    // Keep only groups of size ≥ 2 whose declared type is an
    // OPTIONAL of a non-scalar inner type.  The `?T` shape is by
    // far the strongest signal for conditional heap ownership in
    // Zig — `if (this.field) |*x| x.deinit();` is the canonical
    // destructor pattern.  Bare slices, scalars, allocators, and
    // pointers FP too readily; the optional gate is what keeps
    // the rule's signal-to-noise high.
    var tg: TypeGroups = .{};
    errdefer tg.deinit(gpa);
    var it = by_type.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.items.len < 2) continue;
        const tt = entry.key_ptr.*;
        if (!isOptionalNamedType(tt)) continue;
        var group: SiblingGroup = .{ .type_text = tt };
        try group.fields.appendSlice(gpa, entry.value_ptr.items);
        try tg.groups.append(gpa, group);
    }
    if (tg.groups.items.len == 0) {
        tg.deinit(gpa);
        return;
    }
    try out.put(gpa, ct, tg);
}

/// True iff `tt` is `?<NamedType>` where `<NamedType>` is plausibly
/// a heap-owning value-typed struct.  Tight filter — only accept
/// the `?<TitleCased-ident>` shape:
///
///   - `?QueryStringMap` ✓
///   - `?string`        ✗ (lowercase → type alias, usually a slice)
///   - `?*T`            ✗ (pointer → usually borrowed)
///   - `?[]const u8`    ✗ (slice  → usually borrowed)
///   - `?bool` / `?u32` ✗ (scalar)
///
/// Optional-pointer / optional-slice fields ARE often heap-owned in
/// real code, but their FP rate is too high to flag generically;
/// other rules (`clobbered-by-struct-reset`, `heap-leak`) cover
/// the common owning cases.
fn isOptionalNamedType(tt: []const u8) bool {
    if (tt.len < 2) return false;
    if (tt[0] != '?') return false;
    const inner = std.mem.trim(u8, tt[1..], " \t");
    if (inner.len == 0) return false;
    if (inner[0] == '*') return false;
    if (inner[0] == '[') return false;
    // Title-cased identifier — Zig convention for struct/union/enum
    // types is UpperCamelCase.  Lowercase initial typically means a
    // type alias (`string`, `usize`) or scalar.
    if (inner[0] < 'A' or inner[0] > 'Z') return false;
    if (isScalarOrBorrowedTypeName(inner)) return false;
    return true;
}

fn isScalarOrBorrowedTypeName(s: []const u8) bool {
    if (std.mem.eql(u8, s, "bool")) return true;
    if (std.mem.eql(u8, s, "void")) return true;
    if (std.mem.eql(u8, s, "noreturn")) return true;
    if (std.mem.eql(u8, s, "type")) return true;
    if (std.mem.eql(u8, s, "anyerror")) return true;
    if (std.mem.eql(u8, s, "anytype")) return true;
    if (std.mem.eql(u8, s, "usize") or std.mem.eql(u8, s, "isize")) return true;
    if (std.mem.eql(u8, s, "comptime_int") or std.mem.eql(u8, s, "comptime_float")) return true;
    if (std.mem.eql(u8, s, "f16") or std.mem.eql(u8, s, "f32") or
        std.mem.eql(u8, s, "f64") or std.mem.eql(u8, s, "f80") or
        std.mem.eql(u8, s, "f128")) return true;
    // `u8` / `u32` / `i64` / `c_int` etc.
    if (s.len >= 2 and (s[0] == 'u' or s[0] == 'i')) {
        var all_digits = true;
        for (s[1..]) |c| {
            if (c < '0' or c > '9') {
                all_digits = false;
                break;
            }
        }
        if (all_digits) return true;
    }
    if (std.mem.startsWith(u8, s, "c_")) return true;
    // Allocator vtable — borrowed.
    if (std.mem.eql(u8, s, "Allocator") or
        std.mem.eql(u8, s, "std.mem.Allocator")) return true;
    return false;
}

fn findRootSelfTypeName(tree: *const Ast) ?[]const u8 {
    const root = tree.containerDeclRoot();
    for (root.ast.members) |member| {
        switch (tree.nodeTag(member)) {
            .simple_var_decl,
            .local_var_decl,
            .aligned_var_decl,
            .global_var_decl,
            => {
                const vd = tree.fullVarDecl(member) orelse continue;
                const init_node = vd.ast.init_node.unwrap() orelse continue;
                if (tree.nodeTag(init_node) != .builtin_call_two and
                    tree.nodeTag(init_node) != .builtin_call_two_comma) continue;
                const main_tok = tree.nodeMainToken(init_node);
                if (tree.tokens.items(.tag)[main_tok] != .builtin) continue;
                if (!std.mem.eql(u8, tree.tokenSlice(main_tok), "@This")) continue;
                const name_tok = vd.ast.mut_token + 1;
                if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
                return tree.tokenSlice(name_tok);
            },
            else => {},
        }
    }
    return null;
}

fn checkFn(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: *const Db,
    root_self_type: ?[]const u8,
    groups: *const std.StringHashMapUnmanaged(TypeGroups),
    fn_decl: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    var buf: [1]Ast.Node.Index = undefined;
    const fp = fnProto(tree, &buf, fn_decl) orelse return;
    const name_tok = fp.name_token orelse return;
    const fn_name = tree.tokenSlice(name_tok);
    if (!isDestructorName(fn_name)) return;

    const ct = db.containingType(fn_decl) orelse root_self_type orelse return;
    const tg = groups.getPtr(ct) orelse return;

    // First param name — typically "this" or "self".  Used as the
    // identifier to scan against for `<param>.<field>`.
    const first_param_name = firstParamName(tree, fp) orelse return;

    const body = bodyOf(tree, fn_decl) orelse return;

    // Build the mentioned-fields set by scanning destructor body
    // for `<first_param>.<field>` patterns.
    var mentioned: std.StringHashMapUnmanaged(void) = .empty;
    defer mentioned.deinit(gpa);
    try collectMentionedFields(tree, body, first_param_name, &mentioned, gpa);

    // For each sibling group, check coverage.  Two filters:
    //   - Skip borrowed fields (annotated `/// @borrowed` or
    //     inferred) — legitimately not freed.
    //   - Skip the entire group when the inner named type doesn't
    //     have a discoverable `deinit` method — those `?<X>` shapes
    //     are almost always borrowed pointers / string IDs that
    //     happen to share a type alias, not heap-owned values.
    for (tg.groups.items) |group| {
        if (!innerTypeHasDeinit(db, group.type_text)) continue;
        var owned: std.ArrayListUnmanaged(FieldEntry) = .empty;
        defer owned.deinit(gpa);
        for (group.fields.items) |f| {
            if (db.isBorrowedField(ct, f.name)) continue;
            try owned.append(gpa, f);
        }
        if (owned.items.len < 2) continue;

        var handled_count: usize = 0;
        for (owned.items) |f| {
            if (mentioned.contains(f.name)) handled_count += 1;
        }
        if (handled_count == 0 or handled_count == owned.items.len) continue;
        for (owned.items) |f| {
            if (mentioned.contains(f.name)) continue;
            try report(gpa, problems, tree, f, ct, group.type_text, fn_name);
        }
    }
}

/// True iff the inner type name of `?<X>` (or `?*<X>`) corresponds
/// to a type that defines a `deinit` method discoverable in the
/// Db.  Skips groups where the inner is a slice / sentinel-array
/// shape (those have no inherent deinit), and groups where the
/// named type isn't known to the Db (cross-file types that haven't
/// been resolved — conservative skip rather than potential FP).
fn innerTypeHasDeinit(db: *const Db, tt: []const u8) bool {
    if (tt.len < 2 or tt[0] != '?') return false;
    var inner = std.mem.trim(u8, tt[1..], " \t");
    // Strip pointer prefixes (`*`, `*const`) to get the pointee
    // type name.  A pointer to a deinit-bearing type is a borrow
    // signal, but if it IS owned the field-type pattern matches
    // the canonical sibling case.
    while (true) {
        if (inner.len == 0) return false;
        if (inner[0] == '*') {
            inner = std.mem.trim(u8, inner[1..], " \t");
            continue;
        }
        if (std.mem.startsWith(u8, inner, "const ")) {
            inner = std.mem.trim(u8, inner["const ".len..], " \t");
            continue;
        }
        break;
    }
    if (inner.len == 0) return false;
    // Slice / sentinel-array shapes have no inherent deinit.
    if (inner[0] == '[') return false;
    // Bare identifier (possibly dotted).  Look up `deinit` on the
    // last segment.
    var last_segment_start: usize = 0;
    for (inner, 0..) |c, i| {
        if (c == '.') last_segment_start = i + 1;
    }
    const last_segment = inner[last_segment_start..];
    // Heuristic: if the type IS defined in this file (db.hasType)
    // AND has no deinit method, it's a value type — skip.  If the
    // type isn't local (cross-file import, generic instantiation,
    // or unknown), keep — the sibling-asymmetry signal alone is
    // worth surfacing rather than missing.
    if (db.hasType(last_segment) and db.lookupTyped(last_segment, "deinit") == null) {
        return false;
    }
    return true;
}

fn collectMentionedFields(
    tree: *const Ast,
    body: Ast.Node.Index,
    first_param_name: []const u8,
    out: *std.StringHashMapUnmanaged(void),
    gpa: std.mem.Allocator,
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    var t: Ast.TokenIndex = first;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), first_param_name)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        try out.put(gpa, tree.tokenSlice(t + 2), {});
    }
}

fn isDestructorName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "finalize") or
        std.mem.eql(u8, name, "destroy");
}

fn firstParamName(tree: *const Ast, fp: Ast.full.FnProto) ?[]const u8 {
    var it = fp.iterate(tree);
    const first = it.next() orelse return null;
    const tok = first.name_token orelse return null;
    return tree.tokenSlice(tok);
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
    f: FieldEntry,
    ct: []const u8,
    type_text: []const u8,
    fn_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}.{s}` ({s}) is not freed in `{s}` even though its sibling field(s) of the same type are — this asymmetry is a strong signal `{s}` was forgotten and leaks every time it's populated",
        .{ ct, f.name, type_text, fn_name, f.name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "asymmetric-field-free",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, f.name_tok),
        .end = Pos.fromTokenEnd(tree, f.name_tok),
        .message = msg,
    });
}
