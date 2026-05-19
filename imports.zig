//! Import-statement extractor.  Walks a parsed file's top-level
//! decls looking for `const NAME = @import("path");` and builds a
//! NAME → path map.  Phase 22 wires this into classifyCall so that
//! `foo.bar()` where `foo` is an imported namespace can resolve
//! `bar`'s @returns annotation by parsing the imported file.
//!
//! Scope (phase 21):
//! - Top-level only.  `const X = @import(...)` inside a function
//!   isn't extracted — Zig allows it but it's rare and rule-relevant
//!   imports live at module scope.
//! - String-literal paths only.  `@import(some_expr)` (comptime
//!   string from a function call) isn't resolved.
//! - Both file imports (`@import("ast.zig")`) and std/builtin
//!   imports (`@import("std")`) are extracted; resolution to a
//!   filesystem path is a phase-22 concern.

const std = @import("std");
const Ast = std.zig.Ast;

pub const Entry = struct {
    /// The binding name on the LHS — slice into source.
    name: []const u8,
    /// The raw import path string, without quotes — slice into source.
    /// May be a relative path ("ast.zig", "../foo/bar.zig"), a std
    /// module ("std"), or any other string `@import` accepts.
    path: []const u8,
    /// For `const X = @import("...").Y;` — the `Y` identifier slice.
    /// Null for bare `const X = @import("...");`.  Phase 31 hop:
    /// at resolve time, after loading `path`, look up `subfield` in
    /// that file's own imap to chase one more level.
    subfield: ?[]const u8 = null,
    /// Second-level subfield for 2-hop chains (phase 41).  E.g.:
    ///   const A   = @import("a.zig");
    ///   const B   = A.Sub;            ← B.subfield = "Sub"
    ///   const Inner = B.Other;        ← Inner.subfield = "Sub", subfield2 = "Other"
    /// At resolve time: load A's path, look up "Sub" in A's imap to
    /// get B's actual file, then look up "Other" in B's imap.
    /// Deeper chains (3+) still skip — practical cases stop at 2.
    subfield2: ?[]const u8 = null,
};

pub const Map = struct {
    entries: std.StringHashMapUnmanaged(Entry),

    pub fn deinit(self: *Map, gpa: std.mem.Allocator) void {
        self.entries.deinit(gpa);
    }

    pub fn lookup(self: *const Map, name: []const u8) ?Entry {
        return self.entries.get(name);
    }
};

/// Walk every top-level decl in `tree` looking for three shapes:
///   `const NAME = @import("path");`           — Entry{path, subfield=null}
///   `const NAME = @import("path").Subfield;`  — Entry{path, subfield="Subfield"}
///   `const NAME = OtherImport.Subfield;`      — inherits OtherImport's path
/// Two passes (phase 40):
///   Pass 1: direct @import + wrapped field-access — order-independent.
///   Pass 2: alias-of-import — runs after pass 1 so forward references
///           (alias declared above the @import it depends on) resolve.
/// Subsequent overwrites silently win (Zig forbids shadowing).
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !Map {
    var m: Map = .{ .entries = .empty };
    errdefer m.deinit(gpa);

    const decls = tree.rootDecls();

    // Pass 1: every direct @import shape, regardless of declaration
    // order.  Self-contained — doesn't depend on other decls.
    for (decls) |decl| {
        const var_decl = tree.fullVarDecl(decl) orelse continue;
        const name_tok = var_decl.ast.mut_token + 1;
        if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
        const init_node = var_decl.ast.init_node.unwrap() orelse continue;

        const name = tree.tokenSlice(name_tok);
        if (extractImportPath(tree, init_node)) |path| {
            try m.entries.put(gpa, name, .{ .name = name, .path = path });
            continue;
        }
        if (extractImportFieldAccess(tree, init_node)) |hit| {
            try m.entries.put(gpa, name, .{
                .name = name,
                .path = hit.path,
                .subfield = hit.subfield,
            });
        }
    }

    // Pass 2: alias-of-import.  Uses the fully-populated map from
    // pass 1 so forward references (`const X = lib.Sub;` declared
    // before `const lib = @import(...);`) now resolve.
    //   const lib = @import("foo.zig");
    //   const X   = lib.Sub;      ← X inherits lib's path, adopts "Sub".
    for (decls) |decl| {
        const var_decl = tree.fullVarDecl(decl) orelse continue;
        const name_tok = var_decl.ast.mut_token + 1;
        if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
        const init_node = var_decl.ast.init_node.unwrap() orelse continue;
        const name = tree.tokenSlice(name_tok);

        // Skip if already entered by pass 1.
        if (m.entries.contains(name)) continue;

        const hit = extractIdentFieldAccess(tree, init_node) orelse continue;
        const lhs_entry = m.entries.get(hit.lhs_name) orelse continue;
        if (lhs_entry.subfield == null) {
            // Bare-import LHS (phase 32 shape).
            try m.entries.put(gpa, name, .{
                .name = name,
                .path = lhs_entry.path,
                .subfield = hit.subfield,
            });
        } else if (lhs_entry.subfield2 == null) {
            // One-hop subfielded LHS (phase 41) — chain into subfield2.
            try m.entries.put(gpa, name, .{
                .name = name,
                .path = lhs_entry.path,
                .subfield = lhs_entry.subfield,
                .subfield2 = hit.subfield,
            });
        }
        // Else: 2-hop LHS — would need a 3rd subfield slot.  Deeper
        // chains rare in practice; skip.
    }
    return m;
}

/// Match `@import("string")` directly.  Returns the path slice (no quotes).
fn extractImportPath(tree: *const Ast, init_node: Ast.Node.Index) ?[]const u8 {
    if (tree.nodeTag(init_node) != .builtin_call_two) return null;
    const main = tree.nodeMainToken(init_node);
    if (!std.mem.eql(u8, tree.tokenSlice(main), "@import")) return null;
    const call_data = tree.nodeData(init_node).opt_node_and_opt_node;
    const arg_node = call_data[0].unwrap() orelse return null;
    if (tree.nodeTag(arg_node) != .string_literal) return null;
    const path_raw = tree.tokenSlice(tree.nodeMainToken(arg_node));
    if (path_raw.len < 2 or path_raw[0] != '"' or path_raw[path_raw.len - 1] != '"') return null;
    return path_raw[1 .. path_raw.len - 1];
}

/// Match `@import("string").Subfield` — a field_access whose lhs is
/// the import call.  Returns both path and subfield identifier slices.
fn extractImportFieldAccess(tree: *const Ast, init_node: Ast.Node.Index) ?struct {
    path: []const u8,
    subfield: []const u8,
} {
    if (tree.nodeTag(init_node) != .field_access) return null;
    const fa = tree.nodeData(init_node);
    const lhs = fa.node_and_token[0];
    const sub_tok = fa.node_and_token[1];
    const path = extractImportPath(tree, lhs) orelse return null;
    if (tree.tokens.items(.tag)[sub_tok] != .identifier) return null;
    return .{ .path = path, .subfield = tree.tokenSlice(sub_tok) };
}

/// Match `<ident>.<subfield>` — field_access whose lhs is a bare
/// identifier.  Returns both name slices.  The caller resolves the
/// lhs name against the in-progress imports map to decide whether
/// the alias inherits an import path.
fn extractIdentFieldAccess(tree: *const Ast, init_node: Ast.Node.Index) ?struct {
    lhs_name: []const u8,
    subfield: []const u8,
} {
    if (tree.nodeTag(init_node) != .field_access) return null;
    const fa = tree.nodeData(init_node);
    const lhs = fa.node_and_token[0];
    const sub_tok = fa.node_and_token[1];
    if (tree.nodeTag(lhs) != .identifier) return null;
    if (tree.tokens.items(.tag)[sub_tok] != .identifier) return null;
    return .{
        .lhs_name = tree.tokenSlice(tree.nodeMainToken(lhs)),
        .subfield = tree.tokenSlice(sub_tok),
    };
}

// ── Tests ──────────────────────────────────────────────────

/// Test helper: parse + build, both owned by the returned bundle.
const TestBundle = struct {
    src_z: [:0]u8,
    tree: Ast,
    map: Map,

    fn deinit(self: *TestBundle, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
        self.tree.deinit(gpa);
        gpa.free(self.src_z);
    }
};

fn buildFromSrc(gpa: std.mem.Allocator, src: []const u8) !TestBundle {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    errdefer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    errdefer tree.deinit(gpa);
    const map = try build(gpa, &tree);
    return .{ .src_z = src_z, .tree = tree, .map = map };
}

test "extract @import file path" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const ast = @import("ast.zig");
        \\
    );
    defer r.deinit(gpa);

    const entry = r.map.lookup("ast").?;
    try std.testing.expectEqualStrings("ast.zig", entry.path);
}

test "extract @import std namespace" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const std = @import("std");
        \\
    );
    defer r.deinit(gpa);

    const entry = r.map.lookup("std").?;
    try std.testing.expectEqualStrings("std", entry.path);
}

test "extract multiple @imports in one file" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const std = @import("std");
        \\const ast = @import("ast.zig");
        \\const sem = @import("../sem/sem.zig");
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expectEqualStrings("std", r.map.lookup("std").?.path);
    try std.testing.expectEqualStrings("ast.zig", r.map.lookup("ast").?.path);
    try std.testing.expectEqualStrings("../sem/sem.zig", r.map.lookup("sem").?.path);
}

test "non-import top-level decl ignored" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const PI: f64 = 3.14;
        \\pub fn add(a: u32, b: u32) u32 { return a + b; }
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expect(r.map.lookup("PI") == null);
    try std.testing.expect(r.map.lookup("add") == null);
}

test "function-local @import is NOT extracted (top-level only)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\pub fn foo() void {
        \\    const std = @import("std");
        \\    _ = std;
        \\}
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expect(r.map.lookup("std") == null);
}

test "extract @import().Subfield re-export shape (phase 31)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const Ast = @import("ast.zig").Ast;
        \\
    );
    defer r.deinit(gpa);

    const entry = r.map.lookup("Ast").?;
    try std.testing.expectEqualStrings("ast.zig", entry.path);
    try std.testing.expectEqualStrings("Ast", entry.subfield.?);
}

test "bare @import has subfield = null (phase 31 regression)" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const ast = @import("ast.zig");
        \\
    );
    defer r.deinit(gpa);

    const entry = r.map.lookup("ast").?;
    try std.testing.expect(entry.subfield == null);
}

test "extract local-alias-of-import (phase 32)" {
    // `const lib = @import("foo.zig"); const X = lib.Sub;`
    // → X entry carries lib's path AND "Sub" as subfield.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const lib = @import("foo.zig");
        \\const X = lib.Sub;
        \\
    );
    defer r.deinit(gpa);

    const x = r.map.lookup("X").?;
    try std.testing.expectEqualStrings("foo.zig", x.path);
    try std.testing.expectEqualStrings("Sub", x.subfield.?);
}

test "alias of non-import identifier is NOT extracted (phase 32 guard)" {
    // `const X = obj.Sub;` where `obj` is not an import → no entry.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const obj = struct { pub const Sub = u32; }{};
        \\const X = obj.Sub;
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expect(r.map.lookup("X") == null);
}

test "forward-reference alias resolves via 2-pass extraction (phase 40)" {
    // Alias declared BEFORE the import it depends on.  Pre-phase-40
    // this was an intentional single-pass limitation; phase 40's
    // two-pass build resolves the forward reference because pass 1
    // fully populates @import entries before pass 2 looks for aliases.
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const X = lib.Sub;
        \\const lib = @import("foo.zig");
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expectEqualStrings("foo.zig", r.map.lookup("lib").?.path);
    const x = r.map.lookup("X").?;
    try std.testing.expectEqualStrings("foo.zig", x.path);
    try std.testing.expectEqualStrings("Sub", x.subfield.?);
}

test "extract 2-hop subfielded-alias chain (phase 41)" {
    // const lib = @import("lib.zig");
    // const Inner = lib.Inner;       ← subfield = "Inner"
    // const Foo = Inner.Foo;         ← subfield = "Inner", subfield2 = "Foo"
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const lib = @import("lib.zig");
        \\const Inner = lib.Inner;
        \\const Foo = Inner.Foo;
        \\
    );
    defer r.deinit(gpa);

    const inner = r.map.lookup("Inner").?;
    try std.testing.expectEqualStrings("lib.zig", inner.path);
    try std.testing.expectEqualStrings("Inner", inner.subfield.?);
    try std.testing.expect(inner.subfield2 == null);

    const foo = r.map.lookup("Foo").?;
    try std.testing.expectEqualStrings("lib.zig", foo.path);
    try std.testing.expectEqualStrings("Inner", foo.subfield.?);
    try std.testing.expectEqualStrings("Foo", foo.subfield2.?);
}

test "non-string-literal @import arg ignored" {
    const gpa = std.testing.allocator;
    var r = try buildFromSrc(gpa,
        \\const std = @import("std");
        \\const path = "ast.zig";
        \\const dyn = @import(path);
        \\
    );
    defer r.deinit(gpa);

    try std.testing.expectEqualStrings("std", r.map.lookup("std").?.path);
    try std.testing.expect(r.map.lookup("dyn") == null);
}
