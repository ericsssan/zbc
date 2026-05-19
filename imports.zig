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

/// Walk every top-level decl in `tree` looking for two shapes:
///   `const NAME = @import("path");`           — Entry{path, subfield=null}
///   `const NAME = @import("path").Subfield;`  — Entry{path, subfield="Subfield"}
/// Subsequent overwrites silently win (Zig forbids shadowing).
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !Map {
    var m: Map = .{ .entries = .empty };
    errdefer m.deinit(gpa);

    const decls = tree.rootDecls();
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
