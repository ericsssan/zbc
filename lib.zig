//! Public library API for the borrow-check / escape analyzer.
//! Separates the analyzer kernel (parse + lower + check) from the
//! CLI (main.zig: argparse + diagnostic formatting).  Downstream
//! projects depend on this module via build.zig.zon; ez's own
//! main.zig is one consumer.
//!
//! Two analysis modes:
//!   - `analyzeEscape(...)` — Layer 2.  Full cross-file annotation
//!     lookup, CFG lowering, abstract-interpretation worklist.
//!     Returns problems found by the configured invariants
//!     (currently: arena-escape, ast-identity, post-parse mutation).
//!   - `analyzeHygiene(...)` — Layer 1.  Same-file lint rules
//!     covering annotation-presence checks (the require_* rules).
//!
//! Both modes return an owned `[]Problem` slice; caller must call
//! `freeProblems(gpa, slice)` to release.

const std = @import("std");
const Ast = std.zig.Ast;

const cfg_mod = @import("cfg.zig");
const annotations_mod = @import("annotations.zig");
const analyzer_mod = @import("analyzer.zig");
const imports_mod = @import("imports.zig");
const remote_resolver_mod = @import("remote_resolver.zig");
const config_mod = @import("config.zig");
const problem_mod = @import("problem.zig");

const require_borrowed_from = @import("rules/require_borrowed_from.zig");
const require_node_index_origin = @import("rules/require_node_index_origin.zig");
const require_arena_kill_tag = @import("rules/require_arena_kill_tag.zig");

// ── Public types — re-exported for caller convenience ───────────

pub const Config = config_mod.Config;
pub const DefaultConfig = config_mod.Default;
pub const Problem = problem_mod.Problem;
pub const Cache = remote_resolver_mod.Cache;

// ── Public entry points ─────────────────────────────────────────

/// Layer 2: run the escape analyzer on `path`.  Reads the file,
/// parses it, lowers each top-level fn to a CFG, runs the abstract-
/// interpretation worklist, and returns any reported Problems.
///
/// `cache` — sweep-wide remote-resolver cache, shared across multiple
///   analyzeEscape calls in the same run for cross-file annotation
///   lookup speed.  Pass null to disable cross-file resolution
///   entirely (annotations only resolve same-file).
/// `config` — project knobs (type names, text patterns).  Pass
///   `&DefaultConfig` to use the historical ez defaults.
///
/// Returns an owned slice — caller must call `freeProblems(gpa, slice)`.
pub fn analyzeEscape(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    cache: ?*Cache,
    config: *const Config,
) ![]Problem {
    const src_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        std.Io.Limit.limited(16 * 1024 * 1024),
    );
    defer gpa.free(src_bytes);

    const src = try gpa.allocSentinel(u8, src_bytes.len, 0);
    defer gpa.free(src);
    @memcpy(src[0..src_bytes.len], src_bytes);

    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);

    var db = try annotations_mod.build(gpa, &tree);
    defer db.deinit(gpa);

    // Construct remote context only if caller supplied a cache.
    var imap_storage: ?imports_mod.Map = null;
    defer if (imap_storage) |*m| m.deinit(gpa);
    var remote_ctx_storage: ?cfg_mod.RemoteCtx = null;

    if (cache) |c| {
        imap_storage = try imports_mod.build(gpa, &tree);
        const base_dir = std.fs.path.dirname(path) orelse ".";
        remote_ctx_storage = .{
            .imap = &imap_storage.?,
            .base_dir = base_dir,
            .cache = c,
        };
    }

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    errdefer freeProblemsArrayList(gpa, &problems);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        const remote_ptr: ?*const cfg_mod.RemoteCtx = if (remote_ctx_storage) |*r| r else null;
        var cfg = (try cfg_mod.lowerFunctionFull(
            gpa,
            &tree,
            node,
            &db,
            remote_ptr,
            config,
        )) orelse continue;
        defer cfg.deinit(gpa);
        try analyzer_mod.check(gpa, &cfg, .{ .path = path, .config = config }, &problems);
    }

    return problems.toOwnedSlice(gpa);
}

/// Layer 1: run the annotation-hygiene rules on `path`.  Same-file
/// only; no cross-file lookup needed.  Caller owns the returned slice.
pub fn analyzeHygiene(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) ![]Problem {
    const src_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        std.Io.Limit.limited(16 * 1024 * 1024),
    );
    defer gpa.free(src_bytes);

    const src = try gpa.allocSentinel(u8, src_bytes.len, 0);
    defer gpa.free(src);
    @memcpy(src[0..src_bytes.len], src_bytes);

    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    errdefer freeProblemsArrayList(gpa, &problems);

    try require_borrowed_from.check(gpa, &tree, .{}, &problems);
    try require_node_index_origin.check(gpa, &tree, .{}, &problems);
    try require_arena_kill_tag.check(gpa, &tree, .{}, &problems);

    return problems.toOwnedSlice(gpa);
}

/// Free every Problem in `slice` (each owns its message + optional
/// allocations) plus the slice itself.
pub fn freeProblems(gpa: std.mem.Allocator, slice: []Problem) void {
    for (slice) |*p| p.deinit(gpa);
    gpa.free(slice);
}

fn freeProblemsArrayList(gpa: std.mem.Allocator, list: *std.ArrayListUnmanaged(Problem)) void {
    for (list.items) |*p| p.deinit(gpa);
    list.deinit(gpa);
}

// ── Tests ───────────────────────────────────────────────────────

test "lib API: analyzeEscape end-to-end with a tmpDir-written file" {
    // Smoke test the full public surface: write a synthetic source
    // with a known invariant-#5 violation, call analyzeEscape, expect
    // one problem back.  Validates that the library API contract
    // (caller frees, errdefer cleanup, optional cache, optional
    // config) all hangs together.
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "foo.zig", .data =
        \\const Ast = struct {};
        \\pub fn foo(ast: Ast) void {
        \\    ast.setNodeTag(0);
        \\}
        \\/// @mutates_ast
        \\pub fn setNodeTag(self: Ast, _: u32) void { _ = self; }
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "foo.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "invariant #5") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: analyzeEscape with null cache disables cross-file" {
    // When cache=null, no remote-resolver context is built.  The
    // analyzer still runs against same-file annotations; cross-file
    // lookups just miss.  Synthetic file has only same-file
    // annotations so analysis still fires.
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "bar.zig", .data =
        \\const Ast = struct {};
        \\pub fn foo(ast: Ast) void {
        \\    ast.setNodeTag(0);
        \\}
        \\/// @mutates_ast
        \\pub fn setNodeTag(self: Ast, _: u32) void { _ = self; }
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "bar.zig" });
    defer gpa.free(path);

    const problems = try analyzeEscape(gpa, tio, path, null, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "invariant #5") != null) found = true;
    }
    try std.testing.expect(found);
}

// ── Tests — pull every submodule's tests in via refAllDecls ─────

test {
    _ = cfg_mod;
    _ = annotations_mod;
    _ = analyzer_mod;
    _ = imports_mod;
    _ = remote_resolver_mod;
    _ = config_mod;
    _ = problem_mod;
    _ = @import("abstract_state.zig");
    _ = @import("transfer.zig");
    _ = require_borrowed_from;
    _ = require_node_index_origin;
    _ = require_arena_kill_tag;
    std.testing.refAllDecls(@This());
}
