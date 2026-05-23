//! Public library API for the zbc escape analyzer.

const std = @import("std");
const Ast = std.zig.Ast;

const cfg_mod = @import("cfg.zig");
const annotations_mod = @import("annotations.zig");
const analyzer_mod = @import("analyzer.zig");
const config_mod = @import("config.zig");
const problem_mod = @import("problem.zig");
const rule_registry = @import("rule_registry.zig");
const rule_catalog_mod = @import("rule_catalog.zig");
const file_cache_mod = @import("file_cache.zig");
const suppressions_mod = @import("suppressions.zig");
const zls_resolver_mod = @import("zls_resolver.zig");

pub const Config = config_mod.Config;
pub const DefaultConfig = config_mod.Default;
pub const Invariant = config_mod.Invariant;
pub const all_invariants = config_mod.all_invariants;
pub const isEnabled = config_mod.isEnabled;
pub const invariantFromName = config_mod.invariantFromName;
pub const Problem = problem_mod.Problem;
pub const Note = problem_mod.Note;
pub const Pos = problem_mod.Pos;
pub const Severity = problem_mod.Severity;
pub const Rule = rule_catalog_mod.Rule;
pub const rule_catalog = rule_catalog_mod.all;
pub const lookupRule = rule_catalog_mod.lookup;
pub const trace = @import("trace.zig");

pub fn analyzeEscape(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
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

    var db = try annotations_mod.buildFull(gpa, &tree, config);
    defer db.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    errdefer freeProblemsArrayList(gpa, &problems);

    // ZLS-backed type resolver — cross-module type queries that
    // zbc's own AST-only tracking can't answer (for-loop captures,
    // generic instantiations, multi-hop @import aliases, cross-file
    // method resolution).  Optional; when init fails (e.g. ZLS can't
    // open the path) we silently fall through to the AST-only path.
    // Built BEFORE the FileCache so the cache can consult it during
    // transitive-takes resolution (param-type lookups via ZLS handle
    // `*lib.T` cross-module params that token-walks can't see).
    var zls_resolver: zls_resolver_mod.ZlsResolver = undefined;
    const zls_ok = blk: {
        zls_resolver.init(gpa, io, path, src) catch |err| {
            std.log.debug("zls_resolver init failed for {s}: {}", .{ path, err });
            break :blk false;
        };
        break :blk true;
    };
    defer if (zls_ok) zls_resolver.deinit();
    const zls_ptr: ?*zls_resolver_mod.ZlsResolver = if (zls_ok) &zls_resolver else null;

    // Per-file shared cache, used by both flow analysis (cfg) and
    // pattern rules.  Amortizes FileModel + LocalBindings + FnSummary
    // across every consumer.
    var rule_cache = file_cache_mod.FileCache.init(gpa, &tree);
    defer rule_cache.deinit();
    rule_cache.setZls(zls_ptr);
    try rule_cache.resolveTransitiveTakes();

    // Flow analysis — per-fn CFG + worklist fixed-point.
    // Iterate raw fn_decls (incl. type-builders) — lowerFunctionFull
    // decides per-fn whether to lower (returns null to skip).
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var cfg = (try cfg_mod.lowerFunctionFullWithZls(
            gpa,
            &tree,
            node,
            &db,
            config,
            &rule_cache,
            zls_ptr,
        )) orelse continue;
        defer cfg.deinit(gpa);
        try analyzer_mod.check(gpa, &cfg, .{ .path = path, .config = config }, &problems);
    }

    // Pattern detectors — dispatched via the comptime registry so
    // adding a rule is a one-file change (see rule_registry.zig).
    try rule_registry.runEscape(gpa, &tree, &rule_cache, config, &problems);

    // Apply per-line suppressions parsed from `// zbc-disable-line` /
    // `// zbc-disable-next-line` source comments.  Filter happens at
    // the boundary so individual rules don't need to know about it.
    var supp = try suppressions_mod.parse(gpa, src);
    defer supp.deinit();
    return try filterSuppressed(gpa, &problems, &supp);
}

/// Drop any Problems whose start.line matches an active suppression.
/// Frees dropped problems immediately; the caller still owns the
/// returned slice and the surviving problems' message storage.
fn filterSuppressed(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    supp: *const suppressions_mod.Suppressions,
) ![]Problem {
    if (supp.entries.len == 0) return problems.toOwnedSlice(gpa);
    var kept: std.ArrayListUnmanaged(Problem) = .empty;
    errdefer freeProblemsArrayList(gpa, &kept);
    for (problems.items) |p| {
        if (supp.isSuppressed(p.rule_id, p.start.line)) {
            var dead = p;
            dead.deinit(gpa);
            continue;
        }
        try kept.append(gpa, p);
    }
    problems.deinit(gpa);
    return kept.toOwnedSlice(gpa);
}

pub fn freeProblems(gpa: std.mem.Allocator, slice: []Problem) void {
    for (slice) |*p| p.deinit(gpa);
    gpa.free(slice);
}

fn freeProblemsArrayList(gpa: std.mem.Allocator, list: *std.ArrayListUnmanaged(Problem)) void {
    for (list.items) |*p| p.deinit(gpa);
    list.deinit(gpa);
}

// ── Tests ───────────────────────────────────────────────────────

test "lib API: analyzeEscape end-to-end flags arena escape" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "foo.zig", .data =
        \\const std = @import("std");
        \\const Arena = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    bytes: []const u8 = "",
        \\    pub fn text(self: *const Arena) []const u8 { return self.bytes; }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = Arena{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return arena.text();
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "foo.zig" });
    defer gpa.free(path);

    const problems = try analyzeEscape(gpa, tio, path, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

// NOTE: 6 cross-file annotation tests removed when remote_resolver
// was retired (R7 anytype/imap-scan, R7 type-name resolution, R8
// alloc/free wrappers, R10 chain, R10 field-chain, type-aware
// overload disambiguation).  Cross-module reasoning now flows
// through ZLS-based type resolution (zls_resolver.zig +
// cfg.receiverTypeOfNode).  ZLS does not parse zbc's `/// @returns`
// comments, so cross-file annotation propagation is no longer
// supported.  Same-file inference is unchanged.

test {
    _ = cfg_mod;
    _ = annotations_mod;
    _ = analyzer_mod;
    _ = config_mod;
    _ = problem_mod;
    _ = @import("abstract_state.zig");
    _ = @import("transfer.zig");
    _ = rule_catalog_mod;
    // Pattern rules — registered in rule_registry; pulling it in
    // refAllDecls'es every rule module so inline tests run.
    _ = rule_registry;
    _ = file_cache_mod;
    _ = suppressions_mod;
    _ = @import("fn_summary.zig");
    _ = @import("zls_resolver.zig");
    _ = @import("vocabulary.zig");
    _ = @import("lexer.zig");
    _ = @import("scope.zig");
    _ = @import("receiver.zig");
    _ = @import("testing.zig");
    _ = @import("model.zig");
    _ = @import("trace.zig");
    _ = @import("local.zig");
    _ = @import("query.zig");
    _ = @import("model_query.zig");
    std.testing.refAllDecls(@This());
}
