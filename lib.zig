//! Public library API for the zbc escape analyzer.

const std = @import("std");
const Ast = std.zig.Ast;

const cfg_mod = @import("cfg.zig");
const annotations_mod = @import("annotations.zig");
const analyzer_mod = @import("analyzer.zig");
const imports_mod = @import("imports.zig");
const remote_resolver_mod = @import("remote_resolver.zig");
const config_mod = @import("config.zig");
const problem_mod = @import("problem.zig");
const rule_registry = @import("rule_registry.zig");
const rule_catalog_mod = @import("rule_catalog.zig");
const file_cache_mod = @import("file_cache.zig");
const suppressions_mod = @import("suppressions.zig");

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
pub const Cache = remote_resolver_mod.Cache;
pub const Rule = rule_catalog_mod.Rule;
pub const rule_catalog = rule_catalog_mod.all;
pub const lookupRule = rule_catalog_mod.lookup;
pub const trace = @import("trace.zig");

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

    // Build imap first so the annotation pass (R7) can do cross-file
    // lookups when a remote cache is provided.
    var imap_storage: ?imports_mod.Map = null;
    defer if (imap_storage) |*m| m.deinit(gpa);
    var remote_ctx_storage: ?cfg_mod.RemoteCtx = null;
    var anno_remote: ?annotations_mod.RemoteCtx = null;
    const base_dir = std.fs.path.dirname(path) orelse ".";

    if (cache) |c| {
        imap_storage = try imports_mod.build(gpa, &tree);
        remote_ctx_storage = .{
            .imap = &imap_storage.?,
            .base_dir = base_dir,
            .cache = c,
        };
        anno_remote = .{
            .imap = &imap_storage.?,
            .base_dir = base_dir,
            .cache = c,
        };
    }

    var db = try annotations_mod.buildFull(gpa, &tree, config, anno_remote);
    defer db.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    errdefer freeProblemsArrayList(gpa, &problems);

    // Per-file shared cache, used by both flow analysis (cfg) and
    // pattern rules.  Amortizes FileModel + LocalBindings + FnSummary
    // across every consumer.
    var rule_cache = file_cache_mod.FileCache.init(gpa, &tree);
    defer rule_cache.deinit();
    // Resolve R10 Case A transitive `takes_ownership_of` and R7
    // delegator-borrow inference across all fns before the cfg pass.
    // Cross-file R7 (when remote ctx is wired) lets wrappers that
    // delegate into imported files infer their borrowed_from chain.
    var remote_adapter: ?remote_resolver_mod.RemoteSummaryAdapter = null;
    if (imap_storage) |*m| if (cache != null) {
        remote_adapter = .{
            .cache = cache.?,
            .imap = m,
            .base_dir = base_dir,
        };
    };
    const remote_ctx: ?file_cache_mod.RemoteSummaryCtx = if (remote_adapter) |*a| a.ctx() else null;
    try rule_cache.resolveTransitiveTakesWithRemote(remote_ctx);

    // Flow analysis — per-fn CFG + worklist fixed-point.
    // Iterate raw fn_decls (incl. type-builders) — lowerFunctionFull
    // decides per-fn whether to lower (returns null to skip).
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
            &rule_cache,
        )) orelse continue;
        defer cfg.deinit(gpa);
        try analyzer_mod.check(gpa, &cfg, .{ .path = path, .config = config }, &problems);
    }

    // Pattern detectors — dispatched via the comptime registry so
    // adding a rule is a one-file change (see rule_registry.zig).
    try rule_registry.runEscape(gpa, &tree, &db, &rule_cache, config, &problems);

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
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 { _ = self; return ""; }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return arena.text();
        \\}
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
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R7 method-style via anytype param + imap scan" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "inner.zig", .data =
        \\const std = @import("std");
        \\pub const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const inner = @import("inner.zig");
        \\pub const ReExport = inner.Ctx;
        \\// Anytype wrapper — param has no named type to resolve.
        \\// R7 falls back to imap scan; lib's imap contains inner.zig
        \\// which has text() annotated borrowed_from(self).
        \\pub fn anytype_wrap(c: anytype) []const u8 {
        \\    return c.text();
        \\}
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const inner = @import("inner.zig");
        \\const lib = @import("lib.zig");
        \\pub fn caller() []const u8 {
        \\    var local = inner.Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return lib.anytype_wrap(local);
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "main.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R7 method-style via AST type-name resolution" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "inner.zig", .data =
        \\const std = @import("std");
        \\pub const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const inner = @import("inner.zig");
        \\// Method-style delegator across files.  R7 in lib.zig
        \\// resolves `c`'s type to inner.Ctx and finds text() there.
        \\pub fn wrap(c: *const inner.Ctx) []const u8 {
        \\    return c.text();
        \\}
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const lib = @import("lib.zig");
        \\const inner = @import("inner.zig");
        \\pub fn caller() []const u8 {
        \\    var local = inner.Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return lib.wrap(&local);
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "main.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R8 inference fires UAF through imported alloc/free wrappers" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "heap_lib.zig", .data =
        \\const std = @import("std");
        \\pub fn xalloc(g: std.mem.Allocator, n: usize) []u8 {
        \\    return g.alloc(u8, n) catch unreachable;
        \\}
        \\pub fn dispose(g: std.mem.Allocator, p: []u8) void {
        \\    g.free(p);
        \\}
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const lib = @import("heap_lib.zig");
        \\pub fn caller(g: std.mem.Allocator) []u8 {
        \\    const buf = lib.xalloc(g, 16);
        \\    lib.dispose(g, buf);
        \\    return buf;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "main.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R10 chain — wrapper fn calls cross-file destroying method" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // lib.zig: T.finalize destroys self.
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const bun = struct { pub fn destroy(_: anytype) void {} };
        \\pub const T = struct {
        \\    x: u32 = 0,
        \\    pub fn finalize(this: *T) void { bun.destroy(this); }
        \\};
        \\
    });
    // caller.zig:
    //   `destroyT(t)` calls `t.finalize()` — cross-file method call.
    //   R10 should infer @takes(0) on destroyT by resolving
    //   t.finalize → lib.T.finalize (which IS @takes(0)).
    //   Caller `buggy` then sees destroyT(t) as a free and flags
    //   the subsequent use of t.
    try tmp.dir.writeFile(tio, .{ .sub_path = "caller.zig", .data =
        \\const lib = @import("lib.zig");
        \\pub fn destroyT(t: *lib.T) void {
        \\    t.finalize();
        \\}
        \\pub fn buggy(t: *lib.T) void {
        \\    destroyT(t);
        \\    const v = t.x;
        \\    _ = v;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "caller.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R10 field-chain — wrapper method frees field via cross-file destroy" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // lib.zig: Item.dispose destroys self.
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const bun = struct { pub fn destroy(_: anytype) void {} };
        \\pub const Item = struct {
        \\    pub fn dispose(this: *Item) void { bun.destroy(this); }
        \\};
        \\
    });
    // caller.zig: Wrapper.cleanup calls this.inner.dispose() — chain
    // resolves to lib.Item.dispose (cross-file), so cleanup should be
    // inferred as ownership_field { param=0, field="inner" }.
    try tmp.dir.writeFile(tio, .{ .sub_path = "caller.zig", .data =
        \\const lib = @import("lib.zig");
        \\pub const Wrapper = struct {
        \\    inner: *lib.Item,
        \\    pub fn cleanup(this: *Wrapper) void {
        \\        this.inner.dispose();
        \\    }
        \\};
        \\pub fn buggy(w: *Wrapper) void {
        \\    w.cleanup();
        \\    const x = w.inner;
        \\    _ = x;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "caller.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "use of `w.inner`") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file type-aware lookup disambiguates method overloads" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // lib.zig defines two types with same-named `finalize` method.
    // Only HTMLRewriter.finalize destroys self.
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const bun = struct { pub fn destroy(_: anytype) void {} };
        \\pub const HTMLRewriter = struct {
        \\    pub fn finalize(this: *HTMLRewriter) void { bun.destroy(this); }
        \\};
        \\pub const HTMLRewriterLoader = struct {
        \\    finalized: bool = false,
        \\    pub fn finalize(this: *HTMLRewriterLoader) void { this.finalized = true; }
        \\};
        \\
    });
    // caller.zig uses both — only `r.finalize()` is a real UAF;
    // `l.finalize()` must NOT fire.
    try tmp.dir.writeFile(tio, .{ .sub_path = "caller.zig", .data =
        \\const lib = @import("lib.zig");
        \\pub fn use_rewriter(r: *lib.HTMLRewriter) void {
        \\    r.finalize();
        \\    const x = r;
        \\    _ = x;
        \\}
        \\pub fn use_loader(l: *lib.HTMLRewriterLoader) void {
        \\    l.finalize();
        \\    const x = l;
        \\    _ = x;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "caller.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    // Exactly one rewriter UAF site (the `const x = r;` use; the
    // `_ = x;` use is on the alias).  Loader uses must not fire.
    var rewriter_uaf_count: usize = 0;
    var loader_fp_count: usize = 0;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "use of `r`") != null or
            std.mem.indexOf(u8, p.message, "use of `x`") != null)
        {
            rewriter_uaf_count += 1;
        }
        if (std.mem.indexOf(u8, p.message, "use of `l`") != null) loader_fp_count += 1;
    }
    try std.testing.expect(rewriter_uaf_count >= 1);
    try std.testing.expectEqual(@as(usize, 0), loader_fp_count);
}

test "lib API: analyzeEscape with null cache still works on same-file annotations" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "bar.zig", .data =
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 { _ = self; return ""; }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return arena.text();
        \\}
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
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

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
    _ = rule_catalog_mod;
    // Pattern rules — registered in rule_registry; pulling it in
    // refAllDecls'es every rule module so inline tests run.
    _ = rule_registry;
    _ = file_cache_mod;
    _ = suppressions_mod;
    _ = @import("fn_summary.zig");
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
