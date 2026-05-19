//! Project-tunable knobs.  Every ez-specific string previously
//! hardcoded in cfg.zig now lives here.  `Default` matches the
//! historical behavior so projects already using the tool see no
//! change; downstream projects can construct their own `Config`
//! with their own type names + textual call patterns.
//!
//! Future evolution (phase 43+):
//!   - Load Config from a TOML/JSON/Zig file via a CLI flag.
//!   - Per-project invariant kits (the rule SEMANTICS live in
//!     transfer.zig; the lookup vocabulary is in this Config).
//!   - Pluggable Stmt kinds for project-defined invariants.

const std = @import("std");

/// All knobs are slice literals so a downstream project can declare:
///   const my_config = borrow_check.Config{
///       .ast_type_name = "Tree",
///       .ast_init_patterns = &.{ "Tree.from_source", "parseTree" },
///       .arena_kill_patterns = &.{ ".deinit(", ".release(" },
///       ...
///   };
pub const Config = struct {
    /// Identifier-token name that param-seeding (cfg.seedParams)
    /// treats as "this param is an Ast value, mint a fresh AstId".
    /// Matched on TOKEN boundary, so `FooAst` won't match but
    /// `*const Ast` and `Ast.Node` will.
    ast_type_name: []const u8 = "Ast",

    /// Source-text substrings that classifyExpr treats as
    /// "this call expression mints a fresh Ast value".  First
    /// match wins.  Substring match (NOT token-aware), so order
    /// from most specific to least.
    ast_init_patterns: []const []const u8 = &.{
        "Ast.parse",
    },

    /// Source-text substrings for "this call expression mints a
    /// fresh arena".  Same substring-match semantics as
    /// ast_init_patterns.
    arena_init_patterns: []const []const u8 = &.{
        "ArenaAllocator.init",
    },

    /// Source-text substrings for "this call kills the receiver
    /// arena".  Detected in lowerCallStmt — matching call shapes
    /// emit `.arena_kill` against the receiver local.
    arena_kill_patterns: []const []const u8 = &.{
        ".deinit(",
    },

    /// Source-text substrings for "this call joins a worker
    /// thread".  Detected in lowerCallStmt — emits `.thread_join`.
    thread_join_patterns: []const []const u8 = &.{
        ".join(",
    },

    /// Which invariants to enforce (phase 46).  Downstream projects
    /// can opt out of any subset they don't care about — e.g. a
    /// codebase that doesn't pass NodeIndex across Ast boundaries
    /// might only enable arena_escape + ast_mutation.  Default
    /// `all_invariants` matches historical ez behavior.
    ///
    /// Disabling an invariant skips both the emit-side stmts (cfg
    /// won't allocate per-call check stmts) and the transfer-side
    /// validation (analyzer won't report).  Other invariants stay
    /// fully active.
    enabled: []const Invariant = &all_invariants,
};

/// Set of invariants the analyzer can enforce.  Each maps to a
/// specific check pattern documented in the design doc; downstream
/// projects pick which subset is relevant.
pub const Invariant = enum {
    /// #1: NodeIndex from Ast A must only flow back into A.
    /// Drives @takes node_index_of validation at call sites.
    ast_identity,
    /// #2: A slice borrowed from an arena must not outlive that
    /// arena.  Drives the function-local arena-escape check.
    arena_escape,
    /// #3: Worker-arena pointer must not be read by main thread
    /// before the join point.  Scaffolded only — needs inter-
    /// procedural propagation to fire.
    thread_arena,
    /// #4: ScopeId/SymbolId from pass N must not be used in
    /// pass M.  Scaffolded only.
    pass_identity,
    /// #5: After parse, the Ast is read-only.  Drives
    /// @mutates_ast call-site flagging.
    ast_mutation,
};

pub const all_invariants: [5]Invariant = .{
    .ast_identity,
    .arena_escape,
    .thread_arena,
    .pass_identity,
    .ast_mutation,
};

/// The historical ez config — preserves all behavior from phases 1-41.
/// Existing tests + sweep validate against this.
pub const Default: Config = .{};

/// True iff `config.enabled` contains `inv`.  Used by cfg.zig
/// (gate emit-side checks) and transfer.zig (gate validation).
pub fn isEnabled(config: *const Config, inv: Invariant) bool {
    for (config.enabled) |e| {
        if (e == inv) return true;
    }
    return false;
}

/// Map a CLI-style name ("ast_identity") to its Invariant tag.
/// Returns null on unknown names so callers can surface a useful
/// error message rather than silently ignoring typos.
pub fn invariantFromName(name: []const u8) ?Invariant {
    inline for (@typeInfo(Invariant).@"enum".fields) |f| {
        if (std.mem.eql(u8, name, f.name)) return @enumFromInt(f.value);
    }
    return null;
}

test "invariantFromName round-trips every variant" {
    inline for (@typeInfo(Invariant).@"enum".fields) |f| {
        const got = invariantFromName(f.name).?;
        try std.testing.expectEqual(@as(Invariant, @enumFromInt(f.value)), got);
    }
}

test "invariantFromName returns null on unknown" {
    try std.testing.expectEqual(@as(?Invariant, null), invariantFromName("not_an_invariant"));
    try std.testing.expectEqual(@as(?Invariant, null), invariantFromName(""));
}

// ── Tests ──────────────────────────────────────────────────

test "Default config matches ez historical strings" {
    try std.testing.expectEqualStrings("Ast", Default.ast_type_name);
    try std.testing.expectEqualStrings("Ast.parse", Default.ast_init_patterns[0]);
    try std.testing.expectEqualStrings("ArenaAllocator.init", Default.arena_init_patterns[0]);
    try std.testing.expectEqualStrings(".deinit(", Default.arena_kill_patterns[0]);
    try std.testing.expectEqualStrings(".join(", Default.thread_join_patterns[0]);
}

test "downstream Config example: rename Ast to Tree" {
    const c: Config = .{
        .ast_type_name = "Tree",
        .ast_init_patterns = &.{ "Tree.from_source", "parseTree" },
    };
    try std.testing.expectEqualStrings("Tree", c.ast_type_name);
    try std.testing.expectEqual(@as(usize, 2), c.ast_init_patterns.len);
    // Fields not overridden keep Default values.
    try std.testing.expectEqualStrings(".deinit(", c.arena_kill_patterns[0]);
}
