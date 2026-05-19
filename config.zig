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
};

/// The historical ez config — preserves all behavior from phases 1-41.
/// Existing tests + sweep validate against this.
pub const Default: Config = .{};

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
