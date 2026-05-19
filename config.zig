//! Project-tunable knobs.  Small by design — zbc is a focused
//! arena-escape checker for Zig source.  Two pattern lists let
//! projects declare what counts as arena creation/destruction in
//! their codebase (defaults match std.heap.ArenaAllocator).

const std = @import("std");

pub const Config = struct {
    /// Source-text substrings that classifyExpr treats as
    /// "this call mints a fresh arena."  First match wins.
    /// Substring match (not token-aware) — order from specific to
    /// least specific if you customize.
    arena_init_patterns: []const []const u8 = &.{
        "ArenaAllocator.init",
    },

    /// Source-text substrings for "this call kills the receiver
    /// arena."  Detected in lowerCallStmt — matching call shapes
    /// emit `.arena_kill` against the receiver local.
    arena_kill_patterns: []const []const u8 = &.{
        ".deinit(",
    },

    /// Source-text substrings for "this call returns a heap
    /// allocation."  Defaults cover std.mem.Allocator's surface.
    /// Matched as substrings of the full call expression.
    heap_alloc_patterns: []const []const u8 = &.{
        ".alloc(",
        ".allocSentinel(",
        ".create(",
        ".dupe(",
        ".dupeZ(",
        ".allocPrint(",
        ".allocPrintZ(",
    },

    /// Source-text substrings for "this call frees its first arg."
    /// The freed pointer is extracted from the call's args[0].
    heap_free_patterns: []const []const u8 = &.{
        ".free(",
        ".destroy(",
    },

    /// Which invariants to enforce.  zbc currently has exactly one
    /// — arena_escape (slice borrowed from function-local arena
    /// must not escape).  Kept as a list so future generic
    /// invariants can be added without breaking the CLI surface.
    enabled: []const Invariant = &all_invariants,
};

/// Invariants zbc enforces.  All generic — no language-domain
/// assumptions about parsers, ASTs, or any project-specific
/// vocabulary.
pub const Invariant = enum {
    /// A slice borrowed from a function-local arena must not be
    /// returned past the arena's death.  Catches the common
    /// "return a slice from per-call arena" mistake.
    arena_escape,
    /// A pointer or slice into a function-local stack variable must
    /// not be returned — the storage dies with the frame.
    stack_escape,
    /// A value initialized to `undefined` and never reassigned must
    /// not be returned (caller would receive garbage).
    use_undefined,
    /// A heap allocation must not be freed twice on any path.
    heap_double_free,
    /// A heap pointer must not be read or returned after it has
    /// been freed.
    heap_use_after_free,
    /// A value borrowed from an arena must not be read after the
    /// arena is deinit'd.  Complements arena_escape (which catches
    /// the special case of leaking the borrow past return).
    arena_use_after_kill,
};

pub const all_invariants: [6]Invariant = .{
    .arena_escape,
    .stack_escape,
    .use_undefined,
    .heap_double_free,
    .heap_use_after_free,
    .arena_use_after_kill,
};

pub const Default: Config = .{};

/// True iff `config.enabled` contains `inv`.
pub fn isEnabled(config: *const Config, inv: Invariant) bool {
    for (config.enabled) |e| {
        if (e == inv) return true;
    }
    return false;
}

/// Map a CLI-style name to its Invariant tag.  Returns null on
/// unknown names so callers can surface a useful error message
/// rather than silently ignoring typos.
pub fn invariantFromName(name: []const u8) ?Invariant {
    inline for (@typeInfo(Invariant).@"enum".fields) |f| {
        if (std.mem.eql(u8, name, f.name)) return @enumFromInt(f.value);
    }
    return null;
}

// ── Tests ──────────────────────────────────────────────────

test "Default config defaults" {
    try std.testing.expectEqualStrings("ArenaAllocator.init", Default.arena_init_patterns[0]);
    try std.testing.expectEqualStrings(".deinit(", Default.arena_kill_patterns[0]);
}

test "invariantFromName round-trips every variant" {
    inline for (@typeInfo(Invariant).@"enum".fields) |f| {
        const got = invariantFromName(f.name).?;
        try std.testing.expectEqual(@as(Invariant, @enumFromInt(f.value)), got);
    }
}

test "invariantFromName returns null on unknown" {
    try std.testing.expectEqual(@as(?Invariant, null), invariantFromName("not_an_invariant"));
}
