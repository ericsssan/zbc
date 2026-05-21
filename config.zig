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
    /// A heap allocation must be freed with the same allocator
    /// that produced it.  Catches the PR #29840 class:
    /// `mimalloc_arena.alloc(...)` then `default.free(...)` (UB
    /// under any reasonable allocator implementation).
    allocator_mismatch,
    /// Calling a destructor (`destroy` / `deinit` / etc.) on an
    /// interior pointer into a container's storage is UB under
    /// typical allocators.  Catches the PR #30166 class:
    /// `for (entries.items) |*r| r.destroy();`.
    interior_pointer_destroy,
    /// A type with a heap-creator method (`<x>.create(Self)`) has
    /// a destructor (finalize / deinit / destroy) that doesn't
    /// free `self` — every instance leaks the heap descriptor.
    /// Catches PR #29840 class: `ResolveMessage.create` allocates
    /// self via `allocator.create(...)` but `finalize()` never
    /// calls `allocator.destroy(this)`.
    heap_leak,
    /// An assignment to long-lived storage (`x.* = ...` or
    /// `obj.field = ...`) whose RHS is an anonymous struct literal
    /// `.{ .tag = <expr> }` where `<expr>` contains an early-exit
    /// (`try ...` or `catch return ...` / `catch |...| { ... return; ... }`).
    /// Zig writes the union tag to the result location BEFORE
    /// evaluating the payload, so on the error path the LHS is
    /// left with the new tag and the old/garbage payload bytes — a
    /// later read (often via an `errdefer this.deinit()`) sees a
    /// wild pointer.  Catches PR #29422 class.
    partial_union_write,
    /// A "dupe" function returns `T` by value via a bitwise copy
    /// (`var dup = this.*; return dup;`), and T has a heap-owning
    /// field signalled by an `<X>_allocated: bool` sibling — but
    /// the dupe doesn't either clear `<X>_allocated` or re-allocate
    /// `<X>` independently.  Both the source and the dupe now hold
    /// the same heap pointer with `<X>_allocated == true`, so the
    /// later frees from each side collide (UAF, then double-free).
    /// Catches PR #29910 class: `Blob.dupeWithContentType`.
    aliased_heap_dupe,
    /// A heap-owning field is assigned (`this.<X> = <expr>;`) and
    /// then `this.*` is overwritten with a struct literal that
    /// does NOT include `.<X>`, so `<X>` silently falls back to
    /// its declared default (usually `null` / `&.{}`).  The prior
    /// heap pointer is unreachable and never freed by `deinit()`
    /// (which checks the now-default value).  Catches PR #29854
    /// class: `PathWatcher.init` clobbered `this.resolved_path`.
    clobbered_by_struct_reset,
    /// A call to `<allocator>.realloc(slice, <expr> * @sizeOf(T))`
    /// — the new-length argument multiplies by `@sizeOf(T)` as if
    /// it were a byte count, but Zig's `Allocator.realloc` takes
    /// an ELEMENT count.  The allocation grows by `@sizeOf(T)×`
    /// the intended size on every call.  Catches PR #29452 class:
    /// `SmallList.tryGrow` over-allocated.
    realloc_byte_count,
    /// A type's destructor (`deinit` / `finalize` / `destroy`)
    /// mentions some same-typed sibling fields but omits others.
    /// E.g. fields `query_string_map: ?QueryStringMap` and
    /// `param_map: ?QueryStringMap` — destructor handles the
    /// first but forgets the second.  Catches PR #29853 class:
    /// `MatchedRoute.deinit` forgot to free `param_map`.
    asymmetric_field_free,
    /// `const X = try <Type>.<method>(...);` where `<Type>` has a
    /// `deinit` method, then a subsequent `try` in the same scope
    /// with NO `errdefer X.deinit();` between.  If the second
    /// `try` throws, X leaks (its deinit isn't reached).  Catches
    /// PR #30169 class: `node_fs` Symlink/Link/Rename.fromJS where
    /// `old_path` was leaked when `new_path = try PathLike.fromJS(...)`
    /// errored.
    missing_errdefer_between_tries,
};

pub const all_invariants: [15]Invariant = .{
    .arena_escape,
    .stack_escape,
    .use_undefined,
    .heap_double_free,
    .heap_use_after_free,
    .arena_use_after_kill,
    .allocator_mismatch,
    .interior_pointer_destroy,
    .heap_leak,
    .partial_union_write,
    .aliased_heap_dupe,
    .clobbered_by_struct_reset,
    .realloc_byte_count,
    .asymmetric_field_free,
    .missing_errdefer_between_tries,
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
