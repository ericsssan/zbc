//! Class 1: invariants decided by the CFG + abstract-interpretation
//! worklist, not by a pattern detector.
//!
//! Each entry is a verdict *about flow facts* — the joined
//! `AbstractState` at a CFG node, keyed by allocation identity — so
//! the check lives inside a transfer function in `cfg_transfer.zig`
//! (some shapes are recognized earlier, in `cfg_builder.zig`) and is
//! gated by `isEnabled(config, .<tag>)` there.  Nothing here is
//! dispatched from `detectors.zig`: a detector gets no state.
//!
//! Keeping the list explicit is what lets `invariants.zig` prove that
//! every toggle in `config.Invariant` is accounted for by exactly one
//! class.

const std = @import("std");
const config_mod = @import("../config.zig");

pub const flow_invariants = [_]config_mod.Invariant{
    // Read or return of a heap allocation whose abstract state is dead.
    .heap_use_after_free,
    // Second `free`/`destroy` on an allocation already marked dead.
    .heap_double_free,
    // `free` through an allocator local different from the allocating one.
    .allocator_mismatch,
    // Value borrowed from an arena reaches a `ret` (or an out-param write)
    // while the arena is function-local.
    .arena_escape,
    // Any `.stack` origin reaches a `ret` or an out-param write.
    .stack_escape,
    // A borrow from an arena is read after the arena's deinit.
    .arena_use_after_kill,
    // `.undef` origin reaches a `ret` (excluding literal `return undefined`).
    .use_undefined,
    // A heap-allocating type's destructor has no path that frees `self`.
    .heap_leak,
    // `destroy()` on a pointer into a container's storage rather than one
    // returned by `allocator.create`.
    .interior_pointer_destroy,
    // Tagged-union literal whose payload contains `try` / `catch return`.
    .partial_union_write,
};

pub fn isFlowInvariant(inv: config_mod.Invariant) bool {
    for (flow_invariants) |f| if (f == inv) return true;
    return false;
}

test "flow: no duplicate tags" {
    for (flow_invariants, 0..) |a, i| {
        for (flow_invariants[i + 1 ..]) |b| {
            try std.testing.expect(a != b);
        }
    }
}
