//! Built-in vocabulary for opaque / extern / stdlib fns whose
//! bodies aren't analyzable by source inference.
//!
//! When a call site references a fn we can't see the body of, we
//! fall back to this name-based vocabulary.  Conservative by design:
//! anything not in the vocabulary is `.unknown`, which downstream
//! consumers treat as "assume nothing."
//!
//! Three classification axes:
//!
//!   - returns: what kind of value comes back (heap / borrowed / plain)
//!   - takes_ownership_of: which param's value the call consumes (if any)
//!   - effect: side-effect classification for the (very) coarse "is this
//!     call a free site?" question
//!
//! Method-name patterns intentionally overlap with `receiver.zig`
//! classifiers — receiver.zig says "this NAME is an alloc-style
//! method"; vocabulary says "if you see a call to this name on a
//! receiver, treat the return value as a fresh heap allocation."
//! Two consumers of the same name conventions.

const std = @import("std");
const fn_summary = @import("fn_summary.zig");

const FnSummary = fn_summary.FnSummary;
const Returns = fn_summary.Returns;

/// Look up a method name against the built-in vocabulary.  `name` is
/// the bare method ident — `alloc`, not `gpa.alloc`.  Returns null
/// when the name doesn't have a known summary; caller should fall
/// back to body inference or `.unknown`.
pub fn lookupMethod(name: []const u8) ?FnSummary {
    // Allocation family — returns a fresh heap allocation.
    if (matchAny(name, &.{
        "alloc",
        "allocSentinel",
        "allocAdvanced",
        "create",
        "dupe",
        "dupeZ",
        "allocPrint",
        "allocPrintZ",
        "allocPrintSentinel",
        "realloc",
    })) {
        return .{ .returns = .heap, .allocates = true };
    }

    // Free family — takes ownership of arg 0 (the value being freed).
    if (matchAny(name, &.{
        "free",
        "destroy",
    })) {
        return .{ .takes_ownership_of = 0, .deallocates = true };
    }

    // Cleanup family — receiver consumes itself (self).
    if (matchAny(name, &.{
        "deinit",
        "close",
        "release",
        "deref",
        "unref",
        "removeRef",
        "finalize",
        "dispose",
    })) {
        // Receiver is the implicit arg 0 for method-call style.
        return .{ .takes_ownership_of = 0, .deallocates = true };
    }

    // Acquire family — increments a refcount.  Doesn't return owned;
    // doesn't take ownership.  But callers may want to know.
    if (matchAny(name, &.{
        "reference",
        "retain",
        "addRef",
        "addref",
        "acquire",
        "pendingActivityRef",
    })) {
        return .{ .returns = .plain };
    }

    return null;
}

fn matchAny(name: []const u8, table: []const []const u8) bool {
    for (table) |entry| {
        if (std.mem.eql(u8, name, entry)) return true;
    }
    return false;
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

test "vocabulary: alloc family returns heap" {
    const s = lookupMethod("alloc").?;
    try testing.expect(s.returns == .heap);
    try testing.expect(s.allocates);
}

test "vocabulary: free family takes ownership of arg 0" {
    const s = lookupMethod("free").?;
    try testing.expectEqual(@as(?u32, 0), s.takes_ownership_of);
    try testing.expect(s.deallocates);
}

test "vocabulary: cleanup methods take ownership of receiver" {
    const s = lookupMethod("deinit").?;
    try testing.expectEqual(@as(?u32, 0), s.takes_ownership_of);
}

test "vocabulary: unknown name returns null" {
    try testing.expect(lookupMethod("totally_made_up_method") == null);
}

test "vocabulary: acquire family is plain (no ownership transfer)" {
    const s = lookupMethod("reference").?;
    try testing.expect(s.returns == .plain);
    try testing.expectEqual(@as(?u32, null), s.takes_ownership_of);
}
