//! Receiver / method-name classifiers.
//!
//! Per-rule precision iteration revealed that the same set of
//! name-based filters keeps coming up:
//!   - "is this an allocator receiver name?"
//!   - "is this self / this?"
//!   - "is this a canonical out-param name?"
//!   - "is this a cleanup method (deinit / free / etc.)?"
//!   - "is this an addref / release method?"
//!
//! Before this module, each rule reimplemented these with slight
//! variations (one rule had `allocator`-suffix matching, another
//! didn't; one accepted `gpa`, another didn't).  Centralizing
//! keeps the rules consistent and fixes get rolled out everywhere.

const std = @import("std");

// ── Receiver names ────────────────────────────────────────

/// Conservative allowlist of identifiers that look like an
/// allocator handle.  Matches by suffix / substring patterns
/// rather than an exact list to handle project-specific
/// allocator names (`string_alloc`, `grapheme_alloc`,
/// `default_allocator`, etc.).
pub fn isAllocatorishName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, "gpa")) return true;
    if (std.mem.eql(u8, name, "alloc")) return true;
    if (std.mem.eql(u8, name, "allocator")) return true;
    if (std.mem.eql(u8, name, "a")) return true;
    if (std.mem.endsWith(u8, name, "_alloc")) return true;
    if (std.mem.endsWith(u8, name, "_allocator")) return true;
    if (std.mem.endsWith(u8, name, "Alloc")) return true;
    if (std.mem.endsWith(u8, name, "Allocator")) return true;
    return false;
}

/// True for `self` / `this` — the canonical method-receiver
/// parameter names in Zig.
pub fn isSelfReceiverName(name: []const u8) bool {
    return std.mem.eql(u8, name, "self") or std.mem.eql(u8, name, "this");
}

/// True for `result` / `out` / `r` — canonical out-param names
/// used for in-place struct construction.
pub fn isCanonicalOutName(name: []const u8) bool {
    return std.mem.eql(u8, name, "result") or
        std.mem.eql(u8, name, "out") or
        std.mem.eql(u8, name, "r");
}

// ── Method classification ────────────────────────────────

/// Methods that destroy / clean up a resource.
pub fn isCleanupMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "close") or
        std.mem.eql(u8, name, "release") or
        std.mem.eql(u8, name, "deref") or
        std.mem.eql(u8, name, "unref") or
        std.mem.eql(u8, name, "removeRef") or
        std.mem.eql(u8, name, "finalize") or
        std.mem.eql(u8, name, "dispose");
}

/// Methods that acquire a refcounted reference (addref family).
/// `ref` alone is excluded — too generic, collides with
/// "borrow a sub-reference" usage.
pub fn isAcquireMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "reference") or
        std.mem.eql(u8, name, "retain") or
        std.mem.eql(u8, name, "addRef") or
        std.mem.eql(u8, name, "addref") or
        std.mem.eql(u8, name, "acquire") or
        std.mem.eql(u8, name, "pendingActivityRef");
}

/// Methods that release a refcounted reference (broader than
/// cleanup — used for the suppressor in `unreleased-refs-on-error`).
pub fn isReleaseMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "release") or
        std.mem.eql(u8, name, "deref") or
        std.mem.eql(u8, name, "unref") or
        std.mem.eql(u8, name, "removeRef") or
        std.mem.eql(u8, name, "pendingActivityUnref");
}

/// Methods that conventionally allocate.
pub fn isAllocMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "alloc") or
        std.mem.eql(u8, name, "allocSentinel") or
        std.mem.eql(u8, name, "dupe") or
        std.mem.eql(u8, name, "dupeZ") or
        std.mem.eql(u8, name, "create") or
        std.mem.eql(u8, name, "allocPrint") or
        std.mem.eql(u8, name, "allocPrintZ") or
        std.mem.eql(u8, name, "allocPrintSentinel");
}

/// Destructor-style fn names — used to skip the `<recv>.<field>`
/// reset-check in rules where the receiver is about to be
/// discarded anyway.  Prefix-match catches `deinit_slice` /
/// `destroyInternal` / etc.  `take*` / `consume*` / `into*` are
/// convention for consume-the-receiver methods.
pub fn isDestructorFnName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "deinit") or
        std.mem.startsWith(u8, name, "destroy") or
        std.mem.startsWith(u8, name, "finalize") or
        std.mem.startsWith(u8, name, "dispose") or
        std.mem.startsWith(u8, name, "take") or
        std.mem.startsWith(u8, name, "consume") or
        std.mem.startsWith(u8, name, "into") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "close");
}

/// Fn names matching the idempotent reset/clear/end family —
/// the canonical pattern for state-machine reset methods that
/// may be invoked many times across an object's lifetime.
pub fn isIdempotentResetFnName(name: []const u8) bool {
    return std.mem.eql(u8, name, "reset") or
        std.mem.eql(u8, name, "clear") or
        std.mem.eql(u8, name, "clearRetainingCapacity") or
        std.mem.eql(u8, name, "end") or
        std.mem.eql(u8, name, "endCommand") or
        std.mem.eql(u8, name, "endOperation") or
        std.mem.eql(u8, name, "finish") or
        std.mem.startsWith(u8, name, "reset") or
        std.mem.startsWith(u8, name, "clear") or
        std.mem.startsWith(u8, name, "end_");
}

// ── Tests ──────────────────────────────────────────────────

test "isAllocatorishName" {
    const t = std.testing;
    try t.expect(isAllocatorishName("gpa"));
    try t.expect(isAllocatorishName("allocator"));
    try t.expect(isAllocatorishName("string_alloc"));
    try t.expect(isAllocatorishName("graphemeAllocator"));
    try t.expect(!isAllocatorishName("self"));
    try t.expect(!isAllocatorishName("buffer"));
}

test "isSelfReceiverName" {
    const t = std.testing;
    try t.expect(isSelfReceiverName("self"));
    try t.expect(isSelfReceiverName("this"));
    try t.expect(!isSelfReceiverName("it"));
    try t.expect(!isSelfReceiverName("inspector"));
}

test "method classifiers don't overlap incorrectly" {
    const t = std.testing;
    try t.expect(isCleanupMethodName("deinit"));
    try t.expect(isAcquireMethodName("reference"));
    try t.expect(!isAcquireMethodName("ref")); // too generic
    try t.expect(isReleaseMethodName("release"));
    try t.expect(isReleaseMethodName("pendingActivityUnref"));
}
