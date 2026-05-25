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
        std.mem.eql(u8, name, "allocAdvanced") or
        std.mem.eql(u8, name, "dupe") or
        std.mem.eql(u8, name, "dupeZ") or
        std.mem.eql(u8, name, "create") or
        std.mem.eql(u8, name, "allocPrint") or
        std.mem.eql(u8, name, "allocPrintZ") or
        std.mem.eql(u8, name, "allocPrintSentinel") or
        std.mem.eql(u8, name, "realloc");
}

/// Container-mutation methods that STORE the caller's data into the
/// container's backing storage.  When the data is borrowed (e.g.
/// from an arena that's about to die), storing it through one of
/// these into a longer-lived container leaves a dangling slice.
pub fn isContainerStoreMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "append") or
        std.mem.eql(u8, name, "appendSlice") or
        std.mem.eql(u8, name, "appendNTimes") or
        std.mem.eql(u8, name, "insert") or
        std.mem.eql(u8, name, "insertSlice") or
        std.mem.eql(u8, name, "put") or
        std.mem.eql(u8, name, "putAssumeCapacity") or
        std.mem.eql(u8, name, "putNoClobber") or
        std.mem.eql(u8, name, "addOne") or
        std.mem.eql(u8, name, "addManyAsSlice");
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

test "isAllocMethodName" {
    const t = std.testing;
    try t.expect(isAllocMethodName("alloc"));
    try t.expect(isAllocMethodName("create"));
    try t.expect(isAllocMethodName("dupe"));
    try t.expect(isAllocMethodName("realloc"));
    try t.expect(isAllocMethodName("allocPrint"));
    try t.expect(isAllocMethodName("allocAdvanced"));
    try t.expect(!isAllocMethodName("free"));
    try t.expect(!isAllocMethodName("destroy"));
    try t.expect(!isAllocMethodName("deinit"));
    try t.expect(!isAllocMethodName("totally_made_up_method"));
}

test "method classifiers don't overlap incorrectly" {
    const t = std.testing;
    try t.expect(isCleanupMethodName("deinit"));
    try t.expect(isAcquireMethodName("reference"));
    try t.expect(!isAcquireMethodName("ref")); // too generic
    try t.expect(isReleaseMethodName("release"));
    try t.expect(isReleaseMethodName("pendingActivityUnref"));
}
