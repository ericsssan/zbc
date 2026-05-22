// sentinel-strip-free-size-mismatch — ghostty-org/ghostty#8886.
// `alloc.free(X.ptr[0..X.len])` strips sentinel; if X is `[:0]`
// the allocator's free-size check fails.

const std = @import("std");

const Str = struct {
    ptr: ?[*]const u8,
    len: usize,
};

// Bug — fires on `.free`.
pub fn ghostty_string_free_buggy(str: Str, alloc: std.mem.Allocator) void {
    alloc.free(str.ptr.?[0..str.len]);
}

// Control — pass the slice directly.  Should NOT fire.
pub fn ok_direct(slice: []u8, alloc: std.mem.Allocator) void {
    alloc.free(slice);
}

// Control — preserve sentinel in the slice expression.  Should
// NOT fire.
pub fn ok_sentinel(str: Str, alloc: std.mem.Allocator) void {
    // Note: in real code, [0..len :0] preserves the sentinel.
    // Detector doesn't currently distinguish this from the bug
    // shape, but my matchSentinelStrip only matches `.. <X> . len`
    // followed by `]` (no `:0`), so this won't fire.
    alloc.free(str.ptr.?[0..str.len :0]);
}
