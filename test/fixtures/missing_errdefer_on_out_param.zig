// missing-errdefer-on-out-param — ghostty-org/ghostty#10401 class.
// `try <out>.<field>.<acquire>(...)` then a later `try` with no
// `errdefer <out>.<field>.deinit(...)` → out-param leaks on
// the later try's error path.

const std = @import("std");

const SharedGrid = struct {
    codepoints: std.AutoHashMap(u32, u32),
    glyphs: std.AutoHashMap(u32, u32),

    // Bug — fires twice (codepoints AND glyphs leak the later try).
    pub fn initBuggy(alloc: std.mem.Allocator) !SharedGrid {
        var result: SharedGrid = .{ .codepoints = .empty, .glyphs = .empty };
        try result.codepoints.ensureTotalCapacity(alloc, 128);
        try result.glyphs.ensureTotalCapacity(alloc, 128);
        try reloadMetrics();
        return result;
    }

    // Control — interleaved errdefers.  Should NOT fire.
    pub fn initFixed(alloc: std.mem.Allocator) !SharedGrid {
        var result: SharedGrid = .{ .codepoints = .empty, .glyphs = .empty };
        try result.codepoints.ensureTotalCapacity(alloc, 128);
        errdefer result.codepoints.deinit(alloc);
        try result.glyphs.ensureTotalCapacity(alloc, 128);
        errdefer result.glyphs.deinit(alloc);
        try reloadMetrics();
        return result;
    }
};

fn reloadMetrics() !void {}
