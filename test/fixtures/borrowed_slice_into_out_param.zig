// borrowed-slice-into-out-param — oven-sh/bun#30151 + #30223 +
// #25563 class.  `defer X.deinit()` + a write into a pointer
// out-param using X → out-param dangles when defer fires.

const std = @import("std");

const ZigString = struct {
    ptr: usize = 0,
    pub fn init(_: anytype) ZigString {
        return .{};
    }
};

const Utf8Buf = struct {
    bytes: []const u8 = "",
    pub fn deinit(_: *Utf8Buf) void {}
};

// Bug — `defer specifier_utf8.deinit()` + `query_string.* =
// ZigString.init(specifier_utf8)` → out-param dangles.
pub fn parseBuggy(query_string: *ZigString) !void {
    var specifier_utf8 = Utf8Buf{};
    defer specifier_utf8.deinit();
    query_string.* = ZigString.init(specifier_utf8);
}

// Control — same defer, but the out-param value is cloned with
// a separate allocator's `dupe`.  Should fire (rule can't tell
// from syntax that this is a clone).  Reviewer triages.
// pub fn parseUnclear(query_string: *ZigString, alloc: std.mem.Allocator) !void {
//     var specifier_utf8 = Utf8Buf{};
//     defer specifier_utf8.deinit();
//     query_string.* = ZigString.init(try alloc.dupe(u8, specifier_utf8.bytes));
// }

// Control — no defer, no fire.
pub fn parseSafe(out: *ZigString, src: []const u8) !void {
    out.* = ZigString.init(src);
}
