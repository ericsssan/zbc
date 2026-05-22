// borrowed-slice-into-stack-buffer-returned — ziglang/zig#25713
// class.  Parser populates result with slices INTO a stack
// buffer; returning the result leaves caller with dangling
// sub-slices.

const std = @import("std");

const SemanticVersion = struct {
    major: u32 = 0,
    minor: u32 = 0,
    patch: u32 = 0,
    pre: ?[]const u8 = null,
    build: ?[]const u8 = null,

    pub fn parse(_: []const u8) SemanticVersion {
        return .{};
    }
};

// Bug — fires on the `return ver`.
pub fn detectBuggy() SemanticVersion {
    var buf: [64]u8 = undefined;
    const ver = SemanticVersion.parse(&buf);
    return ver;
}

// Control — strip aliased fields before return.  Should NOT fire
// (the return mentions `stripped`, not `ver`).
pub fn detectFixed() SemanticVersion {
    var buf: [64]u8 = undefined;
    const ver = SemanticVersion.parse(&buf);
    var stripped = ver;
    stripped.pre = null;
    stripped.build = null;
    return stripped;
}
