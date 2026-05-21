// return-borrowed-payload — ghostty-org/ghostty#8358 + #7711 class.
// Sibling-arm asymmetry: one arm clones / allocates, another returns
// bare — the bare arm's value is borrowed from caller's input.

const std = @import("std");

const Command = union(enum) {
    direct: []const u8,
    shell: []const u8,
};

// Bug — `.direct => |v| v` returns a slice borrowed from `command`
// while `.shell => |v| try alloc.dupe(...)` clones.  Sibling-arm
// asymmetry triggers the rule.
pub fn extractBuggy(command: Command, alloc: std.mem.Allocator) ![]const u8 {
    return switch (command) {
        .direct => |v| v,
        .shell => |v| try alloc.dupe(u8, v),
    };
}

// Control — both arms clone.  Should NOT fire.
pub fn extractFixed(command: Command, alloc: std.mem.Allocator) ![]const u8 {
    return switch (command) {
        .direct => |v| try alloc.dupe(u8, v),
        .shell => |v| try alloc.dupe(u8, v),
    };
}

// Control — both arms bare (no clone signal).  Rule needs sibling
// asymmetry to fire, so no fire here.
pub fn extractBoth(command: Command) []const u8 {
    return switch (command) {
        .direct => |v| v,
        .shell => |v| v,
    };
}
