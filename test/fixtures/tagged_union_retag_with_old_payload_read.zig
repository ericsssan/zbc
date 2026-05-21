// tagged-union retag-with-old-payload-read — tigerbeetle/tigerbeetle
// #3317 / #2200 class.  `<path> = .{ .NewTag = .{ ... <path>.OldTag... } };`
// reads OLD payload while writing NEW tag → undefined on x86_64
// self-hosted backend.

const std = @import("std");

const State = union(enum) {
    loading_index: struct { key_exclusive_next: u32 = 0 },
    iterating: struct { key_exclusive_next: u32, values: u32 },
};

const Self = struct {
    state: State,

    // Bug — fires on `.loading_index` (the OldTag read).
    pub fn advanceBuggy(self: *Self) void {
        self.state = .{
            .iterating = .{
                .key_exclusive_next = self.state.loading_index.key_exclusive_next,
                .values = 0,
            },
        };
    }

    // Control 1 — read hoisted into a local.  Should NOT fire.
    pub fn advanceFixed(self: *Self) void {
        const key = self.state.loading_index.key_exclusive_next;
        self.state = .{ .iterating = .{ .key_exclusive_next = key, .values = 0 } };
    }

    // Control 2 — same-tag retag (read and write same variant).
    // Should NOT fire.
    pub fn bumpInPlace(self: *Self) void {
        self.state = .{ .iterating = .{
            .key_exclusive_next = self.state.iterating.key_exclusive_next,
            .values = self.state.iterating.values + 1,
        } };
    }
};
