// defer-and-errdefer-free-overlap — ghostty-org/ghostty#8249
// (Atlas.grow).  defer frees OLD; errdefer frees NEW and
// restores OLD into a field; subsequent try → both fire on
// error → field dangles.

const std = @import("std");

const Atlas = struct {
    data: []u8,
    nodes: std.ArrayList(u8),

    // Bug — fires on the errdefer.
    pub fn growBuggy(self: *Atlas, alloc: std.mem.Allocator) !void {
        const data_old = self.data;
        self.data = try alloc.alloc(u8, 64);
        defer alloc.free(data_old);
        errdefer {
            alloc.free(self.data);
            self.data = data_old;
        }
        try self.nodes.append(alloc, 0);
    }

    // Control — free OLD only on success path; errdefer's
    // restore lands on a still-valid pointer.
    pub fn growFixed(self: *Atlas, alloc: std.mem.Allocator) !void {
        const data_old = self.data;
        self.data = try alloc.alloc(u8, 64);
        errdefer {
            alloc.free(self.data);
            self.data = data_old;
        }
        try self.nodes.append(alloc, 0);
        alloc.free(data_old);
    }
};
