// reset-skips-pooled-resource-release —
// tigerbeetle/tigerbeetle#3436 + #1734 class.
// `deinit` releases pool/handle resources; sibling `reset` doesn't.

const std = @import("std");

const NodePool = struct {
    pub fn release(_: *NodePool, _: anytype) void {}
};

// Bug — fires on `reset` because `deinit` calls
// `node_pool.release(...)` and `alloc.free(...)`, but `reset`
// calls neither.
pub const SegmentedArrayBuggy = struct {
    nodes: []*u8,
    node_count: usize,

    pub fn deinit(self: *SegmentedArrayBuggy, alloc: std.mem.Allocator, node_pool: *NodePool) void {
        for (self.nodes[0..self.node_count]) |node| node_pool.release(node);
        alloc.free(self.nodes);
    }

    pub fn reset(self: *SegmentedArrayBuggy) void {
        self.node_count = 0;
    }
};

// Control — `reset` mirrors the cleanup.  Should NOT fire.
pub const SegmentedArrayFixed = struct {
    nodes: []*u8,
    node_count: usize,

    pub fn deinit(self: *SegmentedArrayFixed, alloc: std.mem.Allocator, node_pool: *NodePool) void {
        for (self.nodes[0..self.node_count]) |node| node_pool.release(node);
        alloc.free(self.nodes);
    }

    pub fn reset(self: *SegmentedArrayFixed, node_pool: *NodePool) void {
        for (self.nodes[0..self.node_count]) |node| node_pool.release(node);
        self.node_count = 0;
    }
};
