// reset-skips-pooled-resource-release —
// tigerbeetle/tigerbeetle#3436 + #1734 class.
// `deinit` releases pool/handle resources; sibling `reset` doesn't.

const std = @import("std");

const NodePool = struct {
    pub fn acquire(_: *NodePool) *u8 {
        return undefined;
    }
    pub fn release(_: *NodePool, _: anytype) void {}
};

// Bug — fires on `reset` because (a) `deinit` calls
// `node_pool.release(...)` per node, (b) the `grow` method
// re-acquires via `node_pool.acquire()` (so resources are
// per-cycle, not pool-lifetime), and (c) `reset` doesn't
// release them.
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

    pub fn grow(self: *SegmentedArrayBuggy, node_pool: *NodePool) void {
        self.nodes[self.node_count] = node_pool.acquire();
        self.node_count += 1;
    }
};

// Control 1 — `reset` mirrors the cleanup.  Should NOT fire.
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

    pub fn grow(self: *SegmentedArrayFixed, node_pool: *NodePool) void {
        self.nodes[self.node_count] = node_pool.acquire();
        self.node_count += 1;
    }
};

// Control 2 — pool-lifetime asymmetry: `init` acquires once,
// `deinit` releases once, `reset` keeps state.  No other method
// re-acquires.  Should NOT fire (cross-fn analysis confirms the
// resource is pool-lifetime).
const Grid = struct {
    pub fn block_unref(_: *Grid, _: anytype) void {}
};
const ScanBuffer = struct {
    index_block: u32,
    pub fn init(self: *ScanBuffer, _: *Grid) void {
        self.* = .{ .index_block = 0 };
    }
    pub fn deinit(self: *ScanBuffer, grid: *Grid) void {
        grid.block_unref(self.index_block);
    }
};
pub const ScanBufferPool = struct {
    scan_buffers: [4]ScanBuffer,
    scan_buffer_used: u8,

    pub fn init(self: *ScanBufferPool, grid: *Grid) void {
        self.scan_buffer_used = 0;
        for (&self.scan_buffers) |*sb| sb.init(grid);
    }

    pub fn deinit(self: *ScanBufferPool, grid: *Grid) void {
        for (&self.scan_buffers) |*sb| sb.deinit(grid);
    }

    pub fn reset(self: *ScanBufferPool) void {
        self.scan_buffer_used = 0;
    }

    pub fn acquire(self: *ScanBufferPool) *ScanBuffer {
        const r = &self.scan_buffers[self.scan_buffer_used];
        self.scan_buffer_used += 1;
        return r;
    }
};
