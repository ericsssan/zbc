// missing-deinit-on-composed-owner — ziglang/zig#22683 class.
// Outer's `deinit` forgets to call `<self>.<field>.deinit()` for
// a field whose type has a deinit → inner non-memory resources
// (file handles, sockets, refs, mmaps) leak.

const std = @import("std");

const MemoryAccessor = struct {
    fd: i32 = -1,

    pub fn deinit(self: *MemoryAccessor) void {
        // Closes /proc/self/mem in real implementation.
        self.fd = -1;
    }
};

// Bug — fires on field `ma`.  StackIteratorBuggy.deinit doesn't
// call `it.ma.deinit()`.
pub const StackIteratorBuggy = struct {
    ma: MemoryAccessor,
    fp: usize,

    pub fn deinit(it: *StackIteratorBuggy) void {
        _ = it;
    }
};

// Control — outer deinit calls inner deinit.  Should NOT fire.
pub const StackIteratorFixed = struct {
    ma: MemoryAccessor,
    fp: usize,

    pub fn deinit(it: *StackIteratorFixed) void {
        it.ma.deinit();
    }
};

// Control — field type has no deinit.  Should NOT fire.
const PlainCounter = struct {
    count: u32,
};

pub const HasPlainField = struct {
    counter: PlainCounter,

    pub fn deinit(self: *HasPlainField) void {
        _ = self;
    }
};
