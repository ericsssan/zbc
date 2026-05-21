// PR #29910 — bitwise-copy of a heap-owning struct.

const std = @import("std");

const Blob = struct {
    content_type: []const u8 = "",
    content_type_allocated: bool = false,
    name: []const u8 = "",

    // The bug shape: returns `T` by value with a bitwise copy of `*const T`
    // and DOES NOT either reset `content_type_allocated` on the dupe nor
    // re-allocate `content_type`.  Both the source and the dupe will free
    // the same pointer at deinit time.
    pub fn dupeBuggy(this: *const Blob) Blob {
        var duped = this.*;
        return duped;
    }

    // Control 1: correctly clears the flag.  Should NOT fire.
    pub fn dupeFlagCleared(this: *const Blob) Blob {
        var duped = this.*;
        duped.content_type_allocated = false;
        return duped;
    }

    // Control 2: correctly re-allocates the field.  Should NOT fire.
    pub fn dupeReallocated(this: *const Blob, alloc: std.mem.Allocator) Blob {
        var duped = this.*;
        duped.content_type = alloc.dupe(u8, this.content_type) catch unreachable;
        return duped;
    }

    pub fn deinit(this: *Blob) void {
        if (this.content_type_allocated) {
            std.heap.page_allocator.free(this.content_type);
        }
    }
};

// Control 3: a type without flag-paired fields.  Should NOT fire even if
// the dupe is a shallow copy.
const PlainStruct = struct {
    a: u32,
    b: u32,

    pub fn dupe(this: *const PlainStruct) PlainStruct {
        var d = this.*;
        return d;
    }
};
