// publish-then-touch-self — oven-sh/bun#29128 + #31177 + #30185 class.
// After handing `this`/`self` to a concurrent queue / thread pool,
// the consumer thread may free the object before any further
// access from the publisher's side completes.

const std = @import("std");

const TranspilerStore = struct {
    queue: Queue,
    const Queue = struct {
        pub fn push(_: *Queue, _: anytype) void {}
    };
};

const Self = struct {
    vm: usize,
    x: u32,

    // Bug — fires on `this.vm`.
    pub fn dispatchBuggy(this: *Self, store: *TranspilerStore) void {
        store.queue.push(this);
        _ = this.vm;
    }

    // Control — read hoisted into a local BEFORE the publish.
    // Should NOT fire.
    pub fn dispatchFixed(this: *Self, store: *TranspilerStore) void {
        const vm = this.vm;
        _ = vm;
        store.queue.push(this);
    }

    // Bug — `enqueueTaskConcurrent`-style method name signal.
    pub fn workBuggy(self: *Self, loop: anytype) void {
        loop.enqueueTaskConcurrent(self);
        _ = self.x;
    }

    // Control — non-concurrent receiver (`list.append`) and no
    // concurrent method name → no fire.
    pub fn collectOk(self: *Self, list: anytype) void {
        list.append(self);
        _ = self.x;
    }
};
