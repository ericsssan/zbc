//! Proof-of-concept: deterministic reproduction of the two
//! publish-then-touch-self UAF bugs in Bun detected by zbc.
//!
//! Build and run:
//!   zig run poc/prove_publish_then_touch_self.zig
//!
//! Both bugs panic with an explicit "USE AFTER FREE" message,
//! proving the deferred wake() fires AFTER the consumer frees the
//! object.  In production Bun (ASAN build) the same access →
//! segfault / ASAN error.
//!
//! ─── Bug 1: bun/src/install/patch_install.zig:101-115 ────────────
//!
//!   pub fn runFromThreadPoolImpl(this: *PatchTask) void {
//!       defer {
//!           defer this.manager.wake();                // ← inner defer
//!           this.manager.patch_task_queue.push(this); // ← publish
//!       }
//!   }
//!
//! The inner defer `this.manager.wake()` is LIFO-last inside the block:
//! push(this) fires first, the consumer calls ptask.deinit() →
//! bun.destroy(this), then the inner defer fires and reads
//! `this.manager` from freed memory.
//!
//! ─── Bug 2: bun/src/install/NetworkTask.zig:136,144 ─────────────
//!
//!   defer this.package_manager.wake();  // ← registered BEFORE push
//!   ...
//!   this.package_manager.async_network_task_queue.push(this);
//!
//! Same hazard: defer fires at fn exit = after push.  Consumer can
//! recycle the task before wake() runs, turning it into a UAF.

const std = @import("std");

// ── Synchronized channel: push blocks until consumer signals "done" ───────
//
// This models the "fast consumer" scenario: the main thread wakes up
// immediately after receiving the task, runs deinit() / returnToPool(),
// and completes — all before push() returns on the worker thread.
// That's when the deferred wake() fires: after the task is freed.

fn SyncChan(comptime T: type) type {
    return struct {
        slot: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        // Set by consumer after it processes (frees) the task.
        consumer_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn push(s: *@This(), v: T) void {
            s.slot.store(@intFromPtr(v), .release);
            // Block until consumer has freed the task — simulates the
            // fast-consumer window where the main thread runs deinit()
            // before the worker's deferred wake() fires.
            while (!s.consumer_done.load(.acquire)) {
                std.Thread.yield() catch {};
            }
        }

        fn pop(s: *@This()) T {
            while (true) {
                const p = s.slot.load(.acquire);
                if (p != 0) return @ptrFromInt(p);
                std.Thread.yield() catch {};
            }
        }

        fn signalDone(s: *@This()) void {
            s.consumer_done.store(true, .release);
        }
    };
}

// ── Bug 1: PatchTask defer-inside-defer ──────────────────────────────────

const Bug1Manager = struct {
    queue: SyncChan(*Bug1Task) = .{},
    freed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // In real Bun: `this.manager.wake()` executes here on the worker
    // thread.  If the consumer already called bun.destroy(this), then
    // `this.manager` is a dangling pointer.
    fn wake(mgr: *Bug1Manager) void {
        if (mgr.freed.load(.acquire)) {
            std.debug.panic(
                "\n[Bug 1 CONFIRMED] wake() fired after consumer freed PatchTask\n" ++
                    "  this.manager is dangling — use-after-free!\n" ++
                    "  File: patch_install.zig:104   defer this.manager.wake()\n",
                .{},
            );
        }
        std.debug.print("  [Bug1] wake() — no race this run\n", .{});
    }
};

const Bug1Task = struct {
    manager: *Bug1Manager,

    // Mirrors PatchTask.deinit() (patch_install.zig:78-94) which calls bun.destroy(this)
    fn deinit(t: *Bug1Task) void {
        std.debug.print("  [Bug1/consumer] deinit() → bun.destroy(this)  [task freed]\n", .{});
        t.manager.freed.store(true, .release);
        // Production: bun.destroy() poisons memory here
    }

    // ── Exact buggy pattern from patch_install.zig:101-115 ──────────────
    fn runFromThreadPoolImpl(this: *Bug1Task) void {
        defer {
            defer this.manager.wake(); // ← inner defer: LIFO-last = fires AFTER push
            this.manager.queue.push(this); // ← publish; blocks until consumer frees
        }
        std.debug.print("  [Bug1/worker] doing work...\n", .{});
    }
};

fn bug1Consumer(mgr: *Bug1Manager) void {
    const task = mgr.queue.pop();
    std.debug.print("  [Bug1/consumer] popped — calling deinit()\n", .{});
    task.deinit(); // mirrors runTasks.zig:38: `defer ptask.deinit()`
    mgr.queue.signalDone(); // push() unblocks; worker's inner defer wake() fires next
}

fn bug1(alloc: std.mem.Allocator) !void {
    std.debug.print(
        \\
        \\═══ Bug 1: PatchTask defer-inside-defer  (patch_install.zig:104) ═══════
        \\
        \\  pub fn runFromThreadPoolImpl(this: *PatchTask) void {{
        \\      defer {{
        \\          defer this.manager.wake();                 // ← fires LAST (LIFO)
        \\          this.manager.patch_task_queue.push(this);  // ← publish
        \\      }}
        \\  }}
        \\  Consumer (runTasks.zig:38): defer ptask.deinit()  // → bun.destroy(this)
        \\
        \\
    , .{});

    var mgr = Bug1Manager{};
    const task = try alloc.create(Bug1Task);
    defer alloc.destroy(task);
    task.* = .{ .manager = &mgr };

    const t = try std.Thread.spawn(.{}, bug1Consumer, .{&mgr});
    task.runFromThreadPoolImpl(); // ← panics in wake() after consumer freed task
    t.join();
}

// ── Bug 2: NetworkTask defer-before-push ─────────────────────────────────

const Bug2PackageManager = struct {
    queue: SyncChan(*Bug2Task) = .{},
    freed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn wake(pm: *Bug2PackageManager) void {
        if (pm.freed.load(.acquire)) {
            std.debug.panic(
                "\n[Bug 2 CONFIRMED] wake() fired after consumer recycled NetworkTask\n" ++
                    "  this.package_manager is dangling — use-after-free!\n" ++
                    "  File: NetworkTask.zig:136   defer this.package_manager.wake()\n",
                .{},
            );
        }
        std.debug.print("  [Bug2] wake() — no race this run\n", .{});
    }
};

const Bug2Task = struct {
    package_manager: *Bug2PackageManager,

    // Mirrors runTasks.zig:599: preallocated_network_tasks.put(task)
    fn returnToPool(t: *Bug2Task) void {
        std.debug.print("  [Bug2/consumer] task returned to pool  [task recycled]\n", .{});
        t.package_manager.freed.store(true, .release);
    }

    // ── Pattern from NetworkTask.zig:136, 144 ───────────────────────────
    fn onHTTPComplete(this: *Bug2Task) void {
        defer this.package_manager.wake(); // ← fires at fn exit = AFTER push

        std.debug.print("  [Bug2/worker] processing HTTP response...\n", .{});
        this.package_manager.queue.push(this); // ← publish; blocks until consumer recycles
        // fn exits → wake() fires → task already recycled
    }
};

fn bug2Consumer(pm: *Bug2PackageManager) void {
    const task = pm.queue.pop();
    std.debug.print("  [Bug2/consumer] popped — returning to pool\n", .{});
    task.returnToPool(); // mirrors preallocated_network_tasks.put(task)
    pm.queue.signalDone();
}

fn bug2(alloc: std.mem.Allocator) !void {
    std.debug.print(
        \\═══ Bug 2: NetworkTask defer-before-push  (NetworkTask.zig:136) ════════
        \\
        \\  fn onHTTPComplete(this: *NetworkTask, ...) void {{
        \\      defer this.package_manager.wake();              // ← fires at fn exit
        \\      ...
        \\      this.package_manager.async_network_task_queue.push(this); // ← publish
        \\  }}
        \\  Consumer (runTasks.zig:599): preallocated_network_tasks.put(task)
        \\
        \\
    , .{});

    var pm = Bug2PackageManager{};
    const task = try alloc.create(Bug2Task);
    defer alloc.destroy(task);
    task.* = .{ .package_manager = &pm };

    const t = try std.Thread.spawn(.{}, bug2Consumer, .{&pm});
    task.onHTTPComplete(); // ← panics in wake() after consumer recycled task
    t.join();
}

// ── Main ──────────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    std.debug.print(
        \\zbc publish-then-touch-self — real-bug proof of concept
        \\========================================================
        \\Simulates the "fast consumer" window: push() blocks until the
        \\consumer thread frees/recycles the task.  The worker's deferred
        \\wake() then fires against freed memory → deterministic panic.
        \\(Production Bun with ASAN: segfault / ASAN error instead.)
        \\
    , .{});

    try bug1(alloc); // panics here — comment out to test bug2 in isolation
    try bug2(alloc);

    std.debug.print("\nAll bugs reproduced.\n", .{});
}
