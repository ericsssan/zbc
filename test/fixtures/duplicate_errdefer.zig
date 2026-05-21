// tigerbeetle/tigerbeetle#2700 — two `errdefer X.deinit();`
// for the same X in one fn body — both fire on the error path,
// running the cleanup twice → double-free / assert.

const std = @import("std");

const IO = struct {
    pub fn init(_: u32, _: u32) !IO {
        return .{};
    }
    pub fn deinit(_: *IO) void {}
};

const Command = struct {
    io: IO = .{},

    // Bug — should fire on the second `errdefer command.io.deinit();`.
    pub fn initBuggy(command: *Command) !void {
        command.io = try IO.init(128, 0);
        errdefer command.io.deinit();

        // …other init steps that fit between the duplicates…

        command.io = try IO.init(128, 0); // copy-paste leftover
        errdefer command.io.deinit(); // duplicate registration
    }

    // Control 1 — single registration is OK.
    pub fn initFixed(command: *Command) !void {
        command.io = try IO.init(128, 0);
        errdefer command.io.deinit();
        // …other init steps…
    }
};

const Multi = struct {
    a: IO = .{},
    b: IO = .{},

    // Control 2 — different receivers, same method.  Should NOT fire.
    pub fn init(this: *Multi) !void {
        this.a = try IO.init(0, 0);
        errdefer this.a.deinit();
        this.b = try IO.init(0, 0);
        errdefer this.b.deinit();
    }
};

// Control 3 — same receiver, same method, DIFFERENT args.  Should
// NOT fire (these are different cleanups).
pub fn freeArgsControl(allocator: std.mem.Allocator) !void {
    const a = try allocator.alloc(u8, 10);
    errdefer allocator.free(a);
    const b = try allocator.alloc(u8, 20);
    errdefer allocator.free(b);
    _ = a;
    _ = b;
}
