// PR #29422 — partial-union-write across all 4 site shapes.

const std = @import("std");

// ─── Site 1: `this.* = .{ .tag = try ... }` (Decompressor.zig)

const Reader = struct {
    pub fn deinit(_: *Reader, _: std.mem.Allocator) void {}
};

const Decompressor = union(enum) {
    none,
    zlib: *Reader,

    fn init(this: *Decompressor) !void {
        if (this.* == .none) {
            // BUG: tag is written first; if the try fails, this.* is
            // left as .{ .zlib = <garbage> } and a later deinit
            // dereferences the wild pointer.
            this.* = .{ .zlib = try ZlibInit() };
        }
    }
};

fn ZlibInit() !*Reader {
    return error.Failed;
}

// ─── Site 2: `this.* = .{ .Tag = .{ ... try ... } }` (Body.zig)
//             nested struct literal with the try buried inside.

const ReadableStream = struct {
    fn fromJS(_: usize) !?ReadableStream {
        return error.Failed;
    }
};

const Strong = struct {
    inner: ReadableStream,
    fn init(s: ReadableStream, _: usize) Strong {
        return .{ .inner = s };
    }
};

const Value = union(enum) {
    Empty,
    Locked: struct { readable: Strong, global: usize },

    fn bodify(this: *Value, value: usize, globalThis: usize) !void {
        // BUG: same as site 1 but the try is nested inside an inner
        // struct literal.  Token-scan still catches it.
        this.* = .{
            .Locked = .{
                .readable = Strong.init((try ReadableStream.fromJS(value)).?, globalThis),
                .global = globalThis,
            },
        };
    }
};

// ─── Site 3: `this.field = .{ .tag = ... catch return ... }` (Listener.zig)
//             catch-tail return.

const NamedPipe = struct { handle: usize };

const Listener = struct {
    listener: union(enum) {
        none,
        namedPipe: NamedPipe,
    },

    fn listen(this: *Listener) usize {
        // BUG: this.listener gets tag .namedPipe with stale payload
        // if listenPipe errors.
        this.listener = .{
            .namedPipe = listenPipe() catch return 0,
        };
        return 1;
    }
};

fn listenPipe() !NamedPipe {
    return error.Failed;
}

// ─── Site 4: `obj.field = .{ .tag = ... catch |err| switch ... return ... }` (JSBundler.zig)
//             catch with capture, switch arm returns.

const Msg = struct {
    text: []const u8,
    fn fromJS(_: usize) !Msg {
        return error.Failed;
    }
};

const Resolve = struct {
    value: union(enum) {
        pending,
        err: Msg,
    },

    fn onError(resolve: *Resolve, exception: usize) void {
        // BUG: tag is .err with garbage Msg bytes on the JSError arm.
        resolve.value = .{
            .err = Msg.fromJS(exception) catch |err| switch (err) {
                error.Failed => {
                    return;
                },
            },
        };
    }
};

// ─── Control 1: pure-local var.  NOT dangerous (frame dies on return).

fn localVar() !void {
    var x: Decompressor = .none;
    x = .{ .zlib = try ZlibInit() };
    _ = x;
}

// ─── Control 2: payload is plain, no try/catch-return.  Not dangerous.

fn plainPayload(this: *Decompressor, r: *Reader) void {
    this.* = .{ .zlib = r };
}

// ─── Control 3: catch with value, no return / unreachable.
//                Should NOT fire (catch produces a fallback value).

fn defaultReader() *Reader {
    return undefined;
}

fn catchValue(this: *Decompressor) void {
    this.* = .{ .zlib = ZlibInit() catch defaultReader() };
}
