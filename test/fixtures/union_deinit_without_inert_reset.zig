// union-deinit-without-inert-reset — ghostty osc.zig class.
// A switch arm in a reset/clear/end-style fn deinit's a union
// payload but doesn't retag the union to an inert variant.  The
// next call to the same fn re-fires the arm and double-frees.

const std = @import("std");

const List = struct { pub fn deinit(_: *List) void {} };

const Command = union(enum) {
    kitty_color_protocol: struct { list: List },
    hyperlink_end: void,
    none: void,
};

const Parser = struct {
    command: Command = .{ .none = {} },

    // Bug — fires on `.kitty_color_protocol`.
    pub fn endBuggy(self: *Parser) void {
        switch (self.command) {
            .kitty_color_protocol => |*v| {
                v.list.deinit();
            },
            else => {},
        }
    }

    // Control 1 — with retag.  Should NOT fire.
    pub fn endFixed(self: *Parser) void {
        switch (self.command) {
            .kitty_color_protocol => |*v| {
                v.list.deinit();
                self.command = .{ .hyperlink_end = {} };
            },
            else => {},
        }
    }

    // Control 2 — `deinit` is single-shot, missing retag is fine.
    pub fn deinit(self: *Parser) void {
        switch (self.command) {
            .kitty_color_protocol => |*v| v.list.deinit(),
            else => {},
        }
    }

    // Control 3 — arm without capture; rule doesn't know what to
    // scan, skips.
    pub fn resetNoCapture(self: *Parser) void {
        switch (self.command) {
            .kitty_color_protocol => doStuff(),
            else => {},
        }
    }
};

fn doStuff() void {}
