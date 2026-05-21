// Arena-into-heap class — a slice allocated through a function-
// local arena is stored into a container whose allocator is NOT
// the arena.  When the arena dies at scope exit, the container
// holds a dangling slice.  Third escape path complementing
// `arena-escape` (return) and `arena-use-after-kill` (post-deinit
// read).

const std = @import("std");

const Parser = struct {
    gpa: std.mem.Allocator,
    token_cache: std.ArrayList([]const u8),

    // Bug — should fire on `tokens` arg of `appendSlice`.
    pub fn buggy(self: *Parser, input: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const arena_alloc = arena.allocator();
        const tokens = try arena_alloc.alloc([]const u8, input.len);
        try self.token_cache.appendSlice(self.gpa, tokens);
    }

    // Bug — `dupe` through arena handle, stored into heap container.
    pub fn buggyDupe(self: *Parser, input: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const dup = try a.dupe(u8, input);
        try self.token_cache.append(self.gpa, dup);
    }

    // Bug — inline `arena.allocator()` form.
    pub fn buggyInline(self: *Parser, input: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const tokens = try arena.allocator().alloc([]const u8, input.len);
        try self.token_cache.appendSlice(self.gpa, tokens);
    }

    // Control — destination uses the SAME arena allocator.  Should
    // NOT fire: the sub-container lives in the arena and gets torn
    // down with it.
    pub fn okSubContainer(self: *Parser, input: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const arena_alloc = arena.allocator();
        const tokens = try arena_alloc.alloc([]const u8, input.len);
        var local_cache = std.ArrayList([]const u8).empty;
        try local_cache.appendSlice(arena_alloc, tokens);
    }

    // Control — no arena in the fn.  Should NOT fire.
    pub fn okNoArena(self: *Parser, input: []const u8) !void {
        const tokens = try self.gpa.alloc([]const u8, input.len);
        try self.token_cache.appendSlice(self.gpa, tokens);
    }
};
