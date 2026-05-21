// File-descriptor use-after-close class — `const file = try
// dir.createFile(...);` followed by `file.close()` followed by any
// use of `file` → operations through a dangling fd.  On POSIX the
// closed fd may already point at a different file by the time the
// stale write lands.

const std = @import("std");

// Bug — should fire on `file.writeAll("hi")`.
pub fn buggy(dir: std.fs.Dir) !void {
    const file = try dir.createFile("x", .{});
    file.close();
    try file.writeAll("hi");
}

// Bug — `openFile` variant; field access (`file.handle`) is also
// a use.
pub fn buggyFieldAccess(dir: std.fs.Dir) !void {
    const file = try dir.openFile("x", .{});
    file.close();
    const h = file.handle;
    _ = h;
}

// Control 1 — `defer file.close()` fires at scope exit, AFTER
// every other use.  Should NOT fire.
pub fn okDeferred(dir: std.fs.Dir) !void {
    const file = try dir.createFile("x", .{});
    defer file.close();
    try file.writeAll("hi");
}

// Control 2 — explicit close as the LAST use in scope.  Should NOT
// fire.
pub fn okExplicitLast(dir: std.fs.Dir) !void {
    const file = try dir.createFile("x", .{});
    try file.writeAll("hi");
    file.close();
}

// Control 3 — close inside a catch block that returns; the
// subsequent use is on the success path of the preceding op.
// Should NOT fire.
pub fn okConditional(dir: std.fs.Dir) !void {
    const file = try dir.createFile("x", .{});
    file.writeAll("a") catch {
        file.close();
        return;
    };
    try file.writeAll("b");
}
