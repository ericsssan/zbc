// deinit-order-violates-construction-dep —
// tigerbeetle/tigerbeetle#3732 class.

const std = @import("std");

const Grid = struct {
    pub fn init() Grid {
        return .{};
    }
    pub fn deinit(_: *Grid) void {}
};

const ManifestLog = struct {
    pub fn init(_: *Grid) ManifestLog {
        return .{};
    }
    pub fn deinit(_: *ManifestLog) void {}
};

// Bug — `grid_verify.deinit()` runs BEFORE
// `manifest_log_verify.deinit()` despite manifest_log_verify
// being init'd with `&grid_verify`.
pub fn runBuggy() void {
    var grid_verify = Grid.init();
    var manifest_log_verify = ManifestLog.init(&grid_verify);
    grid_verify.deinit();
    manifest_log_verify.deinit();
}

// Control — LIFO order observed.  Should NOT fire.
pub fn runFixed() void {
    var grid_verify = Grid.init();
    var manifest_log_verify = ManifestLog.init(&grid_verify);
    manifest_log_verify.deinit();
    grid_verify.deinit();
}
