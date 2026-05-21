// hexops/mach sysgpu/vulkan.zig PipelineLayout.init class — a loop
// body acquires refcounted references via `<obj>.<addref>()` and a
// later `try` runs with no `errdefer` containing a release-class
// cleanup.  On the try's error path every reference leaks.

const std = @import("std");

const BindGroupLayout = struct {
    manager: Manager = .{},
    vk_layout: u32 = 0,
    pub const Manager = struct {
        pub fn reference(_: *Manager) void {}
        pub fn release(_: *Manager) void {}
    };
};

const PipelineLayout = struct {
    group_layouts: []*BindGroupLayout,
};

const Descriptor = struct {
    bind_group_layouts: ?[*]*BindGroupLayout,
    bind_group_layout_count: usize,
};

fn createPipelineLayoutFallible() !u32 {
    return 0;
}

// Bug — should fire on `.reference()` call inside the loop.
pub fn initBuggy(allocator: std.mem.Allocator, desc: *const Descriptor) !*PipelineLayout {
    var group_layouts = try allocator.alloc(*BindGroupLayout, desc.bind_group_layout_count);
    errdefer allocator.free(group_layouts);

    for (0..desc.bind_group_layout_count) |i| {
        const layout: *BindGroupLayout = desc.bind_group_layouts.?[i];
        layout.manager.reference();
        group_layouts[i] = layout;
    }

    const vk_layout = try createPipelineLayoutFallible();
    _ = vk_layout;
    const out = try allocator.create(PipelineLayout);
    out.* = .{ .group_layouts = group_layouts };
    return out;
}

// Control 1 — `errdefer …release()` registered.  Should NOT fire.
pub fn initFixed(allocator: std.mem.Allocator, desc: *const Descriptor) !*PipelineLayout {
    var group_layouts = try allocator.alloc(*BindGroupLayout, desc.bind_group_layout_count);
    errdefer allocator.free(group_layouts);

    var taken: usize = 0;
    errdefer for (group_layouts[0..taken]) |l| l.manager.release();

    for (0..desc.bind_group_layout_count) |i| {
        const layout: *BindGroupLayout = desc.bind_group_layouts.?[i];
        layout.manager.reference();
        group_layouts[i] = layout;
        taken += 1;
    }

    const vk_layout = try createPipelineLayoutFallible();
    _ = vk_layout;
    const out = try allocator.create(PipelineLayout);
    out.* = .{ .group_layouts = group_layouts };
    return out;
}

// Control 2 — no `try` after the loop.  Should NOT fire (no error
// path that would leak the refs).
pub fn initNoTry(allocator: std.mem.Allocator, desc: *const Descriptor) !void {
    _ = allocator;
    for (0..desc.bind_group_layout_count) |i| {
        const layout: *BindGroupLayout = desc.bind_group_layouts.?[i];
        layout.manager.reference();
    }
}

// Control 3 — fn doesn't return an error union (no `try` at all).
// Should NOT fire.
pub fn initInfallible(desc: *const Descriptor) void {
    for (0..desc.bind_group_layout_count) |i| {
        const layout: *BindGroupLayout = desc.bind_group_layouts.?[i];
        layout.manager.reference();
    }
}
