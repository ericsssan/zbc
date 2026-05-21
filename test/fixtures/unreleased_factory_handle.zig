// unreleased-factory-handle — hexops/mach example class.
// `const X = device.create*()` returns a refcounted handle with
// initial refcount=1.  If neither defer-release nor ownership
// transfer (return / struct-field store) happens, the ref leaks.

const Layout = struct {
    pub fn release(_: *Layout) void {}
};

const Device = struct {
    pub fn createPipelineLayout(_: *Device, _: anytype) *Layout {
        return undefined;
    }
};

// Bug — fires on `layout` (no defer release, no escape).
pub fn buildBuggy(device: *Device, desc: anytype) void {
    const layout = device.createPipelineLayout(desc);
    _ = layout;
}

// Control 1 — defer-release.  Should NOT fire.
pub fn buildFixed(device: *Device, desc: anytype) void {
    const layout = device.createPipelineLayout(desc);
    defer layout.release();
    _ = layout;
}

// Control 2 — returned.  Should NOT fire.
pub fn buildReturned(device: *Device, desc: anytype) *Layout {
    const layout = device.createPipelineLayout(desc);
    return layout;
}

// Control 3 — stored as struct field.  Should NOT fire.
const Renderer = struct {
    pipeline_layout: *Layout,
    pub fn setup(self: *Renderer, device: *Device, desc: anytype) void {
        const layout = device.createPipelineLayout(desc);
        self.pipeline_layout = layout;
    }
};
