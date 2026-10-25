//! Reconciliation of zbc's two check classes.
//!
//! Class 1 (`flow/invariants.zig`): 10 invariants decided by the
//! per-fn CFG + abstract-interpretation worklist, gated inside
//! `cfg_transfer.zig`.
//! Class 2 (`detectors.zig`): whole-file walks with no flow state.
//!
//! Both are toggled through `config.Invariant`, and both are documented
//! in `rule_catalog.zig`.  The tests below assert the three lists agree,
//! so a rule added to one place and forgotten in another fails the
//! build instead of silently becoming undiscoverable — which is exactly
//! how 13 detectors ended up firing ids that `--explain` could not
//! resolve.

const std = @import("std");

const config = @import("config.zig");
const detectors_mod = @import("detectors.zig");
const flow_mod = @import("flow/invariants.zig");
const catalog = @import("rule_catalog.zig");

pub const Class = enum { flow, detector };

/// `Invariant` tags are `snake_case`; rule ids are their kebab-case form.
/// Writing into `buf` keeps this allocation-free; 64 bytes covers any tag.
pub fn kebab(buf: *[64]u8, tag: []const u8) []const u8 {
    std.debug.assert(tag.len <= buf.len);
    for (tag, 0..) |c, i| buf[i] = if (c == '_') '-' else c;
    return buf[0..tag.len];
}

pub fn detectorCount(inv: config.Invariant) usize {
    var buf: [64]u8 = undefined;
    const id = kebab(&buf, @tagName(inv));
    var n: usize = 0;
    for (detectors_mod.detectors) |d| {
        if (std.mem.eql(u8, d.id, id)) n += 1;
    }
    return n;
}

/// Which class owns `id`, or null when no invariant maps to it.
pub fn classOfRuleId(id: []const u8) ?Class {
    if (catalog.lookup(id) == null) return null;
    for (detectors_mod.detectors) |d| {
        if (std.mem.eql(u8, d.id, id)) return .detector;
    }
    var buf: [64]u8 = undefined;
    for (flow_mod.flow_invariants) |inv| {
        if (std.mem.eql(u8, kebab(&buf, @tagName(inv)), id)) return .flow;
    }
    return null;
}

test "classes: every invariant belongs to exactly one class" {
    var flow: usize = 0;
    var det: usize = 0;
    for (config.all_invariants) |inv| {
        const is_flow = flow_mod.isFlowInvariant(inv);
        const n = detectorCount(inv);
        try std.testing.expect(n <= 1);
        // Exactly one owner: XOR.
        try std.testing.expect(is_flow != (n == 1));
        if (is_flow) flow += 1 else det += 1;
    }
    try std.testing.expectEqual(flow_mod.flow_invariants.len, flow);
    try std.testing.expectEqual(detectors_mod.detectors.len, det);
}

test "classes: detector ids are the kebab-case form of their invariant tag" {
    for (detectors_mod.detectors) |d| {
        var found = false;
        var buf: [64]u8 = undefined;
        for (config.all_invariants) |inv| {
            if (std.mem.eql(u8, kebab(&buf, @tagName(inv)), d.id)) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "classes: every invariant is documented in the catalog" {
    var buf: [64]u8 = undefined;
    for (config.all_invariants) |inv| {
        const id = kebab(&buf, @tagName(inv));
        try std.testing.expect(catalog.lookup(id) != null);
    }
}

test "classes: every catalog entry names a real invariant" {
    var buf: [64]u8 = undefined;
    outer: for (catalog.all) |r| {
        for (config.all_invariants) |inv| {
            if (std.mem.eql(u8, kebab(&buf, @tagName(inv)), r.id)) continue :outer;
        }
        std.debug.print("catalog id `{s}` has no Invariant tag\n", .{r.id});
        try std.testing.expect(false);
    }
}
