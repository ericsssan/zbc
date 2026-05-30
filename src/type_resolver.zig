//! Bridge between zbc and the type engine.
//! Re-exports TypeContext + TypeResolver for use by lib.zig / main.zig.

const engine = @import("type_engine");

pub const TypeContext = engine.TypeContext;
pub const TypeResolver = engine.TypeResolver;
pub const clearToolchainCacheForTesting = engine.clearToolchainCacheForTesting;

/// Call once on the main thread before spawning any worker threads.
/// Populates the process-global toolchain cache so workers never race on it.
pub fn warmToolchain(gpa: std.mem.Allocator, io: std.Io) void {
    _ = engine.discoverToolchain(io, gpa);
}

const std = @import("std");
