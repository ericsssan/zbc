//! zbc build — exposes the library module + builds the CLI exe.
//!
//! Consumers add zbc as a path dependency in their build.zig.zon
//! and then in their build.zig:
//!
//!     const zbc_dep = b.dependency("zbc", .{
//!         .target = target,
//!         .optimize = optimize,
//!     });
//!     exe.root_module.addImport("zbc", zbc_dep.module("zbc"));
//!
//! Then in their Zig code:
//!
//!     const zbc = @import("zbc");
//!     const problems = try zbc.analyzeEscape(gpa, io, path, &cache, &zbc.DefaultConfig);

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Public library module ───────────────────────────────
    // Importable by downstream consumers as `@import("zbc")`.
    const lib_mod = b.addModule("zbc", .{
        .root_source_file = b.path("lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── CLI executable ──────────────────────────────────────
    // Standalone binary; useful for one-off sweeps without
    // integrating into a host build.zig.
    const exe = b.addExecutable(.{
        .name = "zbc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zbc CLI");
    run_step.dependOn(&run_cmd.step);

    // ── Tests ───────────────────────────────────────────────
    const tests = b.addTest(.{ .root_module = lib_mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run zbc tests");
    test_step.dependOn(&run_tests.step);
}
