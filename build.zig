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

    // ── ZLS dependency ──────────────────────────────────────
    // Powers cross-module type resolution in zls_resolver.zig.
    // ZLS targets Zig master; the version in build.zig.zon is
    // pinned by hash.
    const zls_dep = b.dependency("zls", .{
        .target = target,
        .optimize = optimize,
    });
    const zls_mod = zls_dep.module("zls");

    // ── Public library module ───────────────────────────────
    // Importable by downstream consumers as `@import("zbc")`.
    const lib_mod = b.addModule("zbc", .{
        .root_source_file = b.path("lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("zls", zls_mod);

    // ── CLI executable ──────────────────────────────────────
    // Standalone binary; useful for one-off sweeps without
    // integrating into a host build.zig.
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("zls", zls_mod);
    const exe = b.addExecutable(.{
        .name = "zbc",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zbc CLI");
    run_step.dependOn(&run_cmd.step);

    // ── Tests ───────────────────────────────────────────────
    const test_step = b.step("test", "Run zbc tests");

    // Library tests (lib.zig refAllDecls every submodule).
    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);

    // CLI tests (argparse + invariant-list parsing).
    const cli_test_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_test_mod.addImport("zls", zls_mod);
    const cli_tests = b.addTest(.{ .root_module = cli_test_mod });
    test_step.dependOn(&b.addRunArtifact(cli_tests).step);
}
