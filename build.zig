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

    // ── Type engine module ──────────────────────────────────
    // Extracted ZLS type-resolution machinery, optimised for
    // repo-wide batch analysis.  No LSP server, no incremental
    // update protocol — just the type-resolution core.
    const engine_mod = b.addModule("type_engine", .{
        .root_source_file = b.path("src/type_engine/engine.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── Public library module ───────────────────────────────
    // Importable by downstream consumers as `@import("zbc")`.
    const lib_mod = b.addModule("zbc", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("type_engine", engine_mod);

    // ── CLI executable ──────────────────────────────────────
    // Standalone binary; useful for one-off sweeps without
    // integrating into a host build.zig.
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("type_engine", engine_mod);
    const exe = b.addExecutable(.{
        .name = "zbc",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run zbc CLI");
    run_step.dependOn(&run_cmd.step);

    // ── Tests ───────────────────────────────────────────────
    const test_step = b.step("test", "Run zbc tests");

    // Library tests (lib.zig refAllDecls every submodule).
    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);

    // CLI tests (argparse + invariant-list parsing).
    const cli_test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_test_mod.addImport("type_engine", engine_mod);
    const cli_tests = b.addTest(.{ .root_module = cli_test_mod });
    test_step.dependOn(&b.addRunArtifact(cli_tests).step);

    // Fuzz tests — run once in normal test mode (seed replay); run
    // continuously under libfuzzer with `zig build fuzz`.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz_check.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_mod.addImport("type_engine", engine_mod);
    // Import the library's sub-modules that fuzz_check.zig references
    // directly (cfg_builder, worklist, rule_catalog, etc.).  Resolved
    // through the library module's own import graph.
    const fuzz_tests = b.addTest(.{ .root_module = fuzz_mod });
    test_step.dependOn(&b.addRunArtifact(fuzz_tests).step);

    // `zig build fuzz` — compile fuzz_check with coverage instrumentation.
    // Produces an instrumented test binary at zig-out/bin/fuzz-zbc that
    // is driven by Zig's built-in fuzzer UI server.
    //
    // Usage (Zig 0.17+):
    //   zig build fuzz           # builds the instrumented binary
    //   zig test --fuzz src/fuzz_check.zig   # run under the fuzzer UI
    //
    // Note: the instrumented binary requires a running Zig fuzzer UI
    // process to coordinate corpus mutation; running it standalone
    // crashes in the IPC layer (known Zig 0.17-dev limitation).
    const fuzz_step = b.step("fuzz", "Compile fuzz target with coverage instrumentation");
    const fuzz_instrumented_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz_check.zig"),
        .target = target,
        .optimize = .Debug,
        .fuzz = true,
    });
    fuzz_instrumented_mod.addImport("type_engine", engine_mod);
    const fuzz_instrumented = b.addTest(.{
        .name = "fuzz-zbc",
        .root_module = fuzz_instrumented_mod,
    });
    // Install the binary so it can be invoked by the fuzzer UI.
    b.installArtifact(fuzz_instrumented);
    fuzz_step.dependOn(&b.addInstallArtifact(fuzz_instrumented, .{}).step);
}
