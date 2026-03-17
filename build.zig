const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "coquic",
        .target = target,
        .optimize = optimize,
    });
    exe.addCSourceFiles(.{
        .root = b.path("."),
        .files = &.{"src/main.cpp"},
        .flags = &.{"-std=c++20"},
    });
    exe.linkLibCpp();
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    const run_step = b.step("run", "Run the coquic executable");
    run_step.dependOn(&run_exe.step);

    const smoke = b.addExecutable(.{
        .name = "coquic-smoke",
        .target = target,
        .optimize = optimize,
    });
    smoke.addCSourceFiles(.{
        .root = b.path("."),
        .files = &.{"tests/smoke.cpp"},
        .flags = &.{"-std=c++20"},
    });
    smoke.linkLibCpp();

    const smoke_run = b.addRunArtifact(smoke);
    const test_step = b.step("test", "Run the smoke test executable");
    test_step.dependOn(&smoke_run.step);
}
