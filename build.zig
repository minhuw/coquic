const std = @import("std");

fn requireEnv(b: *std.Build, name: []const u8) []const u8 {
    return b.graph.env_map.get(name) orelse std.debug.panic(
        "missing required environment variable {s}; run inside `nix develop`",
        .{name},
    );
}

fn withExtraFlags(
    b: *std.Build,
    base: []const []const u8,
    extra: []const []const u8,
) []const []const u8 {
    var flags = std.ArrayList([]const u8).init(b.allocator);
    flags.appendSlice(base) catch @panic("failed to append base flags");
    flags.appendSlice(extra) catch @panic("failed to append extra flags");
    return flags.toOwnedSlice() catch @panic("failed to allocate flags");
}

fn appendTlsAdapterSource(files: *std.ArrayList([]const u8), tls_backend: []const u8) void {
    if (std.mem.eql(u8, tls_backend, "quictls")) {
        files.append("src/quic/tls_adapter_quictls.cpp") catch @panic("oom");
        return;
    }

    if (std.mem.eql(u8, tls_backend, "boringssl")) {
        files.append("src/quic/tls_adapter_boringssl.cpp") catch @panic("oom");
        return;
    }

    std.debug.panic("unsupported tls_backend {s}", .{tls_backend});
}

fn appendPacketCryptoSource(files: *std.ArrayList([]const u8), tls_backend: []const u8) void {
    if (std.mem.eql(u8, tls_backend, "quictls")) {
        files.append("src/quic/packet_crypto_quictls.cpp") catch @panic("oom");
        return;
    }

    if (std.mem.eql(u8, tls_backend, "boringssl")) {
        files.append("src/quic/packet_crypto_boringssl.cpp") catch @panic("oom");
        return;
    }

    std.debug.panic("unsupported tls_backend {s}", .{tls_backend});
}

fn tlsIncludeDir(b: *std.Build, tls_backend: []const u8) []const u8 {
    if (std.mem.eql(u8, tls_backend, "quictls"))
        return requireEnv(b, "QUICTLS_INCLUDE_DIR");

    if (std.mem.eql(u8, tls_backend, "boringssl"))
        return requireEnv(b, "BORINGSSL_INCLUDE_DIR");

    std.debug.panic("unsupported tls_backend {s}", .{tls_backend});
}

fn tlsLibDir(b: *std.Build, tls_backend: []const u8) []const u8 {
    if (std.mem.eql(u8, tls_backend, "quictls"))
        return requireEnv(b, "QUICTLS_LIB_DIR");

    if (std.mem.eql(u8, tls_backend, "boringssl"))
        return requireEnv(b, "BORINGSSL_LIB_DIR");

    std.debug.panic("unsupported tls_backend {s}", .{tls_backend});
}

fn addProjectLibrary(
    b: *std.Build,
    name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    project_cpp_flags: []const []const u8,
    tls_backend: []const u8,
    tls_include_dir: []const u8,
    spdlog_include_dir: []const u8,
    fmt_include_dir: []const u8,
) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = name,
        .target = target,
        .optimize = optimize,
    });
    lib.addIncludePath(b.path("."));
    lib.addIncludePath(.{ .cwd_relative = tls_include_dir });
    lib.addIncludePath(.{ .cwd_relative = spdlog_include_dir });
    lib.addIncludePath(.{ .cwd_relative = fmt_include_dir });
    var files = std.ArrayList([]const u8).init(b.allocator);
    files.appendSlice(&.{
        "src/coquic.cpp",
        "src/quic/buffer.cpp",
        "src/quic/congestion.cpp",
        "src/quic/connection.cpp",
        "src/quic/core.cpp",
        "src/quic/crypto_stream.cpp",
        "src/quic/demo_channel.cpp",
        "src/quic/frame.cpp",
        "src/quic/http09.cpp",
        "src/quic/http09_client.cpp",
        "src/quic/http09_server.cpp",
        "src/quic/packet.cpp",
        "src/quic/packet_number.cpp",
        "src/quic/plaintext_codec.cpp",
        "src/quic/recovery.cpp",
        "src/quic/protected_codec.cpp",
        "src/quic/streams.cpp",
        "src/quic/transport_parameters.cpp",
        "src/quic/varint.cpp",
    }) catch @panic("oom");
    appendPacketCryptoSource(&files, tls_backend);
    appendTlsAdapterSource(&files, tls_backend);
    lib.addCSourceFiles(.{
        .root = b.path("."),
        .files = files.toOwnedSlice() catch @panic("oom"),
        .flags = project_cpp_flags,
    });
    lib.linkLibCpp();
    return lib;
}

fn linkTlsBackend(
    b: *std.Build,
    compile: *std.Build.Step.Compile,
    tls_backend: []const u8,
    tls_lib_dir: []const u8,
) void {
    if (std.mem.eql(u8, tls_backend, "quictls")) {
        compile.addObjectFile(.{
            .cwd_relative = b.pathJoin(&.{ tls_lib_dir, "libssl.so" }),
        });
        compile.addObjectFile(.{
            .cwd_relative = b.pathJoin(&.{ tls_lib_dir, "libcrypto.so" }),
        });
        return;
    }

    if (std.mem.eql(u8, tls_backend, "boringssl")) {
        compile.addObjectFile(.{
            .cwd_relative = b.pathJoin(&.{ tls_lib_dir, "libssl.a" }),
        });
        compile.addObjectFile(.{
            .cwd_relative = b.pathJoin(&.{ tls_lib_dir, "libcrypto.a" }),
        });
        return;
    }

    std.debug.panic("unsupported tls_backend {s}", .{tls_backend});
}

fn linkSpdlog(compile: *std.Build.Step.Compile) void {
    compile.linkSystemLibrary2("spdlog", .{
        .use_pkg_config = .force,
    });
}

fn addTestBinary(
    b: *std.Build,
    name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpp_flags: []const []const u8,
    project_lib: *std.Build.Step.Compile,
    gtest_root: []const u8,
    test_files: []const []const u8,
) *std.Build.Step.Compile {
    const gtest_include_dir = b.pathJoin(&.{ gtest_root, "googletest", "include" });
    const gtest_src_dir = b.pathJoin(&.{ gtest_root, "googletest" });

    const test_exe = b.addExecutable(.{
        .name = name,
        .target = target,
        .optimize = optimize,
    });
    test_exe.addIncludePath(b.path("."));
    test_exe.addIncludePath(.{ .cwd_relative = gtest_include_dir });
    test_exe.addIncludePath(.{ .cwd_relative = gtest_src_dir });
    test_exe.addCSourceFiles(.{
        .root = b.path("."),
        .files = test_files,
        .flags = cpp_flags,
    });
    test_exe.addCSourceFiles(.{
        .root = .{ .cwd_relative = gtest_root },
        .files = &.{
            "googletest/src/gtest-all.cc",
            "googletest/src/gtest_main.cc",
        },
        .flags = cpp_flags,
    });
    test_exe.linkLibrary(project_lib);
    test_exe.linkSystemLibrary("pthread");
    test_exe.linkLibCpp();
    return test_exe;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const tls_backend =
        b.option([]const u8, "tls_backend", "quictls or boringssl") orelse "quictls";
    const cpp_flags = &.{"-std=c++20"};
    const spdlog_cpp_flags = withExtraFlags(b, cpp_flags, &.{
        "-DSPDLOG_SHARED_LIB",
        "-DSPDLOG_COMPILED_LIB",
        "-DSPDLOG_FMT_EXTERNAL",
    });
    const coverage_cpp_flags = withExtraFlags(b, cpp_flags, &.{
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
    });
    const coverage_spdlog_cpp_flags = withExtraFlags(b, coverage_cpp_flags, &.{
        "-DSPDLOG_SHARED_LIB",
        "-DSPDLOG_COMPILED_LIB",
        "-DSPDLOG_FMT_EXTERNAL",
    });
    const gtest_root = requireEnv(b, "GTEST_SOURCE_DIR");
    const tls_include_dir = tlsIncludeDir(b, tls_backend);
    const tls_lib_dir = tlsLibDir(b, tls_backend);
    const spdlog_include_dir = requireEnv(b, "SPDLOG_INCLUDE_DIR");
    const fmt_include_dir = requireEnv(b, "FMT_INCLUDE_DIR");
    const llvm_profile_rt = requireEnv(b, "LLVM_PROFILE_RT");
    const default_test_files = &.{
        "tests/smoke.cpp",
        "tests/quic_core_test.cpp",
        "tests/quic_congestion_test.cpp",
        "tests/quic_demo_channel_test.cpp",
        "tests/quic_frame_test.cpp",
        "tests/quic_crypto_stream_test.cpp",
        "tests/quic_packet_test.cpp",
        "tests/quic_packet_number_test.cpp",
        "tests/quic_packet_crypto_test.cpp",
        "tests/quic_plaintext_codec_test.cpp",
        "tests/quic_http09_test.cpp",
        "tests/quic_http09_server_test.cpp",
        "tests/quic_http09_client_test.cpp",
        "tests/quic_recovery_test.cpp",
        "tests/quic_streams_test.cpp",
        "tests/quic_protected_codec_test.cpp",
        "tests/quic_tls_adapter_contract_test.cpp",
        "tests/quic_transport_parameters_test.cpp",
        "tests/quic_varint_test.cpp",
    };

    const exe = b.addExecutable(.{
        .name = "coquic",
        .target = target,
        .optimize = optimize,
    });
    exe.addIncludePath(b.path("."));
    const project_lib = addProjectLibrary(
        b,
        "coquic",
        target,
        optimize,
        spdlog_cpp_flags,
        tls_backend,
        tls_include_dir,
        spdlog_include_dir,
        fmt_include_dir,
    );
    exe.addCSourceFiles(.{
        .root = b.path("."),
        .files = &.{"src/main.cpp"},
        .flags = cpp_flags,
    });
    exe.linkLibrary(project_lib);
    linkTlsBackend(b, exe, tls_backend, tls_lib_dir);
    linkSpdlog(exe);
    exe.linkLibCpp();
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    const run_step = b.step("run", "Run the coquic executable");
    run_step.dependOn(&run_exe.step);

    const smoke = addTestBinary(
        b,
        "coquic-tests",
        target,
        optimize,
        cpp_flags,
        project_lib,
        gtest_root,
        default_test_files,
    );
    linkTlsBackend(b, smoke, tls_backend, tls_lib_dir);
    linkSpdlog(smoke);
    const smoke_run = b.addRunArtifact(smoke);
    if (b.args) |args| {
        smoke_run.addArgs(args);
    }
    const test_step = b.step("test", "Run the GoogleTest suite");
    test_step.dependOn(&smoke_run.step);

    const coverage_lib = addProjectLibrary(
        b,
        "coquic-coverage",
        target,
        optimize,
        coverage_spdlog_cpp_flags,
        tls_backend,
        tls_include_dir,
        spdlog_include_dir,
        fmt_include_dir,
    );
    const coverage_test = addTestBinary(
        b,
        "coquic-coverage-tests",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        gtest_root,
        default_test_files,
    );
    linkTlsBackend(b, coverage_test, tls_backend, tls_lib_dir);
    linkSpdlog(coverage_test);
    coverage_test.addObjectFile(.{ .cwd_relative = llvm_profile_rt });
    coverage_test.forceUndefinedSymbol("__llvm_profile_runtime");
    const coverage_cmd = b.addSystemCommand(&.{ "bash" });
    coverage_cmd.addFileArg(b.path("scripts/run-coverage.sh"));
    coverage_cmd.addArtifactArg(coverage_test);
    const coverage_step = b.step(
        "coverage",
        "Run the test suite and export LLVM coverage reports",
    );
    coverage_step.dependOn(&coverage_cmd.step);
}
