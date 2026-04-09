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

fn withSpdlogFlags(
    b: *std.Build,
    base: []const []const u8,
    spdlog_shared: bool,
) []const []const u8 {
    var extra = std.ArrayList([]const u8).init(b.allocator);
    if (spdlog_shared) {
        extra.append("-DSPDLOG_SHARED_LIB") catch @panic("failed to append spdlog flag");
    }
    extra.appendSlice(&.{
        "-DSPDLOG_COMPILED_LIB",
        "-DSPDLOG_FMT_EXTERNAL",
    }) catch @panic("failed to append spdlog flags");
    return withExtraFlags(b, base, extra.items);
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

fn tlsLinkage(b: *std.Build) []const u8 {
    return requireEnv(b, "COQUIC_TLS_LINKAGE");
}

fn validateTlsConfiguration(tls_backend: []const u8, tls_linkage: []const u8) void {
    const backend_supported =
        std.mem.eql(u8, tls_backend, "quictls") or std.mem.eql(u8, tls_backend, "boringssl");
    if (!backend_supported)
        std.debug.panic("unsupported tls_backend {s}", .{tls_backend});

    const linkage_supported =
        std.mem.eql(u8, tls_linkage, "static") or std.mem.eql(u8, tls_linkage, "shared");
    if (!linkage_supported)
        std.debug.panic("unsupported tls_linkage {s}", .{tls_linkage});

    if (std.mem.eql(u8, tls_backend, "boringssl") and std.mem.eql(u8, tls_linkage, "shared")) {
        std.debug.panic(
            "unsupported TLS configuration: tls_backend=boringssl does not support tls_linkage=shared (use tls_linkage=static or tls_backend=quictls)",
            .{},
        );
    }
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
        "src/quic/frame.cpp",
        "src/quic/http09.cpp",
        "src/quic/http09_client.cpp",
        "src/quic/http09_runtime.cpp",
        "src/quic/http09_server.cpp",
        "src/quic/http3_protocol.cpp",
        "src/quic/http3_qpack.cpp",
        "src/quic/packet.cpp",
        "src/quic/packet_number.cpp",
        "src/quic/plaintext_codec.cpp",
        "src/quic/qlog/json.cpp",
        "src/quic/qlog/session.cpp",
        "src/quic/qlog/sink.cpp",
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
    tls_linkage: []const u8,
) void {
    validateTlsConfiguration(tls_backend, tls_linkage);

    const lib_ext =
        if (std.mem.eql(u8, tls_linkage, "static"))
            "a"
        else
            "so";

    compile.addObjectFile(.{
        .cwd_relative = b.pathJoin(&.{ tls_lib_dir, b.fmt("libssl.{s}", .{lib_ext}) }),
    });
    compile.addObjectFile(.{
        .cwd_relative = b.pathJoin(&.{ tls_lib_dir, b.fmt("libcrypto.{s}", .{lib_ext}) }),
    });
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
    const spdlog_shared =
        b.option(bool, "spdlog_shared", "whether spdlog is linked as a shared library") orelse
        true;
    const cpp_flags = &.{"-std=c++20"};
    const spdlog_cpp_flags = withSpdlogFlags(b, cpp_flags, spdlog_shared);
    const coverage_cpp_flags = withExtraFlags(b, cpp_flags, &.{
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
    });
    const coverage_spdlog_cpp_flags =
        withSpdlogFlags(b, coverage_cpp_flags, spdlog_shared);
    const gtest_root = requireEnv(b, "GTEST_SOURCE_DIR");
    const tls_linkage = tlsLinkage(b);
    validateTlsConfiguration(tls_backend, tls_linkage);
    const tls_include_dir = tlsIncludeDir(b, tls_backend);
    const tls_lib_dir = tlsLibDir(b, tls_backend);
    const spdlog_include_dir = requireEnv(b, "SPDLOG_INCLUDE_DIR");
    const fmt_include_dir = requireEnv(b, "FMT_INCLUDE_DIR");
    const llvm_profile_rt = requireEnv(b, "LLVM_PROFILE_RT");
    const smoke_test_files = &.{
        "tests/smoke/smoke_test.cpp",
    };
    const core_test_files = &.{
        "tests/core/recovery/congestion_test.cpp",
        "tests/core/recovery/recovery_test.cpp",
        "tests/core/packets/frame_test.cpp",
        "tests/core/packets/packet_test.cpp",
        "tests/core/packets/packet_number_test.cpp",
        "tests/core/packets/plaintext_codec_test.cpp",
        "tests/core/packets/protected_codec_test.cpp",
        "tests/core/packets/transport_parameters_test.cpp",
        "tests/core/packets/varint_test.cpp",
        "tests/core/streams/streams_test.cpp",
        "tests/core/streams/crypto_stream_test.cpp",
        "tests/core/connection/handshake_test.cpp",
        "tests/core/connection/zero_rtt_test.cpp",
        "tests/core/connection/connection_id_test.cpp",
        "tests/core/connection/stream_test.cpp",
        "tests/core/connection/flow_control_test.cpp",
        "tests/core/connection/ack_test.cpp",
        "tests/core/connection/migration_test.cpp",
        "tests/core/connection/path_validation_test.cpp",
        "tests/core/connection/retry_version_test.cpp",
        "tests/core/connection/key_update_test.cpp",
        "tests/core/endpoint/open_test.cpp",
        "tests/core/endpoint/multiplex_test.cpp",
    };
    const http09_test_files = &.{
        "tests/http09/protocol/http09_test.cpp",
        "tests/http09/protocol/server_test.cpp",
        "tests/http09/protocol/client_test.cpp",
        "tests/http09/runtime/transfer_test.cpp",
        "tests/http09/runtime/startup_test.cpp",
        "tests/http09/runtime/config_test.cpp",
        "tests/http09/runtime/io_test.cpp",
        "tests/http09/runtime/routing_test.cpp",
        "tests/http09/runtime/migration_test.cpp",
        "tests/http09/runtime/preferred_address_test.cpp",
        "tests/http09/runtime/retry_zero_rtt_test.cpp",
        "tests/http09/runtime/interop_alias_test.cpp",
        "tests/http09/runtime/linux_ecn_test.cpp",
    };
    const http3_test_files = &.{
        "tests/http3/protocol_test.cpp",
        "tests/http3/qpack_test.cpp",
    };
    const qlog_test_files = &.{
        "tests/qlog/qlog_test.cpp",
        "tests/qlog/core_integration_test.cpp",
    };
    const tls_test_files = &.{
        "tests/tls/packet_crypto_test.cpp",
        "tests/tls/tls_adapter_contract_test.cpp",
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
    linkTlsBackend(b, exe, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(exe);
    exe.linkLibCpp();
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    const run_step = b.step("run", "Run the coquic executable");
    run_step.dependOn(&run_exe.step);

    const smoke_tests = addTestBinary(
        b,
        "coquic-tests-smoke",
        target,
        optimize,
        cpp_flags,
        project_lib,
        gtest_root,
        smoke_test_files,
    );
    const core_tests = addTestBinary(
        b,
        "coquic-tests-core",
        target,
        optimize,
        cpp_flags,
        project_lib,
        gtest_root,
        core_test_files,
    );
    const http09_tests = addTestBinary(
        b,
        "coquic-tests-http09",
        target,
        optimize,
        cpp_flags,
        project_lib,
        gtest_root,
        http09_test_files,
    );
    const http3_tests = addTestBinary(
        b,
        "coquic-tests-http3",
        target,
        optimize,
        cpp_flags,
        project_lib,
        gtest_root,
        http3_test_files,
    );
    const qlog_tests = addTestBinary(
        b,
        "coquic-tests-qlog",
        target,
        optimize,
        cpp_flags,
        project_lib,
        gtest_root,
        qlog_test_files,
    );
    const tls_tests = addTestBinary(
        b,
        "coquic-tests-tls",
        target,
        optimize,
        cpp_flags,
        project_lib,
        gtest_root,
        tls_test_files,
    );
    linkTlsBackend(b, smoke_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(smoke_tests);
    const smoke_tests_run = b.addRunArtifact(smoke_tests);
    linkTlsBackend(b, core_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(core_tests);
    const core_tests_run = b.addRunArtifact(core_tests);
    linkTlsBackend(b, http09_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(http09_tests);
    const http09_tests_run = b.addRunArtifact(http09_tests);
    linkTlsBackend(b, http3_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(http3_tests);
    const http3_tests_run = b.addRunArtifact(http3_tests);
    linkTlsBackend(b, qlog_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(qlog_tests);
    const qlog_tests_run = b.addRunArtifact(qlog_tests);
    linkTlsBackend(b, tls_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(tls_tests);
    const tls_tests_run = b.addRunArtifact(tls_tests);
    if (b.args) |args| {
        smoke_tests_run.addArgs(args);
        core_tests_run.addArgs(args);
        http09_tests_run.addArgs(args);
        http3_tests_run.addArgs(args);
        qlog_tests_run.addArgs(args);
        tls_tests_run.addArgs(args);
    }
    const test_step = b.step("test", "Run the GoogleTest suite");
    test_step.dependOn(&smoke_tests_run.step);
    test_step.dependOn(&core_tests_run.step);
    test_step.dependOn(&http09_tests_run.step);
    test_step.dependOn(&http3_tests_run.step);
    test_step.dependOn(&qlog_tests_run.step);
    test_step.dependOn(&tls_tests_run.step);
    const compdb_step = b.step(
        "compdb",
        "Build the main executable and GoogleTest binaries without running them",
    );
    compdb_step.dependOn(&exe.step);
    compdb_step.dependOn(&smoke_tests.step);
    compdb_step.dependOn(&core_tests.step);
    compdb_step.dependOn(&http09_tests.step);
    compdb_step.dependOn(&http3_tests.step);
    compdb_step.dependOn(&qlog_tests.step);
    compdb_step.dependOn(&tls_tests.step);

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
    const smoke_coverage_tests = addTestBinary(
        b,
        "coquic-coverage-tests-smoke",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        gtest_root,
        smoke_test_files,
    );
    const core_coverage_tests = addTestBinary(
        b,
        "coquic-coverage-tests-core",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        gtest_root,
        core_test_files,
    );
    const http09_coverage_tests = addTestBinary(
        b,
        "coquic-coverage-tests-http09",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        gtest_root,
        http09_test_files,
    );
    const http3_coverage_tests = addTestBinary(
        b,
        "coquic-coverage-tests-http3",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        gtest_root,
        http3_test_files,
    );
    const qlog_coverage_tests = addTestBinary(
        b,
        "coquic-coverage-tests-qlog",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        gtest_root,
        qlog_test_files,
    );
    const tls_coverage_tests = addTestBinary(
        b,
        "coquic-coverage-tests-tls",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        gtest_root,
        tls_test_files,
    );
    linkTlsBackend(b, smoke_coverage_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(smoke_coverage_tests);
    smoke_coverage_tests.addObjectFile(.{ .cwd_relative = llvm_profile_rt });
    smoke_coverage_tests.forceUndefinedSymbol("__llvm_profile_runtime");
    linkTlsBackend(b, core_coverage_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(core_coverage_tests);
    core_coverage_tests.addObjectFile(.{ .cwd_relative = llvm_profile_rt });
    core_coverage_tests.forceUndefinedSymbol("__llvm_profile_runtime");
    linkTlsBackend(b, http09_coverage_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(http09_coverage_tests);
    http09_coverage_tests.addObjectFile(.{ .cwd_relative = llvm_profile_rt });
    http09_coverage_tests.forceUndefinedSymbol("__llvm_profile_runtime");
    linkTlsBackend(b, http3_coverage_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(http3_coverage_tests);
    http3_coverage_tests.addObjectFile(.{ .cwd_relative = llvm_profile_rt });
    http3_coverage_tests.forceUndefinedSymbol("__llvm_profile_runtime");
    linkTlsBackend(b, qlog_coverage_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(qlog_coverage_tests);
    qlog_coverage_tests.addObjectFile(.{ .cwd_relative = llvm_profile_rt });
    qlog_coverage_tests.forceUndefinedSymbol("__llvm_profile_runtime");
    linkTlsBackend(b, tls_coverage_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(tls_coverage_tests);
    tls_coverage_tests.addObjectFile(.{ .cwd_relative = llvm_profile_rt });
    tls_coverage_tests.forceUndefinedSymbol("__llvm_profile_runtime");
    const coverage_cmd = b.addSystemCommand(&.{ "bash" });
    coverage_cmd.addFileArg(b.path("scripts/run-coverage.sh"));
    coverage_cmd.addArtifactArg(smoke_coverage_tests);
    coverage_cmd.addArtifactArg(core_coverage_tests);
    coverage_cmd.addArtifactArg(http09_coverage_tests);
    coverage_cmd.addArtifactArg(http3_coverage_tests);
    coverage_cmd.addArtifactArg(qlog_coverage_tests);
    coverage_cmd.addArtifactArg(tls_coverage_tests);
    const coverage_step = b.step(
        "coverage",
        "Run the test suite and export LLVM coverage reports",
    );
    coverage_step.dependOn(&coverage_cmd.step);
}
