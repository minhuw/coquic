const std = @import("std");

const StringList = std.array_list.Managed([]const u8);

fn requireEnv(b: *std.Build, name: []const u8) []const u8 {
    return b.graph.environ_map.get(name) orelse std.debug.panic(
        "missing required environment variable {s}; run inside `nix develop`",
        .{name},
    );
}

fn rootModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .target = target,
        .optimize = optimize,
    });
}

fn addIncludePath(compile: *std.Build.Step.Compile, path: std.Build.LazyPath) void {
    compile.root_module.addIncludePath(path);
}

fn addCSourceFiles(
    compile: *std.Build.Step.Compile,
    options: std.Build.Module.AddCSourceFilesOptions,
) void {
    compile.root_module.addCSourceFiles(options);
}

fn addObjectFile(compile: *std.Build.Step.Compile, path: std.Build.LazyPath) void {
    compile.root_module.addObjectFile(path);
}

fn linkLibrary(
    compile: *std.Build.Step.Compile,
    library: *std.Build.Step.Compile,
) void {
    compile.root_module.linkLibrary(library);
}

fn linkSystemLibrary(
    compile: *std.Build.Step.Compile,
    name: []const u8,
    options: std.Build.Module.LinkSystemLibraryOptions,
) void {
    compile.root_module.linkSystemLibrary(name, options);
}

fn linkLibCpp(compile: *std.Build.Step.Compile) void {
    compile.root_module.link_libcpp = true;
}

fn withExtraFlags(
    b: *std.Build,
    base: []const []const u8,
    extra: []const []const u8,
) []const []const u8 {
    var flags = StringList.init(b.allocator);
    flags.appendSlice(base) catch @panic("failed to append base flags");
    flags.appendSlice(extra) catch @panic("failed to append extra flags");
    return flags.toOwnedSlice() catch @panic("failed to allocate flags");
}

fn withSpdlogFlags(
    b: *std.Build,
    base: []const []const u8,
    spdlog_shared: bool,
) []const []const u8 {
    var extra = StringList.init(b.allocator);
    if (spdlog_shared) {
        extra.append("-DSPDLOG_SHARED_LIB") catch @panic("failed to append spdlog flag");
    }
    extra.appendSlice(&.{
        "-DSPDLOG_COMPILED_LIB",
    }) catch @panic("failed to append spdlog flags");
    return withExtraFlags(b, base, extra.items);
}

fn appendTlsAdapterSource(files: *StringList, tls_backend: []const u8) void {
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

fn appendPacketCryptoSource(files: *StringList, tls_backend: []const u8) void {
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

fn appendSourceFiles(files: *StringList, source_files: []const []const u8) void {
    files.appendSlice(source_files) catch @panic("oom");
}

fn quicSourceFiles() []const []const u8 {
    return &.{
        "src/quic/buffer.cpp",
        "src/quic/cca/bbr.cpp",
        "src/quic/cca/common.cpp",
        "src/quic/cca/copa.cpp",
        "src/quic/cca/cubic.cpp",
        "src/quic/cca/newreno.cpp",
        "src/quic/congestion.cpp",
        "src/quic/connection.cpp",
        "src/quic/connection_diagnostics.cpp",
        "src/quic/connection_effects.cpp",
        "src/quic/connection_flow_control.cpp",
        "src/quic/connection_helper_tests.cpp",
        "src/quic/connection_inbound_recovery.cpp",
        "src/quic/connection_internal_helper_tests.cpp",
        "src/quic/connection_key_update_tests.cpp",
        "src/quic/connection_packet_inspection.cpp",
        "src/quic/connection_paths_streams.cpp",
        "src/quic/connection_pmtud_tests.cpp",
        "src/quic/connection_qlog.cpp",
        "src/quic/connection_send.cpp",
        "src/quic/connection_timers.cpp",
        "src/quic/core.cpp",
        "src/quic/crypto_stream.cpp",
        "src/quic/frame.cpp",
        "src/quic/packet.cpp",
        "src/quic/packet_number.cpp",
        "src/quic/plaintext_codec.cpp",
        "src/quic/protected_codec.cpp",
        "src/quic/protected_codec_test_hooks.cpp",
        "src/quic/qlog/json.cpp",
        "src/quic/qlog/session.cpp",
        "src/quic/qlog/sink.cpp",
        "src/quic/recovery.cpp",
        "src/quic/streams.cpp",
        "src/quic/transport_parameters.cpp",
        "src/quic/varint.cpp",
    };
}

fn ioSourceFiles() []const []const u8 {
    return &.{
        "src/io/io_backend_factory.cpp",
        "src/io/io_uring_backend.cpp",
        "src/io/io_uring_io_engine.cpp",
        "src/io/poll_io_engine.cpp",
        "src/io/shared_udp_backend_core.cpp",
        "src/io/socket_io_backend.cpp",
    };
}

fn http09SourceFiles() []const []const u8 {
    return &.{
        "src/http09/http09.cpp",
        "src/http09/http09_client.cpp",
        "src/http09/http09_runtime.cpp",
        "src/http09/http09_runtime_io_restart_tests.cpp",
        "src/http09/http09_runtime_parser_routing_tests.cpp",
        "src/http09/http09_runtime_server_loop_tests.cpp",
        "src/http09/http09_runtime_test_hooks.cpp",
        "src/http09/http09_server.cpp",
    };
}

fn http3SourceFiles() []const []const u8 {
    return &.{
        "src/http3/http3_bootstrap.cpp",
        "src/http3/http3_client.cpp",
        "src/http3/http3_connection.cpp",
        "src/http3/http3_demo_routes.cpp",
        "src/http3/http3_interop.cpp",
        "src/http3/http3_protocol.cpp",
        "src/http3/http3_qpack.cpp",
        "src/http3/http3_reverse_proxy.cpp",
        "src/http3/http3_runtime.cpp",
        "src/http3/http3_server.cpp",
    };
}

fn perfSourceFiles() []const []const u8 {
    return &.{
        "src/perf/perf_client.cpp",
        "src/perf/perf_loop.cpp",
        "src/perf/perf_metrics.cpp",
        "src/perf/perf_protocol.cpp",
        "src/perf/perf_runtime.cpp",
        "src/perf/perf_server.cpp",
    };
}

fn apiSourceFiles() []const []const u8 {
    return &.{
        "src/api/core.cpp",
        "src/api/http3.cpp",
        "src/api/quic.cpp",
    };
}

fn ffiSourceFiles() []const []const u8 {
    return &.{
        "src/ffi/core.cpp",
    };
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
    liburing_include_dir: []const u8,
) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = name,
        .linkage = .static,
        .root_module = rootModule(b, target, optimize),
    });
    addIncludePath(lib, b.path("."));
    addIncludePath(lib, b.path("include"));
    addIncludePath(lib, .{ .cwd_relative = tls_include_dir });
    addIncludePath(lib, .{ .cwd_relative = spdlog_include_dir });
    addIncludePath(lib, .{ .cwd_relative = fmt_include_dir });
    addIncludePath(lib, .{ .cwd_relative = liburing_include_dir });
    var files = StringList.init(b.allocator);
    appendSourceFiles(&files, quicSourceFiles());
    appendPacketCryptoSource(&files, tls_backend);
    appendTlsAdapterSource(&files, tls_backend);
    appendSourceFiles(&files, ioSourceFiles());
    appendSourceFiles(&files, http09SourceFiles());
    appendSourceFiles(&files, http3SourceFiles());
    appendSourceFiles(&files, perfSourceFiles());
    appendSourceFiles(&files, apiSourceFiles());
    appendSourceFiles(&files, ffiSourceFiles());
    addCSourceFiles(lib, .{
        .root = b.path("."),
        .files = files.toOwnedSlice() catch @panic("oom"),
        .flags = project_cpp_flags,
    });
    linkLibCpp(lib);
    return lib;
}

fn wasmQuicSourceFiles() []const []const u8 {
    return &.{
        "src/quic/buffer.cpp",
        "src/quic/cca/bbr.cpp",
        "src/quic/cca/common.cpp",
        "src/quic/cca/copa.cpp",
        "src/quic/cca/cubic.cpp",
        "src/quic/cca/newreno.cpp",
        "src/quic/congestion.cpp",
        "src/quic/connection.cpp",
        "src/quic/connection_diagnostics.cpp",
        "src/quic/connection_effects.cpp",
        "src/quic/connection_flow_control.cpp",
        "src/quic/connection_helper_tests.cpp",
        "src/quic/connection_inbound_recovery.cpp",
        "src/quic/connection_internal_helper_tests.cpp",
        "src/quic/connection_key_update_tests.cpp",
        "src/quic/connection_packet_inspection.cpp",
        "src/quic/connection_paths_streams.cpp",
        "src/quic/connection_pmtud_tests.cpp",
        "src/quic/connection_qlog.cpp",
        "src/quic/connection_send.cpp",
        "src/quic/connection_timers.cpp",
        "src/quic/core.cpp",
        "src/quic/crypto_stream.cpp",
        "src/quic/frame.cpp",
        "src/quic/packet.cpp",
        "src/quic/packet_crypto_boringssl.cpp",
        "src/quic/packet_number.cpp",
        "src/quic/plaintext_codec.cpp",
        "src/quic/protected_codec.cpp",
        "src/quic/protected_codec_test_hooks.cpp",
        "src/quic/qlog/json.cpp",
        "src/quic/qlog/session.cpp",
        "src/quic/qlog/sink.cpp",
        "src/quic/recovery.cpp",
        "src/quic/streams.cpp",
        "src/quic/tls_adapter_boringssl.cpp",
        "src/quic/transport_parameters.cpp",
        "src/quic/varint.cpp",
        "src/wasm/quic_wasm_api.cpp",
    };
}

fn wasmQuicExportNames() []const []const u8 {
    return &.{
        "coquic_wasm_version",
        "coquic_wasm_alloc",
        "coquic_wasm_free",
        "coquic_wasm_endpoint_create",
        "coquic_wasm_endpoint_create_with_options",
        "coquic_wasm_endpoint_destroy",
        "coquic_wasm_endpoint_open_connection",
        "coquic_wasm_endpoint_open_connection_with_options",
        "coquic_wasm_endpoint_open_connection_with_resumption",
        "coquic_wasm_endpoint_input_datagram",
        "coquic_wasm_endpoint_send_stream",
        "coquic_wasm_endpoint_send_datagram",
        "coquic_wasm_endpoint_request_key_update",
        "coquic_wasm_endpoint_request_migration",
        "coquic_wasm_endpoint_timer_expired",
        "coquic_wasm_endpoint_next_wakeup_ms",
        "coquic_wasm_endpoint_next_datagram_header",
        "coquic_wasm_endpoint_pop_datagram",
        "coquic_wasm_endpoint_next_event_header",
        "coquic_wasm_endpoint_pop_event",
        "coquic_wasm_endpoint_next_packet_inspection_header",
        "coquic_wasm_endpoint_pop_packet_inspection",
        "coquic_wasm_endpoint_connection_count",
        "coquic_wasm_endpoint_diagnostics",
        "coquic_wasm_inspect_initial_packet",
    };
}

fn addWasmQuic(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    cpp_flags: []const []const u8,
    boringssl_include_dir: []const u8,
    boringssl_lib_dir: []const u8,
) *std.Build.Step.Compile {
    const wasm_cpp_flags = withExtraFlags(b, cpp_flags, &.{
        "-fno-exceptions",
        "-fno-rtti",
        "-DCOQUIC_WASM_NO_FILESYSTEM",
        "-DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
    });
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .wasi,
    });
    const wasm = b.addExecutable(.{
        .name = "coquic-wasm-quic",
        .root_module = rootModule(b, wasm_target, optimize),
    });
    wasm.entry = .disabled;
    wasm.wasi_exec_model = .reactor;
    wasm.export_memory = true;
    wasm.root_module.export_symbol_names = wasmQuicExportNames();
    addIncludePath(wasm, b.path("."));
    addIncludePath(wasm, .{ .cwd_relative = boringssl_include_dir });
    addCSourceFiles(wasm, .{
        .root = b.path("."),
        .files = wasmQuicSourceFiles(),
        .flags = wasm_cpp_flags,
    });
    addObjectFile(wasm, .{
        .cwd_relative = b.pathJoin(&.{ boringssl_lib_dir, "libssl.a" }),
    });
    addObjectFile(wasm, .{
        .cwd_relative = b.pathJoin(&.{ boringssl_lib_dir, "libcrypto.a" }),
    });
    linkLibCpp(wasm);
    return wasm;
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

    addObjectFile(compile, .{
        .cwd_relative = b.pathJoin(&.{ tls_lib_dir, b.fmt("libssl.{s}", .{lib_ext}) }),
    });
    addObjectFile(compile, .{
        .cwd_relative = b.pathJoin(&.{ tls_lib_dir, b.fmt("libcrypto.{s}", .{lib_ext}) }),
    });
}

fn linkSpdlog(compile: *std.Build.Step.Compile) void {
    linkSystemLibrary(compile, "spdlog", .{
        .use_pkg_config = .force,
    });
}

fn linkLiburing(compile: *std.Build.Step.Compile) void {
    linkSystemLibrary(compile, "liburing", .{
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
    tls_include_dir: []const u8,
    gtest_root: []const u8,
    test_files: []const []const u8,
) *std.Build.Step.Compile {
    const gtest_include_dir = b.pathJoin(&.{ gtest_root, "googletest", "include" });
    const gtest_src_dir = b.pathJoin(&.{ gtest_root, "googletest" });

    const test_exe = b.addExecutable(.{
        .name = name,
        .root_module = rootModule(b, target, optimize),
    });
    addIncludePath(test_exe, b.path("."));
    addIncludePath(test_exe, b.path("include"));
    addIncludePath(test_exe, .{ .cwd_relative = tls_include_dir });
    addIncludePath(test_exe, .{ .cwd_relative = gtest_include_dir });
    addIncludePath(test_exe, .{ .cwd_relative = gtest_src_dir });
    addCSourceFiles(test_exe, .{
        .root = b.path("."),
        .files = test_files,
        .flags = cpp_flags,
    });
    addCSourceFiles(test_exe, .{
        .root = .{ .cwd_relative = gtest_root },
        .files = &.{
            "googletest/src/gtest-all.cc",
            "googletest/src/gtest_main.cc",
        },
        .flags = cpp_flags,
    });
    linkLibrary(test_exe, project_lib);
    linkSystemLibrary(test_exe, "pthread", .{});
    linkLibCpp(test_exe);
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
    const profile_hooks =
        b.option(bool, "profile_hooks", "enable runtime CoQUIC profile hooks") orelse true;
    const cpp_flags = withExtraFlags(b, &.{"-std=c++20"}, &.{
        if (profile_hooks) "-DCOQUIC_PROFILE_HOOKS=1" else "-DCOQUIC_PROFILE_HOOKS=0",
    });
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
    const liburing_include_dir = requireEnv(b, "LIBURING_INCLUDE_DIR");
    const llvm_profile_rt = requireEnv(b, "LLVM_PROFILE_RT");
    const wasm_boringssl_include_dir =
        b.option([]const u8, "wasm_boringssl_include_dir", "BoringSSL wasm include directory") orelse
        b.graph.environ_map.get("WASM_BORINGSSL_INCLUDE_DIR") orelse
        ".zig-cache/boringssl-wasm/src/include";
    const wasm_boringssl_lib_dir =
        b.option([]const u8, "wasm_boringssl_lib_dir", "BoringSSL wasm library directory") orelse
        b.graph.environ_map.get("WASM_BORINGSSL_LIB_DIR") orelse
        ".zig-cache/boringssl-wasm/build";
    const smoke_test_files = &.{
        "tests/smoke/smoke_test.cpp",
        "tests/api/public_api_test.cpp",
        "tests/ffi/core_ffi_test.cpp",
    };
    const core_test_files = &.{
        "tests/core/recovery/congestion_test.cpp",
        "tests/core/recovery/recovery_test.cpp",
        "tests/core/packets/buffer_test.cpp",
        "tests/core/packets/frame_test.cpp",
        "tests/core/packets/packet_test.cpp",
        "tests/core/packets/packet_number_test.cpp",
        "tests/core/packets/plaintext_codec_test.cpp",
        "tests/core/packets/protected_codec_test.cpp",
        "tests/core/packets/transport_parameters_test.cpp",
        "tests/core/packets/varint_test.cpp",
        "tests/core/streams/streams_test.cpp",
        "tests/core/streams/crypto_stream_test.cpp",
        "tests/core/connection/handshake_lifecycle_test.cpp",
        "tests/core/connection/handshake_inbound_test.cpp",
        "tests/core/connection/handshake_qlog_trace_test.cpp",
        "tests/core/connection/zero_rtt_test.cpp",
        "tests/core/connection/connection_id_test.cpp",
        "tests/core/connection/stream_test.cpp",
        "tests/core/connection/flow_control_test.cpp",
        "tests/core/connection/ack_receive_test.cpp",
        "tests/core/connection/ack_recovery_test.cpp",
        "tests/core/connection/ack_send_path_test.cpp",
        "tests/core/connection/migration_test.cpp",
        "tests/core/connection/path_validation_test.cpp",
        "tests/core/connection/retry_version_test.cpp",
        "tests/core/connection/key_update_test.cpp",
        "tests/core/endpoint/open_test.cpp",
        "tests/core/endpoint/multiplex_test.cpp",
        "tests/core/endpoint/server_routing_test.cpp",
        "tests/core/endpoint/internal_test.cpp",
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
        "tests/http09/runtime/io_backend_contract_test.cpp",
        "tests/http09/runtime/socket_io_backend_test.cpp",
        "tests/http09/runtime/io_backend_factory_test.cpp",
        "tests/http09/runtime/io_uring_backend_test.cpp",
    };
    const http3_test_files = &.{
        "tests/http3/connection_control_stream_test.cpp",
        "tests/http3/connection_request_response_test.cpp",
        "tests/http3/connection_error_paths_test.cpp",
        "tests/http3/protocol_test.cpp",
        "tests/http3/qpack_test.cpp",
        "tests/http3/qpack_dynamic_test.cpp",
        "tests/http3/client_test.cpp",
        "tests/http3/bootstrap_test.cpp",
        "tests/http3/server_test.cpp",
        "tests/http3/runtime_test.cpp",
        "tests/http3/interop_test.cpp",
    };
    const qlog_test_files = &.{
        "tests/qlog/qlog_test.cpp",
        "tests/qlog/core_integration_test.cpp",
    };
    const tls_test_files = &.{
        "tests/tls/packet_crypto_test.cpp",
        "tests/tls/tls_adapter_contract_test.cpp",
    };
    const perf_test_files = &.{
        "tests/perf/config_test.cpp",
        "tests/perf/protocol_test.cpp",
        "tests/perf/metrics_test.cpp",
        "tests/perf/server_test.cpp",
        "tests/perf/bulk_test.cpp",
        "tests/perf/rr_test.cpp",
        "tests/perf/crr_test.cpp",
    };

    const wasm_quic =
        addWasmQuic(b, optimize, cpp_flags, wasm_boringssl_include_dir, wasm_boringssl_lib_dir);
    const install_wasm_quic = b.addInstallArtifact(wasm_quic, .{
        .dest_dir = .{ .override = .prefix },
        .dest_sub_path = "share/wasm-quic/coquic-wasm-quic.wasm",
    });
    const wasm_quic_step = b.step(
        "wasm-quic",
        "Build the no-I/O QUIC WebAssembly module for the Next.js browser demo",
    );
    wasm_quic_step.dependOn(&install_wasm_quic.step);

    const exe = b.addExecutable(.{
        .name = "coquic",
        .root_module = rootModule(b, target, optimize),
    });
    addIncludePath(exe, b.path("."));
    addIncludePath(exe, b.path("include"));
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
        liburing_include_dir,
    );
    addCSourceFiles(exe, .{
        .root = b.path("."),
        .files = &.{"src/main.cpp"},
        .flags = cpp_flags,
    });
    linkLibrary(exe, project_lib);
    linkTlsBackend(b, exe, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(exe);
    linkLiburing(exe);
    linkLibCpp(exe);
    b.installArtifact(exe);

    const h3_server_exe = b.addExecutable(.{
        .name = "h3-server",
        .root_module = rootModule(b, target, optimize),
    });
    addIncludePath(h3_server_exe, b.path("."));
    addIncludePath(h3_server_exe, b.path("include"));
    addCSourceFiles(h3_server_exe, .{
        .root = b.path("."),
        .files = &.{"src/main_h3_server.cpp"},
        .flags = cpp_flags,
    });
    linkLibrary(h3_server_exe, project_lib);
    linkTlsBackend(b, h3_server_exe, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(h3_server_exe);
    linkLiburing(h3_server_exe);
    linkLibCpp(h3_server_exe);
    b.installArtifact(h3_server_exe);

    const perf_exe = b.addExecutable(.{
        .name = "coquic-perf",
        .root_module = rootModule(b, target, optimize),
    });
    addIncludePath(perf_exe, b.path("."));
    addIncludePath(perf_exe, b.path("include"));
    addCSourceFiles(perf_exe, .{
        .root = b.path("."),
        .files = &.{"src/main_perf.cpp"},
        .flags = cpp_flags,
    });
    linkLibrary(perf_exe, project_lib);
    linkTlsBackend(b, perf_exe, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(perf_exe);
    linkLiburing(perf_exe);
    linkLibCpp(perf_exe);
    b.installArtifact(perf_exe);

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
        tls_include_dir,
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
        tls_include_dir,
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
        tls_include_dir,
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
        tls_include_dir,
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
        tls_include_dir,
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
        tls_include_dir,
        gtest_root,
        tls_test_files,
    );
    const perf_tests = addTestBinary(
        b,
        "coquic-tests-perf",
        target,
        optimize,
        cpp_flags,
        project_lib,
        tls_include_dir,
        gtest_root,
        perf_test_files,
    );
    linkTlsBackend(b, smoke_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(smoke_tests);
    linkLiburing(smoke_tests);
    const smoke_tests_run = b.addRunArtifact(smoke_tests);
    linkTlsBackend(b, core_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(core_tests);
    linkLiburing(core_tests);
    const core_tests_run = b.addRunArtifact(core_tests);
    linkTlsBackend(b, http09_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(http09_tests);
    linkLiburing(http09_tests);
    const http09_tests_run = b.addRunArtifact(http09_tests);
    linkTlsBackend(b, http3_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(http3_tests);
    linkLiburing(http3_tests);
    const http3_tests_run = b.addRunArtifact(http3_tests);
    linkTlsBackend(b, qlog_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(qlog_tests);
    linkLiburing(qlog_tests);
    const qlog_tests_run = b.addRunArtifact(qlog_tests);
    linkTlsBackend(b, tls_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(tls_tests);
    linkLiburing(tls_tests);
    const tls_tests_run = b.addRunArtifact(tls_tests);
    linkTlsBackend(b, perf_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(perf_tests);
    linkLiburing(perf_tests);
    const perf_tests_run = b.addRunArtifact(perf_tests);
    if (b.args) |args| {
        smoke_tests_run.addArgs(args);
        core_tests_run.addArgs(args);
        http09_tests_run.addArgs(args);
        http3_tests_run.addArgs(args);
        qlog_tests_run.addArgs(args);
        tls_tests_run.addArgs(args);
        perf_tests_run.addArgs(args);
    }
    const test_step = b.step("test", "Run the GoogleTest suite");
    test_step.dependOn(&smoke_tests_run.step);
    test_step.dependOn(&core_tests_run.step);
    test_step.dependOn(&http09_tests_run.step);
    test_step.dependOn(&http3_tests_run.step);
    test_step.dependOn(&qlog_tests_run.step);
    test_step.dependOn(&tls_tests_run.step);
    test_step.dependOn(&perf_tests_run.step);
    const compdb_step = b.step(
        "compdb",
        "Build the main executable and GoogleTest binaries without running them",
    );
    compdb_step.dependOn(&exe.step);
    compdb_step.dependOn(&perf_exe.step);
    compdb_step.dependOn(&smoke_tests.step);
    compdb_step.dependOn(&core_tests.step);
    compdb_step.dependOn(&http09_tests.step);
    compdb_step.dependOn(&http3_tests.step);
    compdb_step.dependOn(&qlog_tests.step);
    compdb_step.dependOn(&tls_tests.step);
    compdb_step.dependOn(&perf_tests.step);

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
        liburing_include_dir,
    );
    var coverage_test_file_list = StringList.init(b.allocator);
    coverage_test_file_list.appendSlice(smoke_test_files) catch @panic("oom");
    coverage_test_file_list.appendSlice(core_test_files) catch @panic("oom");
    coverage_test_file_list.appendSlice(http09_test_files) catch @panic("oom");
    coverage_test_file_list.appendSlice(http3_test_files) catch @panic("oom");
    coverage_test_file_list.appendSlice(qlog_test_files) catch @panic("oom");
    coverage_test_file_list.appendSlice(tls_test_files) catch @panic("oom");

    const coverage_tests = addTestBinary(
        b,
        "coquic-coverage-tests",
        target,
        optimize,
        coverage_cpp_flags,
        coverage_lib,
        tls_include_dir,
        gtest_root,
        coverage_test_file_list.toOwnedSlice() catch @panic("oom"),
    );
    linkTlsBackend(b, coverage_tests, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(coverage_tests);
    linkLiburing(coverage_tests);
    addObjectFile(coverage_tests, .{ .cwd_relative = llvm_profile_rt });
    coverage_tests.forceUndefinedSymbol("__llvm_profile_runtime");
    const coverage_cmd = b.addSystemCommand(&.{"bash"});
    coverage_cmd.addFileArg(b.path("scripts/run-coverage.sh"));
    coverage_cmd.addArtifactArg(coverage_tests);
    const coverage_step = b.step(
        "coverage",
        "Run the test suite and export LLVM coverage reports",
    );
    coverage_step.dependOn(&coverage_cmd.step);
}
