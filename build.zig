const std = @import("std");

const StringList = std.array_list.Managed([]const u8);

const CoreFfiPackageLibraries = struct {
    static_lib: std.Build.LazyPath,
    shared_lib: std.Build.LazyPath,
};

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

fn picRootModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .target = target,
        .optimize = optimize,
        .pic = true,
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

fn quicProductionSourceFiles() []const []const u8 {
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
        "src/quic/connection_inbound_recovery.cpp",
        "src/quic/connection_packet_inspection.cpp",
        "src/quic/connection_paths_streams.cpp",
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
        "src/quic/qlog/json.cpp",
        "src/quic/qlog/session.cpp",
        "src/quic/qlog/sink.cpp",
        "src/quic/recovery.cpp",
        "src/quic/streams.cpp",
        "src/quic/transport_parameters.cpp",
        "src/quic/varint.cpp",
    };
}

fn quicTestHookSourceFiles() []const []const u8 {
    return &.{
        "src/quic/connection_helper_tests.cpp",
        "src/quic/connection_internal_helper_tests.cpp",
        "src/quic/connection_key_update_tests.cpp",
        "src/quic/connection_pmtud_tests.cpp",
        "src/quic/protected_codec_test_hooks.cpp",
    };
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
        "src/http3/http3_protocol.cpp",
        "src/http3/http3_qpack.cpp",
        "src/http3/http3_reverse_proxy.cpp",
        "src/http3/http3_runtime.cpp",
        "src/http3/http3_server.cpp",
    };
}

fn http3ProtocolSourceFiles() []const []const u8 {
    return &.{
        "src/http3/http3_client.cpp",
        "src/http3/http3_connection.cpp",
        "src/http3/http3_demo_routes.cpp",
        "src/http3/http3_protocol.cpp",
        "src/http3/http3_qpack.cpp",
        "src/http3/http3_server.cpp",
    };
}

fn perfSourceFiles() []const []const u8 {
    return &.{
        "bench/coquic-perf/perf_api.cpp",
        "bench/coquic-perf/perf_client.cpp",
        "bench/coquic-perf/perf_loop.cpp",
        "bench/coquic-perf/perf_metrics.cpp",
        "bench/coquic-perf/perf_protocol.cpp",
        "bench/coquic-perf/perf_runtime.cpp",
        "bench/coquic-perf/perf_server.cpp",
    };
}

fn apiSourceFiles() []const []const u8 {
    return &.{
        "src/api/core.cpp",
        "src/api/h3_server.cpp",
        "src/api/http3.cpp",
        "src/api/quic.cpp",
    };
}

fn interopSourceFiles() []const []const u8 {
    return &.{
        "interop/coquic-interop/http09_interop.cpp",
        "interop/coquic-interop/http3_interop.cpp",
        "interop/coquic-interop/interop.cpp",
    };
}

fn coreApiSourceFiles() []const []const u8 {
    return &.{
        "src/api/core.cpp",
    };
}

fn ffiApiSourceFiles() []const []const u8 {
    return &.{
        "src/api/core.cpp",
        "src/api/http3.cpp",
    };
}

fn ffiSourceFiles() []const []const u8 {
    return &.{
        "src/ffi/core.cpp",
        "src/ffi/http3.cpp",
    };
}

fn appendCoreFfiSourceFiles(files: *StringList, tls_backend: []const u8) void {
    appendSourceFiles(files, quicProductionSourceFiles());
    appendPacketCryptoSource(files, tls_backend);
    appendTlsAdapterSource(files, tls_backend);
    appendSourceFiles(files, http3ProtocolSourceFiles());
    appendSourceFiles(files, ffiApiSourceFiles());
    appendSourceFiles(files, ffiSourceFiles());
}

fn packageName(b: *std.Build, tls_backend: []const u8) []const u8 {
    return b.fmt("coquic-{s}", .{tls_backend});
}

fn packageLibraryName(b: *std.Build, tls_backend: []const u8) []const u8 {
    return packageName(b, tls_backend);
}

fn packageSharedSoname(b: *std.Build, library_name: []const u8) []const u8 {
    return b.fmt("lib{s}.so.0", .{library_name});
}

fn packageSharedVersionedName(b: *std.Build, library_name: []const u8) []const u8 {
    return b.fmt("{s}.1.0", .{packageSharedSoname(b, library_name)});
}

fn packageCmakeTargetName(tls_backend: []const u8) []const u8 {
    if (std.mem.eql(u8, tls_backend, "quictls")) {
        return "coquic_quictls";
    }

    if (std.mem.eql(u8, tls_backend, "boringssl")) {
        return "coquic_boringssl";
    }

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

fn addCoreFfiLibrary(
    b: *std.Build,
    name: []const u8,
    linkage: std.builtin.LinkMode,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpp_flags: []const []const u8,
    tls_backend: []const u8,
    tls_include_dir: []const u8,
    tls_lib_dir: []const u8,
    tls_linkage: []const u8,
) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = name,
        .linkage = linkage,
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
        .root_module = picRootModule(b, target, optimize),
    });
    addIncludePath(lib, b.path("."));
    addIncludePath(lib, b.path("include"));
    addIncludePath(lib, .{ .cwd_relative = tls_include_dir });

    var files = StringList.init(b.allocator);
    appendCoreFfiSourceFiles(&files, tls_backend);
    const ffi_cpp_flags = withExtraFlags(b, cpp_flags, &.{
        "-DCOQUIC_FFI_BUILD=1",
        if (linkage == .dynamic)
            "-fvisibility=hidden"
        else
            "-fvisibility=default",
    });
    addCSourceFiles(lib, .{
        .root = b.path("."),
        .files = files.toOwnedSlice() catch @panic("oom"),
        .flags = ffi_cpp_flags,
    });
    if (linkage == .dynamic) {
        linkTlsBackend(b, lib, tls_backend, tls_lib_dir, tls_linkage);
    }
    linkLibCpp(lib);
    lib.installHeader(b.path("include/coquic/ffi/core.h"), "coquic/ffi/core.h");
    lib.installHeader(b.path("include/coquic/ffi/http3.h"), "coquic/ffi/http3.h");
    return lib;
}

fn packageCxxOptimizeFlag(optimize: std.builtin.OptimizeMode) []const u8 {
    return switch (optimize) {
        .Debug => "-O0",
        .ReleaseSafe => "-O2",
        .ReleaseFast => "-O3",
        .ReleaseSmall => "-Os",
    };
}

fn packageCxxDebugFlag(optimize: std.builtin.OptimizeMode) []const u8 {
    return switch (optimize) {
        .Debug => "-g",
        else => "",
    };
}

fn packageCxxNdebugFlag(optimize: std.builtin.OptimizeMode) []const u8 {
    return switch (optimize) {
        .Debug => "",
        else => "-DNDEBUG",
    };
}

fn addCoreFfiPackageLibraries(
    b: *std.Build,
    library_name: []const u8,
    optimize: std.builtin.OptimizeMode,
    profile_hooks: bool,
    tls_backend: []const u8,
    tls_include_dir: []const u8,
    tls_lib_dir: []const u8,
    export_script: std.Build.LazyPath,
) CoreFfiPackageLibraries {
    const script =
        \\static_lib="$1"
        \\shared_lib="$2"
        \\exports="$3"
        \\project_include="$4"
        \\public_include="$5"
        \\tls_include="$6"
        \\tls_lib_dir="$7"
        \\soname="$8"
        \\opt_flag="$9"
        \\debug_flag="${10}"
        \\ndebug_flag="${11}"
        \\profile_hooks="${12}"
        \\shift 12
        \\
        \\cxx="${CXX:-c++}"
        \\ar="${AR:-ar}"
        \\work="$(mktemp -d)"
        \\trap 'rm -rf "$work"' EXIT
        \\
        \\common_flags=(
        \\  -std=c++20
        \\  -fPIC
        \\  -fvisibility=hidden
        \\  "$opt_flag"
        \\  -DCOQUIC_FFI_BUILD=1
        \\  "-DCOQUIC_PROFILE_HOOKS=$profile_hooks"
        \\  "-I$project_include"
        \\  "-I$public_include"
        \\  "-I$tls_include"
        \\)
        \\if [ -n "$debug_flag" ]; then
        \\  common_flags+=("$debug_flag")
        \\fi
        \\if [ -n "$ndebug_flag" ]; then
        \\  common_flags+=("$ndebug_flag")
        \\fi
        \\
        \\objects=()
        \\index=0
        \\for source in "$@"; do
        \\  object="$work/object-$index.o"
        \\  "$cxx" "${common_flags[@]}" -c "$source" -o "$object"
        \\  objects+=("$object")
        \\  index=$((index + 1))
        \\done
        \\
        \\"$ar" rcs "$static_lib" "${objects[@]}"
        \\"$cxx" -shared \
        \\  "-Wl,-soname,$soname" \
        \\  "-Wl,--version-script=$exports" \
        \\  -Wl,--exclude-libs,ALL \
        \\  -o "$shared_lib" \
        \\  "${objects[@]}" \
        \\  "$tls_lib_dir/libssl.a" \
        \\  "$tls_lib_dir/libcrypto.a" \
        \\  -lm -pthread -ldl
        \\
    ;

    const run = b.addSystemCommand(&.{ "bash", "-eu", "-c", script, "coquic-package-cxx" });
    const static_lib = run.addOutputFileArg(b.fmt("lib{s}.a", .{library_name}));
    const shared_lib = run.addOutputFileArg(packageSharedVersionedName(b, library_name));
    run.addFileArg(export_script);
    run.addArgs(&.{
        b.pathFromRoot("."),
        b.pathFromRoot("include"),
        tls_include_dir,
        tls_lib_dir,
        packageSharedSoname(b, library_name),
        packageCxxOptimizeFlag(optimize),
        packageCxxDebugFlag(optimize),
        packageCxxNdebugFlag(optimize),
        if (profile_hooks) "1" else "0",
    });

    var files = StringList.init(b.allocator);
    appendCoreFfiSourceFiles(&files, tls_backend);
    for (files.items) |file| {
        run.addFileArg(b.path(file));
    }

    return .{
        .static_lib = static_lib,
        .shared_lib = shared_lib,
    };
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

fn tlsStaticPrivateLibs(b: *std.Build, package_name: []const u8) []const u8 {
    return b.fmt(
        "${{libdir}}/{s}/private/libssl.a ${{libdir}}/{s}/private/libcrypto.a",
        .{ package_name, package_name },
    );
}

fn packageCmakeConfig(b: *std.Build, package_name: []const u8, library_name: []const u8) []const u8 {
    return b.fmt(
        \\include("${{CMAKE_CURRENT_LIST_DIR}}/{0s}Targets.cmake")
        \\
        \\if(NOT TARGET CoQUIC::{1s})
        \\  message(FATAL_ERROR "CoQUIC target CoQUIC::{1s} was not defined")
        \\endif()
        \\
    , .{ package_name, library_name });
}

fn packageCmakeVersionConfig() []const u8 {
    return
    \\set(PACKAGE_VERSION "0.1.0")
    \\
    \\if(PACKAGE_FIND_VERSION VERSION_GREATER PACKAGE_VERSION)
    \\  set(PACKAGE_VERSION_COMPATIBLE FALSE)
    \\else()
    \\  set(PACKAGE_VERSION_COMPATIBLE TRUE)
    \\  if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
    \\    set(PACKAGE_VERSION_EXACT TRUE)
    \\  endif()
    \\endif()
    \\
    ;
}

fn packageCmakeTargets(b: *std.Build, package_name: []const u8, library_name: []const u8) []const u8 {
    return b.fmt(
        \\include("${{CMAKE_CURRENT_LIST_DIR}}/{0s}Targets-shared.cmake" OPTIONAL)
        \\include("${{CMAKE_CURRENT_LIST_DIR}}/{0s}Targets-static.cmake" OPTIONAL)
        \\
        \\if(NOT TARGET CoQUIC::{1s} AND TARGET CoQUIC::{1s}_shared)
        \\  add_library(CoQUIC::{1s} ALIAS CoQUIC::{1s}_shared)
        \\elseif(NOT TARGET CoQUIC::{1s} AND TARGET CoQUIC::{1s}_static)
        \\  add_library(CoQUIC::{1s} ALIAS CoQUIC::{1s}_static)
        \\endif()
        \\
    , .{ package_name, library_name });
}

fn packageCmakeSharedTargets(b: *std.Build, package_name: []const u8, library_name: []const u8) []const u8 {
    return b.fmt(
        \\add_library(CoQUIC::{1s}_shared SHARED IMPORTED)
        \\set_target_properties(CoQUIC::{1s}_shared PROPERTIES
        \\  IMPORTED_LOCATION "${{CMAKE_CURRENT_LIST_DIR}}/../../lib{0s}.so"
        \\  INTERFACE_INCLUDE_DIRECTORIES "${{CMAKE_CURRENT_LIST_DIR}}/../../../include"
        \\)
        \\
    , .{ package_name, library_name });
}

fn packageCmakeStaticTargets(b: *std.Build, package_name: []const u8, library_name: []const u8) []const u8 {
    return b.fmt(
        \\add_library(CoQUIC::{1s}_static STATIC IMPORTED)
        \\set_target_properties(CoQUIC::{1s}_static PROPERTIES
        \\  IMPORTED_LOCATION "${{CMAKE_CURRENT_LIST_DIR}}/../../lib{0s}.a"
        \\  INTERFACE_INCLUDE_DIRECTORIES "${{CMAKE_CURRENT_LIST_DIR}}/../../../include"
        \\  INTERFACE_LINK_LIBRARIES "${{CMAKE_CURRENT_LIST_DIR}}/../../{0s}/private/libssl.a;${{CMAKE_CURRENT_LIST_DIR}}/../../{0s}/private/libcrypto.a;stdc++;m;pthread;dl"
        \\)
        \\
    , .{ package_name, library_name });
}

fn packagePkgConfig(b: *std.Build, package_name: []const u8, tls_backend: []const u8) []const u8 {
    return b.fmt(
        \\prefix=${{pcfiledir}}/../..
        \\includedir=${{prefix}}/include
        \\libdir=${{prefix}}/lib
        \\
        \\Name: {0s}
        \\Description: CoQUIC C FFI package built with {1s}
        \\Version: 0.1.0
        \\Cflags: -I${{includedir}}
        \\Libs: -L${{libdir}} -l{0s}
        \\Libs.private: {2s} -lstdc++ -lm -lpthread -ldl
        \\
    , .{ package_name, tls_backend, tlsStaticPrivateLibs(b, package_name) });
}

fn packageStaticPkgConfig(b: *std.Build, package_name: []const u8, tls_backend: []const u8) []const u8 {
    return b.fmt(
        \\prefix=${{pcfiledir}}/../..
        \\includedir=${{prefix}}/include
        \\libdir=${{prefix}}/lib
        \\
        \\Name: {0s}-static
        \\Description: Static CoQUIC C FFI package built with {1s}
        \\Version: 0.1.0
        \\Cflags: -I${{includedir}}
        \\Libs: ${{libdir}}/lib{0s}.a {2s} -lstdc++ -lm -lpthread -ldl
        \\
    , .{ package_name, tls_backend, tlsStaticPrivateLibs(b, package_name) });
}

fn ffiExportVersionScript() []const u8 {
    return
    \\{
    \\  global:
    \\    coquic_*;
    \\  local:
    \\    *;
    \\};
    \\
    ;
}

fn packageNotice() []const u8 {
    return
    \\CoQUIC packages include CoQUIC under the terms in LICENSE.coquic.
    \\
    \\The backend-specific packages also redistribute the selected TLS backend:
    \\
    \\- coquic-boringssl bundles BoringSSL libssl and libcrypto archives.
    \\- coquic-quictls bundles QuicTLS/OpenSSL libssl and libcrypto archives.
    \\
    \\Redistributors must include the applicable upstream TLS license and notice
    \\materials from the pinned dependency source when producing release packages.
    \\
    ;
}

fn installCoreFfiPackage(
    b: *std.Build,
    static_lib: std.Build.LazyPath,
    shared_lib: std.Build.LazyPath,
    tls_backend: []const u8,
    tls_lib_dir: []const u8,
) *std.Build.Step {
    const package_name_value = packageName(b, tls_backend);
    const library_name = packageCmakeTargetName(tls_backend);
    const package_library_name = packageLibraryName(b, tls_backend);
    const cmake_dir = b.fmt("lib/cmake/{s}", .{package_name_value});

    const generated = b.addWriteFiles();
    const cmake_config =
        generated.add(b.fmt("{s}Config.cmake", .{package_name_value}), packageCmakeConfig(b, package_name_value, library_name));
    const cmake_version_config =
        generated.add(b.fmt("{s}ConfigVersion.cmake", .{package_name_value}), packageCmakeVersionConfig());
    const cmake_targets =
        generated.add(b.fmt("{s}Targets.cmake", .{package_name_value}), packageCmakeTargets(b, package_name_value, library_name));
    const cmake_shared_targets =
        generated.add(b.fmt("{s}Targets-shared.cmake", .{package_name_value}), packageCmakeSharedTargets(b, package_name_value, library_name));
    const cmake_static_targets =
        generated.add(b.fmt("{s}Targets-static.cmake", .{package_name_value}), packageCmakeStaticTargets(b, package_name_value, library_name));
    const pkg_config =
        generated.add(b.fmt("{s}.pc", .{package_name_value}), packagePkgConfig(b, package_name_value, tls_backend));
    const static_pkg_config =
        generated.add(b.fmt("{s}-static.pc", .{package_name_value}), packageStaticPkgConfig(b, package_name_value, tls_backend));
    const notice = generated.add("NOTICE", packageNotice());

    const install_package = b.step(
        "package",
        "Install backend-specific CoQUIC C FFI libraries and package metadata",
    );
    install_package.dependOn(&b.addInstallFile(static_lib, b.fmt("lib/lib{s}.a", .{
        package_library_name,
    })).step);
    install_package.dependOn(&b.addInstallFile(shared_lib, b.fmt("lib/{s}", .{
        packageSharedVersionedName(b, package_library_name),
    })).step);
    install_package.dependOn(&b.addInstallFile(shared_lib, b.fmt("lib/{s}", .{
        packageSharedSoname(b, package_library_name),
    })).step);
    install_package.dependOn(&b.addInstallFile(shared_lib, b.fmt("lib/lib{s}.so", .{
        package_library_name,
    })).step);
    install_package.dependOn(&b.addInstallFile(
        b.path("include/coquic/ffi/core.h"),
        "include/coquic/ffi/core.h",
    ).step);
    install_package.dependOn(&b.addInstallFile(
        b.path("include/coquic/ffi/http3.h"),
        "include/coquic/ffi/http3.h",
    ).step);
    install_package.dependOn(&b.addInstallFile(cmake_config, b.fmt("{s}/{s}Config.cmake", .{
        cmake_dir,
        package_name_value,
    })).step);
    install_package.dependOn(&b.addInstallFile(cmake_version_config, b.fmt("{s}/{s}ConfigVersion.cmake", .{
        cmake_dir,
        package_name_value,
    })).step);
    install_package.dependOn(&b.addInstallFile(cmake_targets, b.fmt("{s}/{s}Targets.cmake", .{
        cmake_dir,
        package_name_value,
    })).step);
    install_package.dependOn(&b.addInstallFile(cmake_shared_targets, b.fmt("{s}/{s}Targets-shared.cmake", .{
        cmake_dir,
        package_name_value,
    })).step);
    install_package.dependOn(&b.addInstallFile(cmake_static_targets, b.fmt("{s}/{s}Targets-static.cmake", .{
        cmake_dir,
        package_name_value,
    })).step);
    install_package.dependOn(&b.addInstallFile(pkg_config, b.fmt("lib/pkgconfig/{s}.pc", .{
        package_name_value,
    })).step);
    install_package.dependOn(&b.addInstallFile(static_pkg_config, b.fmt("lib/pkgconfig/{s}-static.pc", .{
        package_name_value,
    })).step);
    install_package.dependOn(&b.addInstallFile(
        b.path("LICENSE"),
        b.fmt("share/doc/{s}/LICENSE.coquic", .{package_name_value}),
    ).step);
    install_package.dependOn(&b.addInstallFile(
        notice,
        b.fmt("share/doc/{s}/NOTICE", .{package_name_value}),
    ).step);
    if (b.graph.environ_map.get("COQUIC_TLS_LICENSE_FILE")) |license_file| {
        install_package.dependOn(&b.addInstallFile(
            .{ .cwd_relative = license_file },
            b.fmt("share/doc/{s}/LICENSE.tls", .{package_name_value}),
        ).step);
    }
    if (b.graph.environ_map.get("COQUIC_TLS_NOTICE_FILE")) |notice_file| {
        install_package.dependOn(&b.addInstallFile(
            .{ .cwd_relative = notice_file },
            b.fmt("share/doc/{s}/NOTICE.tls", .{package_name_value}),
        ).step);
    }
    install_package.dependOn(&b.addInstallFile(
        .{ .cwd_relative = b.pathJoin(&.{ tls_lib_dir, "libssl.a" }) },
        b.fmt("lib/{s}/private/libssl.a", .{package_name_value}),
    ).step);
    install_package.dependOn(&b.addInstallFile(
        .{ .cwd_relative = b.pathJoin(&.{ tls_lib_dir, "libcrypto.a" }) },
        b.fmt("lib/{s}/private/libcrypto.a", .{package_name_value}),
    ).step);
    return install_package;
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
    extra_source_files: []const []const u8,
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
    if (extra_source_files.len != 0) {
        addCSourceFiles(test_exe, .{
            .root = b.path("."),
            .files = extra_source_files,
            .flags = cpp_flags,
        });
    }
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
        "-Wno-error=unicode",
        "-Wno-error=character-conversion",
    });
    const spdlog_cpp_flags = withSpdlogFlags(b, cpp_flags, spdlog_shared);
    const coverage_cpp_flags = withExtraFlags(b, cpp_flags, &.{
        "-DCOQUIC_COVERAGE_BUILD=1",
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
        "tests/ffi/http3_ffi_test.cpp",
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

    const interop_exe = b.addExecutable(.{
        .name = "coquic-interop",
        .root_module = rootModule(b, target, optimize),
    });
    addIncludePath(interop_exe, b.path("."));
    addIncludePath(interop_exe, b.path("include"));
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
    const ffi_export_script = b.addWriteFiles().add("coquic-ffi.exports", ffiExportVersionScript());
    const ffi_package_libs = addCoreFfiPackageLibraries(
        b,
        packageLibraryName(b, tls_backend),
        optimize,
        profile_hooks,
        tls_backend,
        tls_include_dir,
        tls_lib_dir,
        ffi_export_script,
    );
    _ = installCoreFfiPackage(
        b,
        ffi_package_libs.static_lib,
        ffi_package_libs.shared_lib,
        tls_backend,
        tls_lib_dir,
    );
    addCSourceFiles(interop_exe, .{
        .root = b.path("."),
        .files = &.{"interop/coquic-interop/main.cpp"},
        .flags = cpp_flags,
    });
    addCSourceFiles(interop_exe, .{
        .root = b.path("."),
        .files = interopSourceFiles(),
        .flags = cpp_flags,
    });
    linkLibrary(interop_exe, project_lib);
    linkTlsBackend(b, interop_exe, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(interop_exe);
    linkLiburing(interop_exe);
    linkLibCpp(interop_exe);
    b.installArtifact(interop_exe);

    const h3_server_exe = b.addExecutable(.{
        .name = "h3-server",
        .root_module = rootModule(b, target, optimize),
    });
    addIncludePath(h3_server_exe, b.path("include"));
    addCSourceFiles(h3_server_exe, .{
        .root = b.path("."),
        .files = &.{"examples/h3-server/main.cpp"},
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
    addIncludePath(perf_exe, b.path("include"));
    addCSourceFiles(perf_exe, .{
        .root = b.path("."),
        .files = &.{"bench/coquic-perf/main.cpp"},
        .flags = cpp_flags,
    });
    linkLibrary(perf_exe, project_lib);
    linkTlsBackend(b, perf_exe, tls_backend, tls_lib_dir, tls_linkage);
    linkSpdlog(perf_exe);
    linkLiburing(perf_exe);
    linkLibCpp(perf_exe);
    b.installArtifact(perf_exe);

    const run_exe = b.addRunArtifact(interop_exe);
    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    const run_step = b.step("run", "Run the coquic-interop executable");
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
        &.{},
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
        &.{},
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
        &.{"interop/coquic-interop/http09_interop.cpp"},
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
        &.{"interop/coquic-interop/http3_interop.cpp"},
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
        &.{},
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
        &.{},
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
        &.{},
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
    compdb_step.dependOn(&interop_exe.step);
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
    const coverage_extra_sources = &.{
        "interop/coquic-interop/http09_interop.cpp",
        "interop/coquic-interop/http3_interop.cpp",
    };

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
        coverage_extra_sources,
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
