# Python Wrapper

The Python wrapper under `bindings/python` exposes the public CoQUIC C FFI with
`ctypes` and provides a small ergonomic QUIC facade in `coquic.quic`.

The package name is `coquic`. It is currently an in-tree wrapper, and
`bench/coquic-python-perf` is the reference Python runtime using it.

The wrapper remains sans-I/O. Python callers own UDP sockets, timers, route
tables, file I/O, threads, and scheduling. CoQUIC methods consume inputs and
return immutable result values containing effects for the runtime to process.

## Build

Build a C FFI backend package first:

```sh
nix develop .#quictls -c zig build package -Dtls_backend=quictls -Doptimize=ReleaseFast
```

Then run Python with the wrapper and selected shared library on the search path:

```sh
nix develop -c bash -lc 'COQUIC_LIB_DIR="$PWD/zig-out/lib" COQUIC_LIB_NAME=coquic-quictls PYTHONPATH="$PWD/bindings/python" python3 -c "import coquic; print(coquic.TransportConfig.default())"'
```

The wrapper loads the shared library in this order:

- `COQUIC_LIB_PATH`: exact shared-library path.
- `COQUIC_LIB_DIR` plus `COQUIC_LIB_NAME`.
- Repository-local `zig-out/lib/libcoquic-boringssl.so` and
  `zig-out/lib/libcoquic-quictls.so`.
- `ctypes.util.find_library()` for `coquic-boringssl`, `coquic-quictls`, and
  `coquic`.

`COQUIC_LIB_NAME` defaults to `coquic-boringssl` when `COQUIC_LIB_DIR` is set,
so set it explicitly when using a quictls package.

## Low-Level Surface

`coquic._core` is re-exported from `coquic` and mirrors the C FFI value model:

- Type aliases: `ConnectionHandle`, `RouteHandle`, `StreamId`, and `TimeUs`.
- Enumerations: `Status`, `Role`, `CongestionControl`, `EcnCodepoint`,
  `StateChange`, `LocalErrorCode`, `Lifecycle`, `MigrationReason`,
  `ZeroRttStatus`, `PacketInspectionDirection`, and
  `PacketInspectionPacketType`.
- Config dataclasses: `TlsIdentity`, `ZeroRttConfig`, `TransportConfig`,
  `EndpointConfig`, `ResumptionState`, `ClientConnectionConfig`, and
  `OpenConnection`.
- Input dataclasses: `InboundDatagram`, `PathMtuUpdate`, `SendStreamData`,
  `SendDatagramData`, `ResetStream`, `StopSending`, `CloseConnection`,
  `RequestConnectionMigration`, and `ConnectionInput`.
- Output dataclasses: `QueryResult`, `Effect`, `LocalError`,
  `PreferredAddress`, and `PacketInspection`.
- `Endpoint`, the low-level handle owner.

`TransportConfig.default()`, `EndpointConfig.default()`, and
`ClientConnectionConfig.default()` obtain defaults from the native library.
`EndpointConfig.http3_client()` and `EndpointConfig.http3_server()` prepare
basic HTTP/3 ALPN endpoint configs.

`Endpoint` owns the native `coquic_endpoint_t` handle and releases it from
`close_handle()` or object finalization. All endpoint methods raise
`CoquicStatusError` for non-OK FFI status values.

## QUIC Facade

`coquic.quic` wraps the low-level endpoint with handle-oriented helpers:

- `quic.EndpointConfig`, containing the low-level core endpoint config.
- `quic.ClientConfig`, including client connection config, initial route
  handle, and address-validation identity.
- `quic.Endpoint`, with `connect`, `receive_datagram`, `update_path_mtu`,
  `timer_expired`, `connection_count`, `next_wakeup`, and
  `has_send_continuation_pending`.
- `quic.Connection`, with `advance`, `send_stream`, `send_datagram`,
  `reset_stream`, `stop_sending`, `close`, `request_key_update`, and
  `request_migration`.
- `quic.Stream`, with `send`, `finish`, `reset`, and `stop_sending`.

Example:

```python
import coquic
from coquic import quic

core_config = coquic.EndpointConfig.default()
core_config.role = coquic.Role.CLIENT
core_config.application_protocol = b"coquic-perf/1"
core_config.max_outbound_datagram_size = 60 * 1024

endpoint = quic.Endpoint(quic.EndpointConfig(core=core_config))
client = quic.ClientConfig.new(
    b"\xc1\x00\x00\x00\x00\x00\x00\x01",
    b"\x83\x00\x00\x00\x00\x00\x00\x41",
)
client.initial_route_handle = 7

connect = endpoint.connect(client, now_us())
process_result(connect.result)
```

Feed inbound UDP datagrams and timers through the endpoint:

```python
result = endpoint.receive_datagram(
    coquic.InboundDatagram(
        bytes=udp_payload,
        route_handle=route_handle,
        address_validation_identity=address_validation_identity,
        ecn=coquic.EcnCodepoint.UNAVAILABLE,
    ),
    now_us(),
)
process_result(result)
```

## Results

`QueryResult` contains:

- `effects`: tuple of `Effect` values.
- `next_wakeup`: next endpoint deadline in microseconds, or `None`.
- `local_error`: synchronous local error details, or `None`.
- `send_continuation_pending`: whether the runtime should call back without
  blocking so pending send work can continue.

`Effect.kind` is a string, including `send_datagram`, `receive_stream_data`,
`receive_datagram_data`, `peer_reset_stream`, `peer_stop_sending`,
`state_event`, `connection_lifecycle_event`,
`peer_preferred_address_available`, `resumption_state_available`,
`zero_rtt_status_event`, `packet_inspection`, and `new_token_available`.

`send_datagram` is the only network output. The runtime must send every returned
datagram through its UDP socket, preserving `route_handle`, `ecn`, and
`is_pmtu_probe` metadata when the socket layer supports them.

The Python wrapper copies C result views into immutable Python dataclasses and
destroys the native C result before returning. Bytes inside `Effect`,
`LocalError`, and diagnostic values can outlive the endpoint call.

## Runtime Integration

A Python runtime loop should:

1. Read UDP datagrams from Python sockets or an async runtime.
2. Map socket peer/local address state to a stable route handle.
3. Call `endpoint.receive_datagram()` for each inbound datagram.
4. Send every `send_datagram` effect.
5. Deliver stream, DATAGRAM, lifecycle, token, resumption, 0-RTT, and diagnostic
   effects to the application.
6. Arm the next timer from `result.next_wakeup` or `endpoint.next_wakeup()`.
7. Call `endpoint.timer_expired()` when that timer fires.
8. If `send_continuation_pending` or
   `endpoint.has_send_continuation_pending()` is true, re-enter the endpoint
   without waiting for more socket input.

Use one monotonic microsecond clock for all calls on an endpoint.

## Perf Runtime

`bench/coquic-python-perf` is the reference Python runtime. It maps UDP sockets
to route handles, feeds CoQUIC inputs, sends returned datagrams, and implements
the `coquic-perf/1` benchmark protocol.

Example:

```sh
nix develop .#quictls -c bash -lc 'COQUIC_LIB_DIR="$PWD/zig-out/lib" COQUIC_LIB_NAME=coquic-quictls PYTHONPATH="$PWD/bindings/python:$PWD/bench/coquic-python-perf" python3 -m coquic_python_perf server --host 127.0.0.1 --port 4433'
nix develop .#quictls -c bash -lc 'COQUIC_LIB_DIR="$PWD/zig-out/lib" COQUIC_LIB_NAME=coquic-quictls PYTHONPATH="$PWD/bindings/python:$PWD/bench/coquic-python-perf" python3 -m coquic_python_perf client --host 127.0.0.1 --port 4433 --mode bulk --direction download --total-bytes 1048576'
```

## Stability

The Python wrapper tracks `COQUIC_FFI_ABI_VERSION` in `coquic._ffi`. Check
`coquic._ffi.load_library().coquic_ffi_abi_version()` at startup when loading a
shared library from a nonstandard path or when package provenance is unclear.
