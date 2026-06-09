# JavaScript Wrapper

The JavaScript binding under `bindings/javascript` exposes the CoQUIC sans-I/O
QUIC facade to Node.js through the public C FFI and a small N-API addon.

The package is `@coquic/coquic`. It is currently private and in-tree, and the
`bench/coquic-js-perf` runner consumes it as the JavaScript runtime example.

The wrapper remains sans-I/O. JavaScript callers own UDP sockets, timers, route
tables, file I/O, workers, and scheduling. CoQUIC methods consume inputs and
return result objects containing effects for the runtime to process.

## Build

Build a C FFI backend package first:

```sh
nix develop .#quictls -c zig build package -Dtls_backend=quictls -Doptimize=ReleaseFast
```

Then build and test the Node.js addon:

```sh
nix develop -c bash -lc 'npm --prefix bindings/javascript run build'
nix develop -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" npm --prefix bindings/javascript test'
```

The build script uses Node.js N-API and searches for `node_api.h` from the
active Node installation. Set `NODE_INCLUDE_DIR` if the header is installed
outside the usual include paths.

By default the addon links `coquic-quictls` from `zig-out/lib`. Override the
selection with:

- `COQUIC_TLS_BACKEND`: backend suffix used to form `coquic-$COQUIC_TLS_BACKEND`.
- `COQUIC_LIB_NAME`: exact library name without `lib` or extension.
- `COQUIC_LIB_DIR`: directory containing the selected shared library.
- `CXX`: C++ compiler used for the N-API addon.

The generated addon embeds an rpath for the selected library directory. Runtime
launchers can still set `LD_LIBRARY_PATH` when running from a different layout.

## Surface

`index.js` exports constants and classes that mirror the C FFI value model:

- `FFI_ABI_VERSION` and `ffiAbiVersion()`.
- Enumerations: `Status`, `Role`, `CongestionControl`, `EcnCodepoint`,
  `StateChange`, `LocalErrorCode`, `Lifecycle`, `MigrationReason`,
  `ZeroRttStatus`, `PacketInspectionDirection`, and
  `PacketInspectionPacketType`.
- Config builders: `TlsIdentity`, `ZeroRttConfig`, `TransportConfig`,
  `EndpointConfig`, `ResumptionState`, `ClientConnectionConfig`, and
  `ClientConfig`.
- Runtime inputs and handles: `InboundDatagram`, `Endpoint`, `Connection`, and
  `Stream`.
- `quic`, a namespace object that re-exports the high-level QUIC classes.

Byte fields accept `Buffer`, `ArrayBuffer`, typed arrays, arrays of byte values,
or strings. The wrapper copies input bytes before entering the C FFI.

64-bit QUIC values are represented as JavaScript `number` when the value is
inside the safe integer range and as `bigint` when needed. Callers should accept
both forms for connection handles, stream IDs, route handles, packet numbers,
and microsecond timestamps.

## Endpoint Flow

Create an endpoint from `EndpointConfig`:

```js
import * as coquic from "@coquic/coquic";

const endpoint = new coquic.Endpoint(
  new coquic.EndpointConfig({
    role: coquic.Role.CLIENT,
    applicationProtocol: "coquic-perf/1",
    maxOutboundDatagramSize: 60 * 1024,
  }),
);
```

Open a client connection with `Endpoint.connect()`:

```js
const client = coquic.ClientConfig.new(
  Buffer.from([0xc1, 0, 0, 0, 0, 0, 0, 1]),
  Buffer.from([0x83, 0, 0, 0, 0, 0, 0, 0x41]),
);
client.initialRouteHandle = 7n;

const { connection, result } = endpoint.connect(client, nowUs());
processResult(result);
```

Feed inbound UDP datagrams with `receiveDatagram()` and timers with
`timerExpired()`:

```js
const result = endpoint.receiveDatagram(
  new coquic.InboundDatagram({
    bytes: udpPayload,
    routeHandle,
    addressValidationIdentity,
    ecn: coquic.EcnCodepoint.UNAVAILABLE,
  }),
  nowUs(),
);
processResult(result);
```

Application writes use connection and stream helpers:

- `Connection.sendStream(streamId, data, fin, now, priority = 0)`.
- `Connection.sendDatagram(data, now, priority = 0)`.
- `Connection.close(applicationErrorCode, reasonPhrase, now)`.
- `Stream.send(data, fin, now, priority = 0)`.
- `Stream.finish(now)`.

The wrapper also provides snake_case aliases for selected endpoint methods:
`receive_datagram`, `timer_expired`, `connection_count`, `next_wakeup`, and
`has_send_continuation_pending`.

## Results

Endpoint and connection methods return plain JavaScript result objects:

- `effects`: array of effect objects.
- `nextWakeup`: next endpoint deadline in microseconds, or `null`.
- `localError`: synchronous local error details, or `null`.
- `sendContinuationPending`: whether the runtime should call back without
  blocking so pending send work can continue.

Effect objects use a string `kind`, including `send_datagram`,
`receive_stream_data`, `receive_datagram_data`, `peer_reset_stream`,
`peer_stop_sending`, `state_event`, `connection_lifecycle_event`,
`peer_preferred_address_available`, `resumption_state_available`,
`zero_rtt_status_event`, `packet_inspection`, and `new_token_available`.

`send_datagram` is the only network output. The runtime must send every returned
datagram through its UDP socket, preserving `routeHandle`, `ecn`, and
`isPmtuProbe` metadata when the socket layer supports them.

The native addon converts C result views to JavaScript objects immediately and
destroys the C result before returning. Byte payloads in returned effects are
Node `Buffer` copies and can outlive the endpoint call.

## Runtime Integration

A JavaScript runtime loop should:

1. Read UDP datagrams from Node sockets.
2. Map socket peer/local address state to a stable route handle.
3. Call `endpoint.receiveDatagram()` for each inbound datagram.
4. Send every `send_datagram` effect.
5. Deliver stream, DATAGRAM, lifecycle, token, resumption, 0-RTT, and diagnostic
   effects to the application.
6. Arm the next timer from `result.nextWakeup` or `endpoint.nextWakeup()`.
7. Call `endpoint.timerExpired()` when that timer fires.
8. If `sendContinuationPending` or `endpoint.hasSendContinuationPending()` is
   true, re-enter the endpoint without waiting for more socket input.

Use one monotonic microsecond clock for all calls on an endpoint.

## Perf Runtime

`bench/coquic-js-perf` is the reference Node.js runtime. It maps UDP sockets to
route handles, feeds CoQUIC inputs, sends returned datagrams, and implements the
`coquic-perf/1` benchmark protocol.

Example:

```sh
nix develop -c bash -lc 'npm --prefix bench/coquic-js-perf install'
nix develop .#quictls -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" npm --prefix bench/coquic-js-perf exec -- coquic-js-perf server --host 127.0.0.1 --port 4433'
nix develop .#quictls -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" npm --prefix bench/coquic-js-perf exec -- coquic-js-perf client --host 127.0.0.1 --port 4433 --mode bulk --direction download --total-bytes 1048576'
```

## Stability

The addon checks `COQUIC_FFI_ABI_VERSION` when creating endpoints. Call
`ffiAbiVersion()` at startup when package provenance is unclear or when loading
a shared library from a nonstandard location.
