# Go Wrapper

The Go wrapper under `bindings/go` exposes the public CoQUIC C FFI through
cgo. It provides a small handle-oriented QUIC facade for Go runtimes and is
consumed by the `bench/coquic-go-perf` reference runner.

The module is `github.com/minhuw/coquic/bindings/go`, with the wrapper package
at `github.com/minhuw/coquic/bindings/go/coquic`.

The wrapper remains sans-I/O. Go callers own UDP sockets, timers, route tables,
file I/O, goroutines, and scheduling. CoQUIC methods consume inputs and return
query results containing effects for the runtime to process.

## Build

Build a C FFI backend package first:

```sh
nix develop .#quictls -c zig build package -Dtls_backend=quictls -Doptimize=ReleaseFast
```

Then run the Go wrapper tests:

```sh
nix develop -c bash -lc 'cd bindings/go && LD_LIBRARY_PATH="$PWD/../../zig-out/lib:$LD_LIBRARY_PATH" go test ./...'
```

By default the cgo directives link `coquic-quictls` from `zig-out/lib`.
Build with the `boringssl` tag to link `coquic-boringssl`:

```sh
nix develop -c bash -lc 'cd bindings/go && LD_LIBRARY_PATH="$PWD/../../zig-out/lib:$LD_LIBRARY_PATH" go test -tags boringssl ./...'
```

The package includes headers from the repository `include/` directory and links
against the repository-local `zig-out/lib` directory. Consumers outside this
source tree should provide equivalent cgo include and library paths or package
the C FFI SDK first.

## Surface

The `coquic` Go package exposes:

- Constants and aliases: `FFIABIVersion`, `ConnectionHandle`, `RouteHandle`,
  `StreamID`, and `TimeUs`.
- Status handling: `Status`, `StatusError`, and `CheckFFIABIVersion()`.
- Enumerations: `Role`, `CongestionControl`, `EcnCodepoint`, `StateChange`,
  `LocalErrorCode`, and `Lifecycle`.
- Config structs: `TlsIdentity`, `ZeroRttConfig`, `TransportConfig`,
  `EndpointConfig`, and `ClientConfig`.
- Input structs: `InboundDatagram` and `SendStreamData`.
- Runtime owners and outputs: `Endpoint`, `QueryResult`, `LocalError`, and
  `Effect`.

`DefaultTransportConfig()` and `DefaultEndpointConfig()` obtain defaults from
the native library. `NewClientConfig()` prepares source and initial destination
connection IDs and sets a default server name of `localhost`.

`NewEndpoint()` checks the FFI ABI version, creates the native endpoint, and
installs a finalizer. Call `Destroy()` explicitly when the endpoint lifetime is
known; the finalizer is a cleanup fallback.

## Endpoint Flow

Create an endpoint from `EndpointConfig`:

```go
package main

import coquic "github.com/minhuw/coquic/bindings/go/coquic"

func openEndpoint() (*coquic.Endpoint, error) {
    config := coquic.DefaultEndpointConfig()
    config.Role = coquic.RoleClient
    config.ApplicationProtocol = []byte("coquic-perf/1")
    config.MaxOutboundDatagramSize = 60 * 1024
    return coquic.NewEndpoint(config)
}
```

Open a client connection with `Endpoint.Connect()`:

```go
client := coquic.NewClientConfig(
    []byte{0xc1, 0, 0, 0, 0, 0, 0, 1},
    []byte{0x83, 0, 0, 0, 0, 0, 0, 0x41},
)
client.InitialRouteHandle = 7
client.AddressValidationIdentity = []byte{0x04, 127, 0, 0, 1, 0x11, 0x51}

connection, result, err := endpoint.Connect(client, nowUs())
if err != nil {
    return err
}
defer result.Destroy()
processResult(result)
```

Feed inbound UDP datagrams and timers through the endpoint:

```go
result, err := endpoint.ReceiveDatagram(coquic.InboundDatagram{
    Bytes:                     udpPayload,
    RouteHandle:               routeHandle,
    HasRouteHandle:            true,
    AddressValidationIdentity: addressValidationIdentity,
    Ecn:                       coquic.EcnUnavailable,
}, nowUs())
if err != nil {
    return err
}
defer result.Destroy()
processResult(result)
```

Application writes use:

- `Endpoint.SendStream(connection, streamID, data, fin, now)`.
- `Endpoint.SendStreamWithPriority(connection, SendStreamData, now)`.
- `Endpoint.CloseConnection(connection, applicationErrorCode, reason, now)`.

Endpoint state helpers include `NextWakeup()`, `ConnectionCount()`,
`HasSendContinuationPending()`, and `HasPendingStreamSend()`.

## Results

`QueryResult` owns the native `coquic_result_t`. Call `Destroy()` when finished;
the finalizer is a cleanup fallback.

Use:

- `Effects()` to copy result effects into a Go slice.
- `LocalError()` to inspect synchronous local errors.
- `NextWakeup()` to obtain the next endpoint deadline.
- `SendContinuationPending()` to determine whether the runtime should call back
  without blocking so pending send work can continue.

`Effect.Kind` can be `EffectSendDatagram`, `EffectReceiveStreamData`,
`EffectReceiveDatagramData`, `EffectPeerResetStream`,
`EffectPeerStopSending`, `EffectStateEvent`, or
`EffectConnectionLifecycleEvent`.

`send_datagram` is the only network output. The runtime must send every
`EffectSendDatagram` payload through its UDP socket, preserving `RouteHandle`,
`Ecn`, and `IsPMTUProbe` metadata when the socket layer supports them.

`Effects()` copies byte payloads out of the native result, so returned
`Effect.Bytes` slices can outlive the `QueryResult`. Destroy the result after
copying effects and metadata needed by the application.

## Runtime Integration

A Go runtime loop should:

1. Read UDP datagrams from `net.PacketConn`, `net.UDPConn`, or another socket
   backend.
2. Map socket peer/local address state to a stable route handle.
3. Call `endpoint.ReceiveDatagram()` for each inbound datagram.
4. Send every `EffectSendDatagram` effect.
5. Deliver stream, DATAGRAM, lifecycle, state, and local-error effects to the
   application.
6. Arm the next timer from `result.NextWakeup()` or `endpoint.NextWakeup()`.
7. Call `endpoint.TimerExpired()` when that timer fires.
8. If `result.SendContinuationPending()` or
   `endpoint.HasSendContinuationPending()` is true, re-enter the endpoint
   without waiting for more socket input.

Use one monotonic microsecond clock for all calls on an endpoint.

## Perf Runtime

`bench/coquic-go-perf` is the reference Go runtime. It maps UDP sockets to route
handles, feeds CoQUIC inputs, sends returned datagrams, and implements the
`coquic-perf/1` benchmark protocol.

Example:

```sh
nix develop .#quictls -c bash -lc 'cd bench/coquic-go-perf && LD_LIBRARY_PATH="$PWD/../../zig-out/lib:$LD_LIBRARY_PATH" go run ./cmd/coquic-go-perf server --host 127.0.0.1 --port 4433'
nix develop .#quictls -c bash -lc 'cd bench/coquic-go-perf && LD_LIBRARY_PATH="$PWD/../../zig-out/lib:$LD_LIBRARY_PATH" go run ./cmd/coquic-go-perf client --host 127.0.0.1 --port 4433 --mode bulk --direction download --total-bytes 1048576'
```

Use `-tags boringssl` with `go test`, `go run`, or `go build` when linking the
BoringSSL backend.

## Stability

The Go wrapper tracks `COQUIC_FFI_ABI_VERSION` as `FFIABIVersion`.
`NewEndpoint()` calls `CheckFFIABIVersion()` automatically. Call it explicitly at
startup when package provenance is unclear or when cgo is pointed at a
nonstandard shared library.
