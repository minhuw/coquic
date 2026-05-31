# Runtime Integration

CoQUIC is driven by the caller runtime. The library does not own the event loop,
UDP sockets, timers, worker threads, or persistent storage.

## Event Loop

A typical runtime loop:

1. Read UDP datagrams from the socket.
2. Convert each datagram to `coquic::core::InboundDatagram`.
3. Call `Endpoint::input_datagram` or `quic::Endpoint::receive_datagram`.
4. Send every returned `SendDatagram` effect.
5. Dispatch stream, DATAGRAM, lifecycle, state, token, qlog, and diagnostic
   effects to the application.
6. Arm the next timer from `Result::next_wakeup` or `Endpoint::next_wakeup`.
7. On timer expiry, call `timer_expired`.
8. For application writes, call `advance_connection` or the `quic::Connection`
   and `quic::Stream` helpers.

Every endpoint method takes `coquic::core::TimePoint`. Use one monotonic runtime
clock consistently for all calls on an endpoint.

## Sending Datagrams

`SendDatagram` effects are the only network output. The runtime sends:

- `bytes`: UDP payload.
- `route_handle`: selected local route, if present.
- `ecn`: ECN codepoint requested by the endpoint.
- `is_pmtu_probe`: whether the datagram is a PMTU probe.

Send all produced datagrams before waiting for more socket or timer input. If
`send_continuation_pending` or `Endpoint::has_send_continuation_pending()` is
true, call back into the endpoint without blocking so pending send work can
continue.

## Timers

Always arm the runtime timer from the most recent result:

- Prefer `Result::next_wakeup` when processing a call result.
- Use `Endpoint::next_wakeup()` when the runtime needs the current endpoint
  deadline outside a call result.
- If no wakeup is present, no timer is currently needed.

Timer callbacks should call `timer_expired(now)` and process the returned
effects exactly like network or application input.

## Errors

`core::LocalError` reports synchronous API misuse or locally detected failure.
It does not send UDP bytes by itself. Treat it as an application signal and keep
processing any returned effects that are valid for the call.

For HTTP/3, `terminal_failure` and `has_failed()` report protocol-layer failure.
Request-level failures are returned as request error or cancellation events.

## Checklist

- Include public headers from `include/coquic/`.
- Do not include internal headers from `src/`.
- Keep one monotonic clock source per endpoint.
- Preserve route-handle identity between inbound datagrams and outbound sends.
- Send every `SendDatagram` effect.
- Re-arm the timer after each endpoint call.
- Feed HTTP/3 `quic_inputs` to the matching QUIC connection.
- Persist resumption state and address-validation tokens only if the
  application wants to reuse them.
- Treat diagnostics as observability data, not protocol commands.

## Build Notes

Inside this repository, `zig build` adds `include/` to the project library,
executables, and tests. Public API smoke tests live in
`tests/api/public_api_test.cpp` and are run by:

```bash
nix develop -c zig build test
```

Packaging and installation of exported headers for external consumers is still
separate from the in-repo build.
