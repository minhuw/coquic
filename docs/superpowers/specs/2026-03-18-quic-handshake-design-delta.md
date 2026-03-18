# QUIC Handshake Design Delta: TLS Backend Blocker

## Date

2026-03-18

## Why This Delta Exists

During Task 2 of `docs/superpowers/plans/2026-03-18-quic-handshake.md`, I
probed the actual OpenSSL 3.4.3 installation in the current Nix shell to verify
that `TlsAdapter` can exchange real QUIC TLS handshake bytes under application
control.

The result is a blocker for the current backend choice.

## Evidence Collected

Available public headers expose:

- `SSL_set_msg_callback`
- `SSL_CTX_add_custom_ext`
- `SSL_CTX_set_keylog_callback`
- `SSL_is_quic`
- `OSSL_QUIC_client_method`
- `SSL_handle_events`
- `SSL_set_connect_state`
- `SSL_set_accept_state`

But the installed headers and exported `libssl.so` symbols do not expose the raw
QUIC/TLS control points needed for a custom client+server QUIC packetization
layer, including:

- `SSL_provide_quic_data`
- `SSL_process_quic_post_handshake`
- `SSL_set_quic_method`
- `SSL_set_quic_tls_cbs`
- any visible `OSSL_QUIC_server_method`

## Impact On The Current Plan

The approved architecture requires `TlsAdapter` to:

- accept handshake bytes by QUIC encryption level
- emit outbound handshake bytes by QUIC encryption level
- surface transport parameters
- surface handshake and 1-RTT traffic secrets
- do this for both client and server while `QuicConnection` retains ownership
  of QUIC packetization

With the current OpenSSL 3.4.3 public surface, I do not have a supported way to
feed and drain raw QUIC CRYPTO-stream handshake bytes for both endpoints under
our own packetization logic.

Generic TLS-over-BIO would only prove record-layer TLS, not QUIC CRYPTO-stream
integration, so using it here would create false confidence and violate the
intent of the probe.

## Recommended Adjustment

Keep the `QuicCore` / `QuicConnection` / codec layering from the approved spec,
but change the TLS backend assumption before continuing implementation.

Recommended options, in order:

1. Switch to a TLS backend with a supported QUIC integration surface for custom
   packetization, such as BoringSSL, quictls, or picotls.
2. If you want to stay on stock OpenSSL 3.4.3, reduce the milestone so the next
   slice is only transport-parameter and CRYPTO buffering groundwork, not a real
   end-to-end QUIC handshake.

## Execution Status

Completed:

- isolated worktree setup
- clean baseline verification (`nix develop -c zig build test` passed with 196
  tests)
- Task 1 scaffolding and red test for `TlsAdapter`
- backend probe and blocker confirmation

Stopped before:

- implementing `TlsAdapter`
- touching `QuicConnection`
- touching `QuicCore`

