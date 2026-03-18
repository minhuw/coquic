# QUIC Handshake Backend Pivot Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the QUIC handshake engine using a build-time-selectable QUIC-capable TLS backend, with `quictls` first and `boringssl` second, while keeping `QuicCore` and `QuicConnection` backend-agnostic.

**Architecture:** Preserve the approved `QuicCore` / `QuicConnection` / codec layering, but replace the old stock-OpenSSL assumption with a backend-neutral `TlsAdapter` seam selected by `build.zig`. Land a full end-to-end handshake on `quictls` first, then add `boringssl` support against the same TLS contract tests and handshake integration tests.

**Tech Stack:** C++20, Zig build options, existing QUIC packet/crypto codecs in `src/quic/`, `quictls`, `BoringSSL`, GoogleTest, RFC 9000 and RFC 9001

---

## Supersedes

- `docs/superpowers/plans/2026-03-18-quic-handshake.md`

Use this plan instead of the earlier OpenSSL-based execution path.

## File Map

- Modify: `flake.nix`
  - Add build inputs for `quictls` and `BoringSSL` selection.
- Modify: `build.zig`
  - Add `-Dtls_backend=quictls|boringssl`, select include/link settings, and compile backend-specific sources.
- Modify: `src/coquic.h`
  - Export the final `QuicCore` API.
- Create: `src/quic/core.h`
  - Declare `QuicCore` and `QuicCoreConfig`.
- Create: `src/quic/core.cpp`
  - Implement the public wrapper.
- Create: `src/quic/connection.h`
  - Declare `QuicConnection`, packet-space state, and handshake status.
- Create: `src/quic/connection.cpp`
  - Implement connection-level handshake orchestration.
- Create: `src/quic/crypto_stream.h`
  - Declare CRYPTO send/reassembly helpers.
- Create: `src/quic/crypto_stream.cpp`
  - Implement CRYPTO buffering logic.
- Create: `src/quic/transport_parameters.h`
  - Declare minimal transport-parameter types and validators.
- Create: `src/quic/transport_parameters.cpp`
  - Implement transport-parameter serialization, parsing, and validation.
- Modify: `src/quic/tls_adapter.h`
  - Keep the backend-neutral seam only.
- Create: `src/quic/tls_adapter_quictls.cpp`
  - Implement the `quictls` backend.
- Create: `src/quic/tls_adapter_boringssl.cpp`
  - Implement the `boringssl` backend.
- Modify or Split: `src/quic/packet_crypto.cpp`
  - Keep `quictls` compatibility or split backend-specific crypto if needed.
- Create: `tests/quic_tls_adapter_contract_test.cpp`
  - Backend-neutral TLS seam contract tests.
- Create: `tests/quic_transport_parameters_test.cpp`
  - Transport-parameter tests.
- Create: `tests/quic_crypto_stream_test.cpp`
  - CRYPTO buffering tests.
- Create: `tests/quic_core_test.cpp`
  - End-to-end handshake tests through `QuicCore`.
- Modify: `tests/quic_test_utils.h`
  - Shared handshake fixtures and config builders.
- Reuse: `tests/fixtures/quic-server-cert.pem`
- Reuse: `tests/fixtures/quic-server-key.pem`

## Execution Notes

- Follow `@superpowers:test-driven-development` task by task.
- Use `quictls` as the default backend during the first green path.
- Treat `boringssl` support as required, but land it after the `quictls`
  handshake is already passing.
- If `BoringSSL` forces a `packet_crypto` split, do that explicitly instead of
  hiding backend-specific crypto conditionals throughout one file.

### Task 1: Add Build-Time TLS Backend Selection And Contract-Test Scaffolding

**Files:**
- Modify: `flake.nix`
- Modify: `build.zig`
- Modify: `src/quic/tls_adapter.h`
- Create: `tests/quic_tls_adapter_contract_test.cpp`

- [ ] **Step 1: Write the failing backend-neutral TLS contract test**

Create `tests/quic_tls_adapter_contract_test.cpp` by moving the existing
`QuicTlsAdapterTest` into a backend-neutral contract test name and tightening it
to require Handshake-level secrets.

- [ ] **Step 2: Run the filtered test and confirm it fails at link time**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTlsAdapterContractTest.*
```

Expected: FAIL because no backend implementation is linked.

- [ ] **Step 3: Add the build option**

Update `build.zig` to accept:

```zig
const tls_backend =
    b.option([]const u8, "tls_backend", "quictls or boringssl") orelse "quictls";
```

Then select the backend-specific source file:

```zig
if (std.mem.eql(u8, tls_backend, "quictls")) {
    files.append("src/quic/tls_adapter_quictls.cpp") catch @panic("oom");
} else if (std.mem.eql(u8, tls_backend, "boringssl")) {
    files.append("src/quic/tls_adapter_boringssl.cpp") catch @panic("oom");
} else {
    @panic("unsupported tls_backend");
}
```

- [ ] **Step 4: Update Nix inputs for backend selection**

Add `quictls` and `boringssl` development inputs to `flake.nix`, but keep
`quictls` as the default dev-shell link target.

- [ ] **Step 5: Re-run the filtered test**

Run:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTlsAdapterContractTest.*
```

Expected: still FAIL, but now at unresolved backend implementation symbols from
`tls_adapter_quictls.cpp`.

- [ ] **Step 6: Commit**

```bash
git add flake.nix build.zig src/quic/tls_adapter.h tests/quic_tls_adapter_contract_test.cpp
git commit -m "build: add selectable QUIC TLS backends"
```

### Task 2: Implement The Quictls TLS Backend

**Files:**
- Modify: `build.zig`
- Create: `src/quic/tls_adapter_quictls.cpp`
- Modify: `tests/quic_tls_adapter_contract_test.cpp`

- [ ] **Step 1: Keep the contract test red with the stricter assertions**

Ensure the contract test explicitly checks:
- pending Initial bytes on client start
- peer transport parameters on both sides
- Handshake secrets on both sides
- final handshake completion on both peers

- [ ] **Step 2: Implement the minimum `quictls` backend**

Create `src/quic/tls_adapter_quictls.cpp` using the QUIC-capable raw TLS hooks
provided by `quictls`, including:

- `SSL_set_quic_method` / `SSL_CTX_set_quic_method`
- `SSL_provide_quic_data`
- `SSL_process_quic_post_handshake`
- `SSL_set_quic_transport_params`
- `SSL_get_peer_quic_transport_params`

Map those hooks onto the existing `TlsAdapter` seam.

- [ ] **Step 3: Re-run the contract test and verify it passes on `quictls`**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicTlsAdapterContractTest.*
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add build.zig src/quic/tls_adapter_quictls.cpp tests/quic_tls_adapter_contract_test.cpp
git commit -m "feat: add quictls handshake backend"
```

### Task 3: Add Transport-Parameter And CRYPTO Stream Helpers

**Files:**
- Modify: `build.zig`
- Create: `src/quic/transport_parameters.h`
- Create: `src/quic/transport_parameters.cpp`
- Create: `src/quic/crypto_stream.h`
- Create: `src/quic/crypto_stream.cpp`
- Create: `tests/quic_transport_parameters_test.cpp`
- Create: `tests/quic_crypto_stream_test.cpp`

- [ ] **Step 1: Write the failing transport-parameter and CRYPTO tests**
- [ ] **Step 2: Run each filtered test and confirm the red phase**
- [ ] **Step 3: Implement the minimal helpers**
- [ ] **Step 4: Re-run the filtered tests and verify green**
- [ ] **Step 5: Commit**

Commands:

```bash
nix develop -c zig build test -- --gtest_filter=QuicTransportParametersTest.*
nix develop -c zig build test -- --gtest_filter=QuicCryptoStreamTest.*
```

### Task 4: Add QuicCore And QuicConnection Bootstrap

**Files:**
- Modify: `src/coquic.h`
- Create: `src/quic/core.h`
- Create: `src/quic/core.cpp`
- Create: `src/quic/connection.h`
- Create: `src/quic/connection.cpp`
- Modify: `tests/quic_test_utils.h`
- Create: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write the failing bootstrap tests**
- [ ] **Step 2: Run the filtered bootstrap tests and verify red**
- [ ] **Step 3: Implement client bootstrap through `quictls`**
- [ ] **Step 4: Re-run the filtered tests and verify green**
- [ ] **Step 5: Commit**

Commands:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.ClientStartsHandshakeFromEmptyInput:QuicCoreTest.ServerDoesNotEmitUntilItReceivesBytes
```

### Task 5: Process Client Initials And Emit The First Server Flight

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write the failing server-flight test**
- [ ] **Step 2: Run it and confirm red**
- [ ] **Step 3: Implement server Initial processing and coalesced Initial+Handshake response**
- [ ] **Step 4: Re-run and verify green**
- [ ] **Step 5: Commit**

### Task 6: Complete The Two-Peer Handshake On Quictls

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write the failing end-to-end handshake test**
- [ ] **Step 2: Run it and confirm red**
- [ ] **Step 3: Implement client continuation, secret installation, and peer transport-parameter validation**
- [ ] **Step 4: Re-run the integration test and verify green**
- [ ] **Step 5: Run the handshake-focused suite on `quictls`**
- [ ] **Step 6: Commit**

Commands:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.TwoPeersCompleteHandshake
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicTlsAdapterContractTest.*:QuicTransportParametersTest.*:QuicCryptoStreamTest.*:QuicCoreTest.*
```

### Task 7: Add The BoringSSL Backend

**Files:**
- Modify: `flake.nix`
- Modify: `build.zig`
- Create: `src/quic/tls_adapter_boringssl.cpp`
- Modify or Split: `src/quic/packet_crypto.cpp`
- Modify: `tests/quic_tls_adapter_contract_test.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Run the TLS contract and handshake tests against `boringssl` and confirm they fail**
- [ ] **Step 2: Implement the `boringssl` backend using its QUIC hooks**
- [ ] **Step 3: If needed, split packet crypto into backend-specific implementations**
- [ ] **Step 4: Re-run TLS contract tests on `boringssl` and verify green**
- [ ] **Step 5: Re-run handshake integration tests on `boringssl` and verify green**
- [ ] **Step 6: Commit**

Commands:

```bash
nix develop -c zig build test -- -Dtls_backend=boringssl --gtest_filter=QuicTlsAdapterContractTest.*
nix develop -c zig build test -- -Dtls_backend=boringssl --gtest_filter=QuicCoreTest.TwoPeersCompleteHandshake
```

### Task 8: Full Verification

**Files:**
- Modify: all files touched by previous tasks

- [ ] **Step 1: Run format verification**
- [ ] **Step 2: Run clang-tidy verification**
- [ ] **Step 3: Run full build on `quictls`**
- [ ] **Step 4: Run full test suite on `quictls`**
- [ ] **Step 5: Run full build on `boringssl`**
- [ ] **Step 6: Run full test suite on `boringssl`**
- [ ] **Step 7: Run coverage on the default backend**
- [ ] **Step 8: Commit the final verified implementation**

Commands:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build -- -Dtls_backend=quictls
nix develop -c zig build test -- -Dtls_backend=quictls
nix develop -c zig build -- -Dtls_backend=boringssl
nix develop -c zig build test -- -Dtls_backend=boringssl
nix develop -c zig build coverage -- -Dtls_backend=quictls
```
