# Full BoringSSL Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `boringssl` a fully supported QUIC TLS backend with `100%` coverage, passing tests, and clean format/lint results, while preserving the existing backend-neutral QUIC transport surface.

**Architecture:** Keep `QuicConnection` and `QuicCore` backend-agnostic behind `TlsAdapter`, split packet crypto into backend-selected translation units, and generalize TLS adapter test hooks so the same behavior and fault-path coverage can run under both `quictls` and `boringssl`.

**Tech Stack:** C++20, Zig build options, GoogleTest, QUIC packet protection helpers in `src/quic/`, `quictls`, `BoringSSL`, LLVM coverage, pre-commit `clang-format`, custom `clang-tidy`

---

## Spec Reference

- `docs/superpowers/specs/2026-03-20-boringssl-support-design.md`

## File Map

- Modify: `build.zig`
  - Select backend-specific packet crypto sources in addition to backend-specific TLS adapter sources.
- Delete: `src/quic/packet_crypto.cpp`
  - Replace the single OpenSSL-oriented implementation file with backend-selected implementations.
- Create: `src/quic/packet_crypto_internal.h`
  - Shared constants, helper declarations, fault-state helpers, and backend-neutral crypto utility declarations.
- Create: `src/quic/packet_crypto_quictls.cpp`
  - Current EVP-oriented packet crypto implementation, preserved for `quictls`.
- Create: `src/quic/packet_crypto_boringssl.cpp`
  - BoringSSL-native HKDF, AEAD, and ChaCha header-protection implementation.
- Modify: `src/quic/packet_crypto_test_hooks.h`
  - Keep the shared fault-injection surface aligned with both backend implementations.
- Create: `src/quic/tls_adapter_test_hooks.h`
  - Backend-neutral TLS adapter test hook surface replacing the quictls-specific header name.
- Delete: `src/quic/tls_adapter_quictls_test_hooks.h`
  - Retire the backend-specific test hook header after consumers move to the generic name.
- Modify: `src/quic/tls_adapter_quictls.cpp`
  - Include the generic test hook header and keep the current behavior green after the rename.
- Modify: `src/quic/tls_adapter_boringssl.cpp`
  - Implement the BoringSSL adapter and the generic test hook methods for the BoringSSL build.
- Modify: `tests/quic_packet_crypto_test.cpp`
  - Add any missing backend-neutral assertions needed to drive BoringSSL crypto behavior and reach `100%` coverage.
- Modify: `tests/quic_tls_adapter_contract_test.cpp`
  - Move to the generic TLS adapter test hooks header and add assertions for BoringSSL-specific coverage gaps if needed.
- Modify: `tests/quic_core_test.cpp`
  - Move to the generic TLS adapter test hooks header and add any handshake regressions exposed by the BoringSSL backend.

## Execution Notes

- Follow `@superpowers:test-driven-development` for each behavior change.
- Use targeted filtered suites for red/green cycles; use full verification only after all tasks are green.
- `scripts/run-coverage.sh` overwrites `coverage/` on each run, so inspect or copy the artifacts after each backend-specific coverage run before running the next one.
- Keep all backend selection at build time. Do not add runtime branching in `QuicConnection` or `QuicCore`.

### Task 1: Split Packet Crypto Into Backend-Selected Translation Units

**Files:**
- Modify: `build.zig`
- Delete: `src/quic/packet_crypto.cpp`
- Create: `src/quic/packet_crypto_internal.h`
- Create: `src/quic/packet_crypto_quictls.cpp`
- Create: `src/quic/packet_crypto_boringssl.cpp`
- Modify: `src/quic/packet_crypto_test_hooks.h`
- Test: `tests/quic_packet_crypto_test.cpp`

- [ ] **Step 1: Use the current packet-crypto suite as the refactor safety net**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls test -- --gtest_filter='*PacketCrypto*'
```

Expected: PASS. This is the baseline before splitting files.

- [ ] **Step 2: Add backend-specific packet crypto source selection in `build.zig`**

Implement a helper alongside `appendTlsAdapterSource`:

```zig
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
```

Then remove the hard-coded `"src/quic/packet_crypto.cpp"` entry from the file list and append the backend-selected source instead.

- [ ] **Step 3: Move backend-neutral packet-crypto helpers into `src/quic/packet_crypto_internal.h`**

Move the shared constants, helper declarations, and fault-state declarations behind a private internal header:

```cpp
struct CipherSuiteParameters {
    const EVP_MD *(*digest)();
    std::size_t key_length;
    std::size_t iv_length;
    std::size_t hp_key_length;
};

struct PacketCryptoFaultState {
    std::optional<PacketCryptoFaultPoint> fault_point;
    std::size_t occurrence = 0;
};

PacketCryptoFaultState &packet_crypto_fault_state();
bool consume_packet_crypto_fault(PacketCryptoFaultPoint fault_point);
```

Keep the public API in `src/quic/packet_crypto.h` unchanged.

- [ ] **Step 4: Move the existing implementation into `src/quic/packet_crypto_quictls.cpp` without changing behavior**

This file should be a behavior-preserving move of the current implementation, still using the EVP-based APIs already working under `quictls`.

- [ ] **Step 5: Add a compiling placeholder `src/quic/packet_crypto_boringssl.cpp`**

Create the file with the same public function definitions and internal helper shape, even if the bodies temporarily return failure:

```cpp
CodecResult<std::vector<std::byte>> seal_payload(...) {
    return CodecResult<std::vector<std::byte>>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
}
```

The goal for this step is a controlled red state under `boringssl`, not a passing implementation yet.

- [ ] **Step 6: Re-run the quictls safety-net suite**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls test -- --gtest_filter='*PacketCrypto*'
```

Expected: PASS. The refactor must not change `quictls` behavior.

- [ ] **Step 7: Confirm the `boringssl` packet-crypto suite is now a clean red**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl test -- --gtest_filter='*PacketCrypto*'
```

Expected: FAIL in packet-crypto behavior, not in missing source-file selection or unrelated build wiring.

- [ ] **Step 8: Commit**

```bash
git add build.zig src/quic/packet_crypto_internal.h src/quic/packet_crypto_quictls.cpp src/quic/packet_crypto_boringssl.cpp src/quic/packet_crypto_test_hooks.h
git rm src/quic/packet_crypto.cpp
git commit -m "refactor: split packet crypto by TLS backend"
```

### Task 2: Implement BoringSSL Packet Crypto Parity

**Files:**
- Modify: `src/quic/packet_crypto_internal.h`
- Modify: `src/quic/packet_crypto_boringssl.cpp`
- Modify: `tests/quic_packet_crypto_test.cpp`

- [ ] **Step 1: Add any missing backend-neutral regression tests before implementation**

If the current suite does not directly pin the BoringSSL-specific paths, add tests such as:

```cpp
TEST(QuicPacketCryptoTest, RoundTripsChaChaPayloadAndHeaderProtectionAcrossPublicApi) {
    // Derive keys, seal payload, reopen it, and build the header mask.
}
```

Prefer public API assertions over backend-specific internals.

- [ ] **Step 2: Run the packet-crypto suite on `boringssl` and confirm red**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl test -- --gtest_filter='*PacketCrypto*'
```

Expected: FAIL because the BoringSSL implementation is still incomplete.

- [ ] **Step 3: Implement HKDF using BoringSSL’s exported HKDF API**

Use `<openssl/hkdf.h>` instead of the unsupported OpenSSL EVP HKDF mode calls:

```cpp
std::vector<std::byte> pseudorandom_key(EVP_MD_size(digest));
size_t output_length = pseudorandom_key.size();
const auto failed =
    consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_extract_setup) ||
    HKDF_extract(reinterpret_cast<uint8_t *>(pseudorandom_key.data()), &output_length, digest,
                 reinterpret_cast<const uint8_t *>(input_key_material.data()),
                 input_key_material.size(),
                 reinterpret_cast<const uint8_t *>(salt.data()), salt.size()) != 1;
```

Mirror the existing error mapping and fault-point behavior.

- [ ] **Step 4: Implement AEAD sealing and opening with `EVP_AEAD_CTX`**

Use `<openssl/aead.h>` for AES-GCM and ChaCha20-Poly1305:

```cpp
const EVP_AEAD *aead = EVP_aead_chacha20_poly1305();
std::unique_ptr<EVP_AEAD_CTX, decltype(&EVP_AEAD_CTX_free)> ctx(
    consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_context_new)
        ? nullptr
        : EVP_AEAD_CTX_new(aead, key_bytes, key_len, EVP_AEAD_DEFAULT_TAG_LENGTH),
    &EVP_AEAD_CTX_free);
```

Preserve the current fault points and error codes for:

- bad lengths
- context construction
- init/setup
- AAD handling
- payload handling
- tag-related failure mapping

- [ ] **Step 5: Implement ChaCha20 header protection with `CRYPTO_chacha_20`**

Split the 16-byte QUIC sample into counter and nonce exactly once:

```cpp
const uint32_t counter =
    std::to_integer<uint8_t>(sample_prefix[0]) |
    (std::to_integer<uint8_t>(sample_prefix[1]) << 8) |
    (std::to_integer<uint8_t>(sample_prefix[2]) << 16) |
    (std::to_integer<uint8_t>(sample_prefix[3]) << 24);
const auto nonce = sample_prefix.subspan(4, 12);
CRYPTO_chacha_20(mask_bytes, zero_bytes, header_protection_mask_length,
                 hp_key_bytes, nonce_bytes, counter);
```

Keep the AES header-protection path behavior aligned with the quictls implementation.

- [ ] **Step 6: Re-run the packet-crypto suite on both backends**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl test -- --gtest_filter='*PacketCrypto*'
nix develop -c zig build -Dtls_backend=quictls test -- --gtest_filter='*PacketCrypto*'
```

Expected: PASS on both backends.

- [ ] **Step 7: Commit**

```bash
git add src/quic/packet_crypto_internal.h src/quic/packet_crypto_boringssl.cpp tests/quic_packet_crypto_test.cpp
git commit -m "feat: add boringssl packet crypto backend"
```

### Task 3: Generalize TLS Adapter Test Hooks

**Files:**
- Create: `src/quic/tls_adapter_test_hooks.h`
- Delete: `src/quic/tls_adapter_quictls_test_hooks.h`
- Modify: `src/quic/tls_adapter_quictls.cpp`
- Modify: `tests/quic_tls_adapter_contract_test.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Move test consumers to a backend-neutral header name**

Update test includes:

```cpp
#include "src/quic/tls_adapter_test_hooks.h"
```

in place of the quictls-specific header path.

- [ ] **Step 2: Run the affected suites and confirm the red phase**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls test -- --gtest_filter='QuicTlsAdapterContractTest.*:QuicCoreTest.*'
```

Expected: FAIL because the generic test hook header and exports are not wired yet.

- [ ] **Step 3: Create `src/quic/tls_adapter_test_hooks.h` with the existing shared test surface**

Move the existing enums and test-peer declarations into the generic header:

```cpp
enum class TlsAdapterFaultPoint : std::uint8_t {
    initialize_ctx_new,
    initialize_ctx_config,
    initialize_verify_paths,
    load_identity_cert_bio,
    load_identity_key_bio,
    load_identity_use_certificate,
    initialize_ssl_new,
    initialize_ssl_set_quic_method,
    initialize_server_name,
    initialize_transport_params,
    provide_quic_data,
    provide_post_handshake,
    drive_handshake,
    set_encryption_secrets_unsupported_cipher,
};
```

- [ ] **Step 4: Update `src/quic/tls_adapter_quictls.cpp` to include the new header and keep all existing hook definitions green**

This should be a naming/boundary change only. Do not change `quictls` behavior in this task.

- [ ] **Step 5: Re-run the affected suites on `quictls`**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls test -- --gtest_filter='QuicTlsAdapterContractTest.*:QuicCoreTest.*'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/quic/tls_adapter_test_hooks.h src/quic/tls_adapter_quictls.cpp tests/quic_tls_adapter_contract_test.cpp tests/quic_core_test.cpp
git rm src/quic/tls_adapter_quictls_test_hooks.h
git commit -m "refactor: generalize tls adapter test hooks"
```

### Task 4: Implement the BoringSSL TLS Adapter

**Files:**
- Modify: `src/quic/tls_adapter_boringssl.cpp`
- Modify: `tests/quic_tls_adapter_contract_test.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Use the contract and handshake suites as the failing regression**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl test -- --gtest_filter='QuicTlsAdapterContractTest.*:QuicCoreTest.ClientStartProducesSendEffect:QuicCoreTest.TwoPeersEmitHandshakeReadyExactlyOnce:QuicCoreTest.TwoPeersExchangeApplicationDataThroughEffects'
```

Expected: FAIL because the BoringSSL adapter is still a stub.

- [ ] **Step 2: Port the quictls adapter logic into a BoringSSL implementation**

Implement the same `TlsAdapter::Impl` contract using BoringSSL’s QUIC hooks:

```cpp
if (SSL_CTX_set_quic_method(ctx_.get(), &kQuicMethod) != 1) {
    sticky_error_ = CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
    return;
}

if (SSL_set_quic_transport_params(ssl_.get(), as_tls_bytes(config_.local_transport_parameters),
                                  config_.local_transport_parameters.size()) != 1) {
    sticky_error_ = CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
    return;
}
```

Mirror the existing behavior for:

- initialization and identity loading
- handshake driving
- post-handshake processing
- secret capture
- pending flight buffering
- peer transport parameter capture
- sticky error semantics

- [ ] **Step 3: Implement the generic test-peer methods in the BoringSSL build**

The same `TlsAdapterTestPeer` surface must work under `boringssl`, including:

- `cipher_suite_for_ssl`
- `drive_handshake`
- sticky error helpers
- static callback helpers
- transport-parameter capture helpers
- fault injector lifecycle

- [ ] **Step 4: Add or tighten regression tests only where BoringSSL exposes a real gap**

If any adapter behavior differs because of callback ordering or cipher reporting, add targeted assertions in `tests/quic_tls_adapter_contract_test.cpp` rather than weakening the shared contract.

- [ ] **Step 5: Re-run contract and handshake suites on both backends**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl test -- --gtest_filter='QuicTlsAdapterContractTest.*:QuicCoreTest.ClientStartProducesSendEffect:QuicCoreTest.TwoPeersEmitHandshakeReadyExactlyOnce:QuicCoreTest.TwoPeersExchangeApplicationDataThroughEffects'
nix develop -c zig build -Dtls_backend=quictls test -- --gtest_filter='QuicTlsAdapterContractTest.*:QuicCoreTest.ClientStartProducesSendEffect:QuicCoreTest.TwoPeersEmitHandshakeReadyExactlyOnce:QuicCoreTest.TwoPeersExchangeApplicationDataThroughEffects'
```

Expected: PASS on both backends.

- [ ] **Step 6: Commit**

```bash
git add src/quic/tls_adapter_boringssl.cpp tests/quic_tls_adapter_contract_test.cpp tests/quic_core_test.cpp
git commit -m "feat: add boringssl tls adapter"
```

### Task 5: Close Coverage Gaps to 100% on Both Backends

**Files:**
- Modify: `tests/quic_packet_crypto_test.cpp`
- Modify: `tests/quic_tls_adapter_contract_test.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `src/quic/packet_crypto_boringssl.cpp` (only if a branch cannot be hit without a behavior-preserving test seam)
- Modify: `src/quic/tls_adapter_boringssl.cpp` (only if a branch cannot be hit without a behavior-preserving test seam)

- [ ] **Step 1: Run `quictls` coverage and record the remaining uncovered lines**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls coverage
cp -R coverage coverage-quictls
```

Expected: inspect `coverage-quictls/lcov.info` or HTML and note any regressions introduced by the refactor.

- [ ] **Step 2: Run `boringssl` coverage and record the remaining uncovered lines**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl coverage
cp -R coverage coverage-boringssl
```

Expected: identify every remaining uncovered backend-specific branch before writing more code.

- [ ] **Step 3: Add the smallest missing tests first**

Typical places to close gaps:

- packet-crypto fault injection coverage
- BoringSSL-specific header-protection error paths
- TLS adapter callback edge cases
- handshake/post-handshake sticky error branches

Prefer tests like:

```cpp
TEST(QuicTlsAdapterContractTest, BoringSslCallbackFailureSticksAdapterError) {
    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::provide_post_handshake);
    // drive the smallest path that reaches the branch
}
```

- [ ] **Step 4: Re-run targeted suites after each added test**

Run only the affected filtered suite until the branch goes green:

```bash
nix develop -c zig build -Dtls_backend=boringssl test -- --gtest_filter='QuicTlsAdapterContractTest.*'
nix develop -c zig build -Dtls_backend=boringssl test -- --gtest_filter='*PacketCrypto*'
```

- [ ] **Step 5: Re-run both backend coverage commands until both report 100%**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls coverage
nix develop -c zig build -Dtls_backend=boringssl coverage
```

Expected: both coverage reports reach `100%` for the tracked project files.

- [ ] **Step 6: Commit**

```bash
git add tests/quic_packet_crypto_test.cpp tests/quic_tls_adapter_contract_test.cpp tests/quic_core_test.cpp src/quic/packet_crypto_boringssl.cpp src/quic/tls_adapter_boringssl.cpp
git commit -m "test: raise dual-backend coverage to 100 percent"
```

### Task 6: Run Full Verification and Finalize

**Files:**
- Modify: all files touched in previous tasks

- [ ] **Step 1: Run formatting**

Run:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
```

Expected: PASS with no diffs.

- [ ] **Step 2: Run clang-tidy**

Run:

```bash
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: PASS.

- [ ] **Step 3: Run full build and test on `quictls`**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls
nix develop -c zig build -Dtls_backend=quictls test
```

Expected: PASS.

- [ ] **Step 4: Run full coverage on `quictls`**

Run:

```bash
nix develop -c zig build -Dtls_backend=quictls coverage
```

Expected: `100%`.

- [ ] **Step 5: Run full build and test on `boringssl`**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl
nix develop -c zig build -Dtls_backend=boringssl test
```

Expected: PASS.

- [ ] **Step 6: Run full coverage on `boringssl`**

Run:

```bash
nix develop -c zig build -Dtls_backend=boringssl coverage
```

Expected: `100%`.

- [ ] **Step 7: Commit the fully verified implementation**

```bash
git add build.zig src/quic/packet_crypto_internal.h src/quic/packet_crypto_quictls.cpp src/quic/packet_crypto_boringssl.cpp src/quic/packet_crypto_test_hooks.h src/quic/tls_adapter_test_hooks.h src/quic/tls_adapter_quictls.cpp src/quic/tls_adapter_boringssl.cpp tests/quic_packet_crypto_test.cpp tests/quic_tls_adapter_contract_test.cpp tests/quic_core_test.cpp
git rm src/quic/packet_crypto.cpp src/quic/tls_adapter_quictls_test_hooks.h
git commit -m "feat: add full boringssl backend support"
```
