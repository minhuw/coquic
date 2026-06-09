# CoQUIC Fuzzing Design

Status: first local AFL++ step implemented

This document proposes a first fuzzing step for CoQUIC's QUIC transport core. It
is intentionally scoped to deterministic, sans-I/O targets that can run quickly
under sanitizers before the project invests in long-running distributed fuzzing.

## Goals

- Find memory-safety, undefined-behavior, parser, and state-machine bugs in the
  QUIC core.
- Exercise RFC-shaped inputs, not just random byte strings.
- Keep the first implementation compatible with the existing `zig build` and
  `nix develop -c ...` workflow.
- Produce local reproducers that can be promoted into unit tests.
- Leave interop, benchmarks, and generated local state out of the fuzzing path.

Non-goals for the first step:

- Full live TLS handshake fuzzing.
- Socket, `io_uring`, benchmark, or HTTP server fuzzing.
- Cross-implementation differential fuzzing.
- OSS-Fuzz onboarding before local targets are stable.

## Survey

Mature QUIC implementations generally combine three kinds of fuzzing:

- Byte-oriented parser fuzzing for frames, packets, varints, transport
  parameters, QPACK, and helper data structures.
- Stateful receive-path fuzzing where a single connection processes fuzzed
  packets or fuzzed operation sequences.
- Continuous fuzzing infrastructure that stores corpora, minimizes inputs,
  runs sanitizer builds, and reports reproducers.

Representative practices:

- Cloudflare `quiche` keeps a dedicated `fuzz/` crate based on libFuzzer. Its
  targets include client/server packet receive, post-handshake server packet
  receive, multi-packet server receive, and QPACK decode. It also documents seed
  generation, coverage, and corpus minimization.
- `ngtcp2` keeps C++ libFuzzer targets for frame decode, packet read/write,
  handshake packet read/write, and core containers. Its ClusterFuzzLite build
  script compiles each target with `$CXXFLAGS`, links `$LIB_FUZZING_ENGINE`, and
  exports seed corpus archives.
- `quic-go` documents OSS-Fuzz and ClusterFuzzLite operation, local corpus
  directories, coverage builds, and reproduction against mounted local source.
- MsQuic integrates with OSS-Fuzz/libFuzzer and documents local address,
  undefined, and memory sanitizer builds through OSS-Fuzz helper scripts.
- AWS `s2n-quic` keeps many narrow Rust fuzz targets with per-target corpora,
  including frame, packet, packet-number, varint, transport-parameter,
  recovery, path manager, stream controller, and reassembler fuzzing.
- Google QUICHE has QUIC framer fuzzers and QPACK fuzzers under project test
  tooling.

The common lesson is not "start with the whole endpoint." The durable pattern is
to make narrow parser targets cheap, deterministic, and corpus-backed, then add
stateful receive fuzzing once the target API can run many iterations without
network, wall-clock, or file-system effects.

## Framework Choice

Use AFL++ as the first local campaign runner, while keeping each harness
compatible with libFuzzer-style entrypoints.

Rationale:

- CoQUIC is C++ built through Zig, and AFL++'s LLVM/LTO compiler wrappers fit a
  local source-build workflow without introducing a second project build system.
- The libFuzzer-style entrypoint model is minimal:
  `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.
- AFL++ can run these harnesses through a tiny stdin/file driver, while the same
  harness logic remains portable to libFuzzer, OSS-Fuzz, ClusterFuzzLite, or
  future engines.
- AddressSanitizer and UndefinedBehaviorSanitizer give immediate value for C++
  parser and state-machine code.

Defer LibAFL and honggfuzz until there is a stable corpus and at least one
stateful target. LibAFL is a powerful framework for building custom fuzzers,
but for the first parser targets it would add Rust-side fuzzer architecture
that CoQUIC does not need yet.

## Protocol Surface

The first fuzzing wave should align with these QUIC surfaces:

- Variable-length integers, because RFC 9000 section 16 defines the shared
  integer encoding used throughout packet and frame parsing.
- Frames, because RFC 9000 section 12.4 defines frame encoding as typed
  payloads and packet-type restrictions.
- Coalesced datagrams and packet parsing, because RFC 9000 sections 12.2 and
  17 define multiple packet forms and datagram-level packet processing.
- Transport parameters, because RFC 9000 section 7.4 carries critical peer
  configuration in TLS and malformed values drive connection errors.
- Version information and QUIC v2 packet bits, because CoQUIC already supports
  RFC 9368/RFC 9369 paths in packet and transport-parameter tests.

## Current CoQUIC Fit

CoQUIC already has pure codec APIs that are suitable fuzz targets:

- `decode_varint_bytes` and `encode_varint` in
  `src/quic/codec/varint.h`.
- `deserialize_frame`, `deserialize_received_frame`, `serialize_frame`,
  `serialized_frame_size`, and `append_serialized_frame` in
  `src/quic/codec/frame.h`.
- `deserialize_packet`, `serialize_packet`, `deserialize_datagram`, and
  `serialize_datagram` in `src/quic/codec/packet.h` and
  `src/quic/codec/plaintext_codec.h`.
- `deserialize_transport_parameters`, `serialize_transport_parameters`, and
  `validate_peer_transport_parameters` in
  `src/quic/transport/transport_parameters.h`.
- Sans-I/O endpoint entrypoints under `include/coquic/core.h`, once byte-level
  targets are stable.

The existing GoogleTest suite already contains compact seed examples for
frames, packets, varints, transport parameters, recovery, migration, path
validation, and endpoint routing. Those tests should be mined into seed
corpora rather than hand-writing a large corpus from scratch.

## First-Step Targets

Create `fuzz/` with one source file per target, a small shared harness helper,
per-target seed corpus directories, and a short README.

Recommended first targets:

1. `fuzz_varint`
   - Input: arbitrary bytes up to 16 bytes.
   - Calls `decode_varint_bytes`.
   - If decode succeeds, re-encodes the value, decodes the re-encoding, and
     checks value stability and shortest encoding size.
   - Purpose: very fast smoke target for build plumbing and integer edge cases.

2. `fuzz_frame`
   - Input: arbitrary bytes up to one QUIC datagram, initially 1500 bytes.
   - Calls both `deserialize_frame` and `deserialize_received_frame`.
   - If both fail, their error code and offset should agree unless a documented
     ownership-mode difference exists.
   - If decode succeeds and the frame has an outbound `Frame` representation,
     serialize it, deserialize the serialization, and check stable frame kind.
   - Purpose: main parser target for ACK ranges, STREAM lengths, CONNECTION_CLOSE
     reason lengths, NEW_CONNECTION_ID lengths, DATAGRAM length/no-length, and
     forbidden/non-shortest frame type encodings.

3. `fuzz_plaintext_packet`
   - Input: arbitrary bytes up to 1500 bytes.
   - Calls `deserialize_packet` with a few deterministic option variants:
     no short-header DCID length, a small short-header DCID length, and
     `accept_greased_quic_bit = true`.
   - If a packet decodes and consumes the whole input, serialize and decode
     again.
   - Purpose: header, packet-length, packet-number-length, coalesced datagram,
     frame-in-packet-type, retry, version negotiation, and QUIC v1/v2 bit
     coverage without packet protection.

4. `fuzz_transport_parameters`
   - Input: arbitrary bytes up to 4096 bytes.
   - Calls `deserialize_transport_parameters`.
   - If decode succeeds, serialize and decode again.
   - Runs `validate_peer_transport_parameters` under a small matrix of client
     and server validation contexts generated deterministically from the input.
   - Purpose: duplicate parameters, varint-length handling, preferred address,
     version information, CID length, ACK exponent, max ACK delay, and
     connection error metadata.

5. `fuzz_core_datagram_parse`
   - Input: arbitrary bytes up to 1500 bytes.
   - Uses an endpoint or test-visible wrapper around `QuicCore::parse_endpoint_datagram`
     if that can be exposed without weakening production visibility.
   - Purpose: endpoint routing classification, supported/unsupported version
     handling, token extraction, source/destination CID bounds, and stateless
     response decision logic.

Only targets 1 through 4 need to land in the first implementation PR. Target 5
is the first state-adjacent follow-up because the parsing method is currently
internal to `src/quic/core.h`.

## Harness Rules

Each target should follow these rules:

- No sockets, sleeping, threads, qlog file output, or live wall-clock behavior.
- No uncaught exceptions or `abort()` for expected malformed inputs.
- Cap input sizes explicitly: 16 bytes for varints, 1500 bytes for frame/packet
  datagrams, 4096 bytes for transport parameters.
- Treat every `CodecResult` failure as valid unless it violates an invariant
  such as an out-of-range offset.
- Assert semantic invariants only after successful decode or successful
  serialize/decode cycles.
- Keep fuzz-only helper code under `fuzz/` unless production code needs a
  narrow test hook.
- Minimize dependencies. Codec targets should link only QUIC codec/transport
  sources, C++ runtime, and sanitizer/fuzzer libraries.
- Use deterministic pseudo-random choices from the input when a target needs a
  small option matrix. Do not use global RNG.

Suggested invariants:

- A successful decoder never reports `bytes_consumed > input.size()`.
- Error offsets are no larger than input size.
- `serialize(decode(serialize(x)))` remains decodable and preserves variant
  kind for packets and frames.
- `serialized_frame_size(frame)` matches `serialize_frame(frame).size()` for
  frames produced by the decoder.
- Received-frame decode and ordinary frame decode agree on malformed byte
  errors where they parse the same representation.
- Re-encoded varints decode to the same value and use the expected encoded size.
- Transport parameters that round-trip keep defaults and option presence stable.

## Corpus Strategy

Check in only small seed corpus definitions as `.hex` files. Let the scripts
decode them into raw AFL++ inputs under `.fuzz/corpus/`, and let long-running
fuzzing grow generated corpora outside tracked source.

Recommended layout:

```text
fuzz/
  README.md
  corpus/
    fuzz_varint/
    fuzz_frame/
    fuzz_plaintext_packet/
    fuzz_transport_parameters/
  src/
    fuzz_varint.cpp
    fuzz_frame.cpp
    fuzz_plaintext_packet.cpp
    fuzz_transport_parameters.cpp
    fuzz_support.h
```

Seed sources:

- Encode positive examples from `tests/core/packets/*_test.cpp`.
- Include one or two negative examples for truncation, invalid varint,
  non-shortest frame type, forbidden packet frame type, too-short preferred
  address, malformed version information, and unknown frame type.
- Include QUIC v1 and v2 long-header examples.
- Include ACK, ACK_ECN, CRYPTO, STREAM with and without explicit length,
  DATAGRAM with and without length, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID,
  CONNECTION_CLOSE, PATH_CHALLENGE, PATH_RESPONSE, and HANDSHAKE_DONE frames.

Generated corpora should live outside the repo, for example:

```text
.fuzz/corpus/<target>/
.fuzz/artifacts/<target>/
.fuzz/minimized/<target>/
```

Generated `.fuzz/` state is ignored by git. If a generated input exposes a fixed
bug, copy only the minimized reproducer into a regression test or a small named
seed under `fuzz/corpus/<target>/`.

## Build Integration

The first integration is script-based AFL++. A later PR can wrap these scripts
in `zig build` steps if that proves useful.

Build shape:

- Build local AFL++ binaries with `afl-clang-lto++` when available, falling back
  to `afl-clang-fast++`.
- Add `-fsanitize=address,undefined` for local default fuzz builds.
- Prefer `-O1 -g` for first local runs.
- Compile targets with a narrow codec source subset and avoid IO, HTTP/3, perf,
  TLS, and binding sources.
- Keep generated campaign output under `.fuzz/`.

Primary commands:

```sh
nix develop -c scripts/build-fuzzers.sh
nix develop -c scripts/run-fuzz-smoke.sh
nix develop -c scripts/run-afl-fuzzer.sh fuzz_frame
```

The scripts call the toolchain from the Nix shell and do not introduce CMake or
another permanent build system. The AFL++ runner should pass `-m none` by
default for ASan/UBSan builds.

## CI Rollout

Phase 1: local-only

- Build all fuzz targets in `nix develop`.
- Replay checked-in seeds with `scripts/run-fuzz-smoke.sh`.
- Run bounded or open-ended AFL++ campaigns locally with
  `scripts/run-afl-fuzzer.sh <target>`, for example
  `scripts/run-afl-fuzzer.sh fuzz_frame -V 60`.
- Run `zig build test` separately as normal validation.

Phase 2: optional CI replay only

- Do not run open-ended fuzz campaigns on GitHub-hosted runners.
- If CI coverage is desired, build the fuzz binaries and replay checked-in
  seeds/minimized regressions only.
- Keep any replay job separate from real fuzzing campaigns.

Phase 3: ClusterFuzzLite or OSS-Fuzz

- Add `.clusterfuzzlite/` only after targets are stable and deterministic.
- Follow the C++ model used by `ngtcp2`: compile targets with `$CXXFLAGS`, link
  with `$LIB_FUZZING_ENGINE`, and export `*_seed_corpus.zip`.
- Once reliable, consider OSS-Fuzz onboarding so CoQUIC benefits from long-run
  sanitizer coverage and generated corpus storage.

## Triage Workflow

When a fuzzer finds a crash:

1. Reproduce with the exact target and artifact:

   ```sh
   nix develop -c .fuzz/bin/<target> <artifact>
   ```

2. Minimize:

   ```sh
   afl-tmin -i <artifact> -o .fuzz/minimized/<name> -- .fuzz/bin/<target> @@
   ```

3. Fix the bug without weakening parser validation.
4. Add the minimized input as a unit test or a named seed corpus entry.
5. Run:

   ```sh
   nix develop -c zig build test
   nix develop -c scripts/run-fuzz-smoke.sh
   git diff --check
   ```

## Future Targets

After the first four targets are stable:

- `fuzz_endpoint_sequence`: structured input that drives a client and server
  sans-I/O endpoint pair through open, inbound datagram delivery, timer expiry,
  stream write, datagram write, migration request, and close commands.
- `fuzz_protected_packet`: packet protection decode with fake deterministic
  keys or test hooks. This needs careful setup so invalid crypto is not just a
  shallow decryption-failure oracle.
- `fuzz_http3_protocol` and `fuzz_qpack`: HTTP/3 frame and QPACK decode targets,
  following the pattern used by QUICHE and quiche.
- `fuzz_recovery_model`: structured operation sequences for ACK/loss/recovery
  and congestion-controller invariants.
- Differential parser checks against another implementation are useful later,
  but only after CoQUIC has stable local parsers and minimized corpora.

## Implemented First Step

The first implementation includes:

- `fuzz/README.md`.
- Four target files: varint, frame, plaintext packet, transport parameters.
- A small shared helper header and source file for byte span conversion,
  invariant checks, and fuzz-only transport-version helpers.
- AFL++ build, corpus preparation, smoke replay, and campaign scripts.
- Small checked-in seed corpora derived from current tests.
- `.gitignore` entries for `.fuzz/`.

The implementation should not touch the root `README.md` beyond an optional
single link after fuzzing is actually available.

## References

- LLVM libFuzzer documentation:
  https://llvm.org/docs/LibFuzzer.html
- OSS-Fuzz new project guide:
  https://google.github.io/oss-fuzz/getting-started/new-project-guide/
- OSS-Fuzz continuous integration/CIFuzz:
  https://google.github.io/oss-fuzz/getting-started/continuous-integration/
- Cloudflare quiche fuzzing:
  https://github.com/cloudflare/quiche/tree/master/fuzz
- ngtcp2 fuzz targets and ClusterFuzzLite config:
  https://github.com/ngtcp2/ngtcp2/tree/main/fuzz
  https://github.com/ngtcp2/ngtcp2/tree/main/.clusterfuzzlite
- quic-go fuzzing:
  https://github.com/quic-go/quic-go/blob/master/FUZZING.md
- MsQuic fuzzing:
  https://github.com/microsoft/msquic/tree/main/src/fuzzing
- s2n-quic fuzz corpus layout:
  https://github.com/aws/s2n-quic/tree/main/quic/s2n-quic-core/src
- Google QUICHE QUIC fuzzing tools:
  https://github.com/google/quiche/tree/main/quiche/quic/test_tools/fuzzing
- QUIC transport RFC:
  https://www.rfc-editor.org/rfc/rfc9000.html
- QUIC version 2 RFC:
  https://www.rfc-editor.org/rfc/rfc9369.html
