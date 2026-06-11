# CoQUIC Fuzzing

CoQUIC fuzz targets use `LLVMFuzzerTestOneInput` harnesses so the same target
logic can run under AFL++, libFuzzer-compatible runners, or future engines.
The first local campaign runner is AFL++.

Build fuzzers from the default Nix shell:

```sh
nix develop -c scripts/build-fuzzers.sh
```

Replay checked-in and generated seeds:

```sh
nix develop -c scripts/run-fuzz-smoke.sh
```

Run a local AFL++ campaign:

```sh
nix develop -c scripts/run-afl-fuzzer.sh fuzz_frame
```

The runner passes `-m none` by default because the local binaries are built with
ASan/UBSan unless `COQUIC_FUZZ_SANITIZERS` is overridden. It also defaults
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` so local campaigns can run on Linux
systems whose `core_pattern` is managed by a crash handler; override that
environment variable if you want AFL++ to enforce the stricter system setting.
When stdout is not a terminal, the runner enables `AFL_NO_UI=1` for readable
logs. If `fuzz/dicts/<target>.dict` exists, the runner passes it to AFL++ with
`-x`.

Generated corpora, queue entries, crashes, and minimized artifacts live under
`.fuzz/` and are intentionally ignored by git. Keep only small hand-written hex
seed definitions under `fuzz/corpus/`; the scripts decode them into raw inputs
under `.fuzz/corpus/` before replay or AFL++ campaigns. The build also creates
`.fuzz/bin/generate_corpus`; corpus preparation runs it by default and merges
serializer-derived raw seeds from `.fuzz/generated-corpus/`. Set
`COQUIC_FUZZ_SKIP_GENERATED_CORPUS=1` to replay only checked-in hex seeds.

Collect high-quality candidate seeds from normal CoQUIC execution by wrapping a
perf, interop, or test command:

```sh
nix develop -c scripts/collect-fuzz-corpus.sh -- zig build test
```

The wrapper sets `COQUIC_FUZZ_CORPUS_CAPTURE_DIR` and stores raw candidates
under `.fuzz/captured/<timestamp>/<target>/`. Runtime capture is disabled during
fuzzer builds, and it only runs when the environment variable is set.

Minimize corpus candidates after a campaign:

```sh
nix develop -c scripts/minimize-fuzz-corpus.sh fuzz_frame
```

The minimizer combines the prepared seed corpus with the latest AFL queue for
the target, runs `afl-cmin`, and writes raw minimized inputs under
`.fuzz/minimized/<target>/`. To promote minimized coverage-distinct inputs into
the checked-in seed corpus, pass `--promote`:

```sh
nix develop -c scripts/minimize-fuzz-corpus.sh fuzz_frame --promote --replace-promoted
```

To minimize captured candidates, pass the target-specific capture directory:

```sh
nix develop -c scripts/minimize-fuzz-corpus.sh fuzz_transport_parameters \
  --candidate .fuzz/captured/<run>/fuzz_transport_parameters \
  --promote
```

Promotion converts raw minimized inputs into `fuzz/corpus/<target>/afl_*.hex`.
Review promoted seeds before committing; keep only compact inputs that add
useful coverage or preserve a regression.

Measure local source coverage for the prepared corpus:

```sh
nix develop -c scripts/run-fuzz-coverage.sh
```

Pass AFL output roots to include queue entries in the replay:

```sh
nix develop -c scripts/run-fuzz-coverage.sh .fuzz/afl .fuzz/afl-1h
```

The coverage script writes a summary to `.fuzz/coverage/report/summary.txt`.
Set `COQUIC_FUZZ_COVERAGE_HTML=1` to also write annotated HTML. It defaults to
`clang++`; set `COQUIC_FUZZ_COVERAGE_CXX` to use another Clang-compatible
compiler. LLVM can warn about mismatched data because each standalone fuzzer has
its own `LLVMFuzzerTestOneInput` body; the source-file coverage report is still
written.

## Targets

- `fuzz_varint`: QUIC variable-length integer decode and round-trip checks.
- `fuzz_frame`: QUIC frame decode, received-frame decode, and serialization
  invariants.
- `fuzz_plaintext_packet`: aggregate plaintext packet/datagram decode and
  serialization invariants.
- `fuzz_long_header_packet`: long-header plaintext packet decode and packet
  serialization invariants.
- `fuzz_short_header_packet`: short-header plaintext packet decode with several
  fixed destination connection ID lengths.
- `fuzz_datagram`: coalesced plaintext datagram decode and serialization
  invariants.
- `fuzz_transport_parameters`: transport-parameter decode, round-trip, and
  validation checks.
- `fuzz_protected_packet`: protected packet decode plus protected datagram
  serialization/redecode checks over Initial, Handshake, 0-RTT, and 1-RTT
  packets.
- `fuzz_stream_state`: stream send, receive, flow-control, reset, stop-sending,
  blocked-frame, and stream-limit state transitions.
- `fuzz_recovery_ack`: received-packet history, ACK frame construction, ACK
  range cursor iteration, packet recovery, loss collection, and PTO helpers.
- `fuzz_congestion`: congestion-controller event sequences across NewReno,
  CUBIC, BBR, and Copa.

The targets treat malformed input as expected. They abort only when a successful
decode violates an invariant, an error offset is impossible, or a round-trip
result becomes internally inconsistent.
