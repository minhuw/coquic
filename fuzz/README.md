# CoQUIC Fuzzing

CoQUIC fuzz targets use `LLVMFuzzerTestOneInput` harnesses so the same target
logic can run under AFL++, libFuzzer-compatible runners, or future engines.
The first local campaign runner is AFL++.

Build fuzzers from the default Nix shell:

```sh
nix develop -c scripts/build-fuzzers.sh
```

Replay checked-in seeds:

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
logs.

Generated corpora, queue entries, crashes, and minimized artifacts live under
`.fuzz/` and are intentionally ignored by git. Keep only small hand-written hex
seed definitions under `fuzz/corpus/`; the scripts decode them into raw inputs
under `.fuzz/corpus/` before replay or AFL++ campaigns.

## Targets

- `fuzz_varint`: QUIC variable-length integer decode and round-trip checks.
- `fuzz_frame`: QUIC frame decode, received-frame decode, and serialization
  invariants.
- `fuzz_plaintext_packet`: plaintext packet/datagram decode and packet
  serialization invariants.
- `fuzz_transport_parameters`: transport-parameter decode, round-trip, and
  validation checks.

The targets treat malformed input as expected. They abort only when a successful
decode violates an invariant, an error offset is impossible, or a round-trip
result becomes internally inconsistent.
