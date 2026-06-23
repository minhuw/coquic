# Rattan WAN Benchmarks

This directory contains the host-side harness for replaying WAN bandwidth traces
with Rattan and measuring CoQUIC transfer behavior with `coquic-perf`.

The harness keeps third-party trace data out of git:

- downloaded raw data: `.bench-traces/raw/`
- converted Rattan-ready traces: `.bench-traces/rattan/`
- generated Rattan configs: `.bench-traces/configs/`
- benchmark results: `.bench-results/rattan/`

## Trace Prep

Download and convert the default smoke corpus:

```sh
python3 bench/rattan/prepare-traces.py --subset smoke
```

Download a broader opt-in subset:

```sh
python3 bench/rattan/prepare-traces.py --subset wireless
python3 bench/rattan/prepare-traces.py --subset full
```

The default corpus includes small Mahimahi LTE traces and normalized public
bandwidth traces. Larger corpora such as Pantheon, FCC MBA, Puffer, and the UCC
5G archive need explicit source-specific selection before they should be pulled
into local state.

## Quick 30-Minute Evaluation

The quick path targets one congestion-control algorithm in about 30 minutes by
building 30-second symmetric downlink windows and selecting a stratified bank
that fits the wall-clock budget:

```sh
RATTAN_CONGESTION_CONTROLS=pcc-vivace \
bench/rattan/run-rattan-quick.sh --dry-run
```

Drop `--dry-run` when Rattan is installed and the host has the privileges needed
for network namespaces. The quick wrapper defaults to one workload
(`bulk-download`), `RATTAN_DURATION=30s`, no warmup, corpus-derived RTT, and
timed bulk transfers. It computes the selected window count from
`RATTAN_TARGET_WALLCLOCK_SECONDS` and the current CC/workload/repetition matrix.
By default it excludes windows below `RATTAN_MIN_AVG_MBPS=0.05` so the quick run
does not spend its budget on paths that are unlikely to finish handshakes
cleanly. Set `RATTAN_MAX_WINDOWS=30` when you want exactly 30 windows instead of
the budget-derived count. Timed `bulk-download` uses a large response object by
default (`RATTAN_BULK_DOWNLOAD_RESPONSE_BYTES=16777216`) so it measures sustained
WAN transfer instead of repeated small-object turnover.

## Running

Generate Rattan configs and run a small matrix:

```sh
bench/rattan/run-rattan-matrix.sh --subset smoke
```

Useful overrides:

```sh
RATTAN_BIN=/path/to/rattan \
RATTAN_CONGESTION_CONTROLS="newreno cubic bbr copa pcc pcc-vivace" \
RATTAN_MODES="bulk-download bulk-upload rr" \
RATTAN_REPETITIONS=3 \
RATTAN_DURATION=20s \
RATTAN_WARMUP=5s \
RATTAN_BULK_DOWNLOAD_RESPONSE_BYTES=16777216 \
RATTAN_TOTAL_BYTES=67108864 \
bench/rattan/run-rattan-matrix.sh --subset wireless
```

Additional knobs that matter for WAN realism:

```sh
RATTAN_USE_SUDO=1 \
RATTAN_QUEUE_BDP_MULTIPLIER=2.0 \
RATTAN_LOSS_RATE=0.001 \
RATTAN_SERVER_HOST=10.2.1.1 \
bench/rattan/run-rattan-matrix.sh --subset smoke
```

Rattan creates network namespaces and veth pairs, so actual runs require Linux
and the privileges Rattan needs for namespace setup. Config generation and trace
conversion do not require privileges.

## Outputs

Each run writes:

- `*.rattan.toml`: generated emulator config
- `*.json`: `coquic-perf` result JSON
- `*.log`: Rattan/client/server logs
- `summary.csv` and `summary.json`: flattened result tables

Summarize an existing result directory:

```sh
python3 bench/rattan/summarize-results.py .bench-results/rattan/latest
```

## Notes

Rattan `BwReplay` accepts Mahimahi trace files directly. The converter also turns
simple throughput time series into Mahimahi packet-opportunity traces so all
downloaded bandwidth traces use one Rattan path. The default direction model is
symmetric: downlink traces are copied to the uplink path so upload/download use
identical path capacity. Fixed base RTT is modeled as a pair of one-way `Delay`
cells; queue size can be configured as a multiple of estimated BDP.
