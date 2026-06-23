#!/usr/bin/env python3
"""Focused tests for the Rattan benchmark harness."""

from __future__ import annotations

import csv
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
RATTAN_DIR = REPO_ROOT / "bench" / "rattan"


def load_script(name: str):
    path = RATTAN_DIR / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


prepare_traces = load_script("prepare-traces.py")


class RattanHarnessTest(unittest.TestCase):
    def test_time_series_conversion_marks_synthesized_uplink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            source = tmp_path / "source.trace"
            source.write_text("0.0 0.012\n1.0 0.024\n", encoding="utf-8")
            entry = {
                "id": "synthetic-down-only",
                "corpus": "unit",
                "network": "lte",
                "mobility": "bus",
                "base_rtt_ms": 80,
                "format": "time-throughput-mbps",
                "download": {"down": source.as_uri()},
            }

            prepared = prepare_traces.convert_entry(entry, tmp_path / "raw", tmp_path / "rattan", False)
            manifest_path = tmp_path / "manifest.json"
            prepare_traces.write_manifest([prepared], manifest_path, {"schema_version": 1})

            metadata = json.loads(prepared.metadata_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(metadata["up_synthesized"])
            self.assertTrue(manifest["traces"][0]["up_synthesized"])
            self.assertEqual(manifest["traces"][0]["subset"], [])
            self.assertEqual(
                prepared.down_trace.read_text(encoding="utf-8"),
                prepared.up_trace.read_text(encoding="utf-8"),
            )
            self.assertGreater(len(prepared.down_trace.read_text(encoding="utf-8").splitlines()), 0)

    def test_throughput_csv_conversion_honors_bandwidth_units(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            source = tmp_path / "source.csv"
            source.write_text("1,Mbits/sec\n500,Kbits/sec\n250,bits/sec\n", encoding="utf-8")
            samples = prepare_traces.parse_throughput_csv(source)

        self.assertEqual(samples, [(0.0, 1.0), (1.0, 0.5), (2.0, 0.00025)])

    def test_generate_config_emits_isolated_lossy_rattan_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            down_trace = tmp_path / "down.trace"
            up_trace = tmp_path / "up.trace"
            down_trace.write_text("0\n1000\n", encoding="utf-8")
            up_trace.write_text("0\n1000\n", encoding="utf-8")
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "traces": [
                            {
                                "id": "synthetic",
                                "corpus": "unit",
                                "network": "wired-wan",
                                "mobility": "fixed",
                                "base_rtt_ms": 40,
                                "down_trace": str(down_trace),
                                "up_trace": str(up_trace),
                                "up_synthesized": False,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            run_dir = tmp_path / "run"
            config_path = run_dir / "synthetic.rattan.toml"

            subprocess.run(
                [
                    sys.executable,
                    str(RATTAN_DIR / "generate-config.py"),
                    "--manifest",
                    str(manifest_path),
                    "--trace-id",
                    "synthetic",
                    "--output",
                    str(config_path),
                    "--results-root",
                    str(run_dir),
                    "--perf-bin",
                    str(tmp_path / "coquic-perf"),
                    "--congestion-control",
                    "pcc-vivace",
                    "--duration",
                    "2s",
                    "--warmup",
                    "1s",
                    "--loss-rate",
                    "0.001",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )

            config = config_path.read_text(encoding="utf-8")
            metadata = json.loads(config_path.with_suffix(".toml.json").read_text(encoding="utf-8"))
            self.assertIn('mode = "Isolated"', config)
            self.assertIn('type = "BwReplay"', config)
            self.assertIn(str(down_trace), config)
            self.assertIn('delay = "20.000ms"', config)
            self.assertIn('type = "Loss"', config)
            self.assertIn("--congestion-control pcc-vivace", config)
            self.assertIn("--host 10.2.1.1", config)
            self.assertEqual(metadata["congestion_control"], "pcc-vivace")
            self.assertEqual(metadata["loss_rate"], 0.001)
            self.assertGreaterEqual(metadata["queue_bytes"], 65536)

    def test_build_trace_bank_creates_symmetric_thirty_second_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            source_dir = tmp_path / "source"
            source_dir.mkdir()
            down_trace = source_dir / "down.trace"
            down_trace.write_text(
                "".join(f"{second * 1000 + repeat}\n" for second in range(70) for repeat in range(100)),
                encoding="utf-8",
            )
            up_trace = source_dir / "up.trace"
            up_trace.write_text("0\n", encoding="utf-8")
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "traces": [
                            {
                                "id": "long-lte",
                                "corpus": "unit",
                                "network": "lte",
                                "mobility": "train",
                                "base_rtt_ms": 60,
                                "subset": ["full"],
                                "down_trace": str(down_trace),
                                "up_trace": str(up_trace),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output_dir = tmp_path / "bank"
            output_manifest = output_dir / "manifest.json"

            subprocess.run(
                [
                    sys.executable,
                    str(RATTAN_DIR / "build-trace-bank.py"),
                    "--manifest",
                    str(manifest_path),
                    "--output-dir",
                    str(output_dir),
                    "--output-manifest",
                    str(output_manifest),
                    "--window-seconds",
                    "30",
                    "--max-windows",
                    "2",
                    "--min-avg-mbps",
                    "0.0",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )

            bank = json.loads(output_manifest.read_text(encoding="utf-8"))
            self.assertEqual(bank["window_seconds"], 30.0)
            self.assertEqual(len(bank["traces"]), 2)
            for trace in bank["traces"]:
                self.assertEqual(trace["subset"], ["quick", "windowed"])
                self.assertEqual(trace["direction_model"], "symmetric-downlink-window")
                self.assertEqual(
                    pathlib.Path(trace["down_trace"]).read_text(encoding="utf-8"),
                    pathlib.Path(trace["up_trace"]).read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    pathlib.Path(trace["rattan_down_trace"]).read_text(encoding="utf-8"),
                    pathlib.Path(trace["rattan_up_trace"]).read_text(encoding="utf-8"),
                )
                self.assertEqual(trace["rattan_format"], "netem-trace-bw-json")
                self.assertIn("RepeatedBwPatternConfig", pathlib.Path(trace["rattan_down_trace"]).read_text())
                self.assertLess(max(int(line) for line in pathlib.Path(trace["down_trace"]).read_text().split()), 30_000)

    def test_build_trace_bank_supports_overlapping_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            down_trace = tmp_path / "down.trace"
            down_trace.write_text(
                "".join(f"{second * 1000 + repeat}\n" for second in range(45) for repeat in range(10)),
                encoding="utf-8",
            )
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "traces": [
                            {
                                "id": "overlap-source",
                                "corpus": "unit",
                                "network": "lte",
                                "mobility": "driving",
                                "base_rtt_ms": 50,
                                "subset": ["full"],
                                "down_trace": str(down_trace),
                                "up_trace": str(down_trace),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output_manifest = tmp_path / "bank" / "manifest.json"

            subprocess.run(
                [
                    sys.executable,
                    str(RATTAN_DIR / "build-trace-bank.py"),
                    "--manifest",
                    str(manifest_path),
                    "--output-dir",
                    str(output_manifest.parent),
                    "--output-manifest",
                    str(output_manifest),
                    "--window-seconds",
                    "30",
                    "--window-stride-seconds",
                    "5",
                    "--max-windows",
                    "4",
                    "--min-avg-mbps",
                    "0.0",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )

            bank = json.loads(output_manifest.read_text(encoding="utf-8"))
            self.assertEqual(bank["window_stride_seconds"], 5.0)
            self.assertEqual(len(bank["traces"]), 4)
            self.assertTrue(any(trace["source_start_ms"] % 30_000 != 0 for trace in bank["traces"]))

    def test_build_trace_bank_filters_outage_heavy_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            down_trace = tmp_path / "down.trace"
            down_trace.write_text(
                "".join(f"{millis}\n" for millis in list(range(0, 100)) + list(range(30_000, 60_000, 10))),
                encoding="utf-8",
            )
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "traces": [
                            {
                                "id": "mixed",
                                "corpus": "unit",
                                "network": "lte",
                                "mobility": "driving",
                                "base_rtt_ms": 60,
                                "subset": ["full"],
                                "down_trace": str(down_trace),
                                "up_trace": str(down_trace),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output_manifest = tmp_path / "bank" / "manifest.json"

            subprocess.run(
                [
                    sys.executable,
                    str(RATTAN_DIR / "build-trace-bank.py"),
                    "--manifest",
                    str(manifest_path),
                    "--output-dir",
                    str(output_manifest.parent),
                    "--output-manifest",
                    str(output_manifest),
                    "--window-seconds",
                    "30",
                    "--max-windows",
                    "10",
                    "--min-avg-mbps",
                    "0.0",
                    "--max-outage-ratio",
                    "0.5",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )

            bank = json.loads(output_manifest.read_text(encoding="utf-8"))
            self.assertEqual([trace["source_window_index"] for trace in bank["traces"]], [1])
            self.assertLessEqual(bank["traces"][0]["outage_ratio"], 0.5)

    def test_summarize_results_uses_metadata_fallbacks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            run_dir = root / "trace-pcc-bulk-rep1"
            run_dir.mkdir()
            (run_dir / "trace.rattan.toml.json").write_text(
                json.dumps(
                    {
                        "trace": {
                            "id": "trace",
                            "corpus": "unit",
                            "network": "lte",
                            "mobility": "driving",
                            "base_rtt_ms": 50,
                            "up_synthesized": True,
                        },
                        "avg_down_mbps": 12.0,
                        "avg_up_mbps": 12.0,
                        "queue_bytes": 131072,
                        "loss_rate": 0.001,
                        "congestion_control": "pcc",
                        "mode": "bulk",
                        "direction": "download",
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "rattan.exit").write_text("7\n", encoding="utf-8")

            subprocess.run(
                [sys.executable, str(RATTAN_DIR / "summarize-results.py"), str(root)],
                check=True,
                stdout=subprocess.DEVNULL,
            )

            with (root / "summary.csv").open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], "rattan_failed")
            self.assertEqual(rows[0]["congestion_control"], "pcc")
            self.assertEqual(rows[0]["mode"], "bulk")
            self.assertEqual(rows[0]["up_synthesized"], "True")
            self.assertEqual(rows[0]["failure_reason"], "rattan exited 7")

    def test_matrix_bulk_download_uses_large_default_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            trace = tmp_path / "trace.bw.json"
            trace.write_text(
                json.dumps(
                    {
                        "RepeatedBwPatternConfig": {
                            "pattern": [
                                {"TraceBwConfig": {"pattern": [["1s", ["10000000bps"]]]}}
                            ],
                            "count": 0,
                        }
                    }
                ),
                encoding="utf-8",
            )
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "traces": [
                            {
                                "id": "synthetic",
                                "corpus": "unit",
                                "network": "wired-wan",
                                "mobility": "fixed",
                                "base_rtt_ms": 40,
                                "subset": ["unit"],
                                "down_trace": str(trace),
                                "up_trace": str(trace),
                                "rattan_down_trace": str(trace),
                                "rattan_up_trace": str(trace),
                                "up_synthesized": True,
                                "avg_down_mbps": 10.0,
                                "avg_up_mbps": 10.0,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            results_root = tmp_path / "results"

            env = {
                **os.environ,
                "RATTAN_TRACE_MANIFEST": str(manifest_path),
                "RATTAN_RESULTS_ROOT": str(results_root),
                "RATTAN_PERF_BIN": str(tmp_path / "coquic-perf"),
                "RATTAN_CONGESTION_CONTROLS": "newreno",
                "RATTAN_MODES": "bulk-download",
                "RATTAN_DURATION": "1s",
            }
            env.pop("RATTAN_RESPONSE_BYTES", None)
            env.pop("RATTAN_BULK_DOWNLOAD_RESPONSE_BYTES", None)

            subprocess.run(
                [
                    str(RATTAN_DIR / "run-rattan-matrix.sh"),
                    "--subset",
                    "unit",
                    "--skip-prepare",
                    "--dry-run",
                ],
                check=True,
                env=env,
                stdout=subprocess.DEVNULL,
            )

            config = next(results_root.glob("synthetic-newreno-bulk-download-rep1/*.toml"))
            self.assertIn("--response-bytes 16777216", config.read_text(encoding="utf-8"))

    def test_matrix_rr_keeps_small_default_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            trace = tmp_path / "trace.bw.json"
            trace.write_text(
                json.dumps(
                    {
                        "RepeatedBwPatternConfig": {
                            "pattern": [
                                {"TraceBwConfig": {"pattern": [["1s", ["10000000bps"]]]}}
                            ],
                            "count": 0,
                        }
                    }
                ),
                encoding="utf-8",
            )
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "traces": [
                            {
                                "id": "synthetic",
                                "corpus": "unit",
                                "network": "wired-wan",
                                "mobility": "fixed",
                                "base_rtt_ms": 40,
                                "subset": ["unit"],
                                "down_trace": str(trace),
                                "up_trace": str(trace),
                                "rattan_down_trace": str(trace),
                                "rattan_up_trace": str(trace),
                                "up_synthesized": True,
                                "avg_down_mbps": 10.0,
                                "avg_up_mbps": 10.0,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            results_root = tmp_path / "results"

            env = {
                **os.environ,
                "RATTAN_TRACE_MANIFEST": str(manifest_path),
                "RATTAN_RESULTS_ROOT": str(results_root),
                "RATTAN_PERF_BIN": str(tmp_path / "coquic-perf"),
                "RATTAN_CONGESTION_CONTROLS": "newreno",
                "RATTAN_MODES": "rr",
                "RATTAN_DURATION": "1s",
            }
            env.pop("RATTAN_RESPONSE_BYTES", None)
            env.pop("RATTAN_BULK_DOWNLOAD_RESPONSE_BYTES", None)

            subprocess.run(
                [
                    str(RATTAN_DIR / "run-rattan-matrix.sh"),
                    "--subset",
                    "unit",
                    "--skip-prepare",
                    "--dry-run",
                ],
                check=True,
                env=env,
                stdout=subprocess.DEVNULL,
            )

            config = next(results_root.glob("synthetic-newreno-rr-rep1/*.toml"))
            self.assertIn("--response-bytes 65536", config.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
