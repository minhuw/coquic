#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Counter:
    covered: int = 0
    total: int = 0

    @property
    def percent(self) -> float:
        if self.total == 0:
            return 100.0
        return self.covered * 100.0 / self.total


def source_key(path: str) -> str:
    marker = "/src/"
    if marker in path:
        return path.split(marker, 1)[1]
    return path


def component_for(path: str) -> str:
    relative = source_key(path)
    parts = relative.split("/")
    if len(parts) >= 2:
        return parts[0]
    return "root"


def parse_lcov(path: pathlib.Path) -> tuple[list[dict], dict[str, Counter], dict[str, Counter]]:
    files: list[dict] = []
    totals = {
        "functions": Counter(),
        "lines": Counter(),
        "branches": Counter(),
    }
    components: dict[str, dict[str, Counter]] = defaultdict(
        lambda: {
            "functions": Counter(),
            "lines": Counter(),
            "branches": Counter(),
        }
    )

    current_path: str | None = None
    current = {
        "functions": Counter(),
        "lines": Counter(),
        "branches": Counter(),
    }

    def finish_record() -> None:
        nonlocal current_path, current
        if current_path is None:
            return

        relative_path = source_key(current_path)
        component = component_for(current_path)
        file_metrics = {
            name: {
                "covered": counter.covered,
                "total": counter.total,
                "percent": round(counter.percent, 2),
            }
            for name, counter in current.items()
        }
        files.append(
            {
                "path": relative_path,
                "component": component,
                "metrics": file_metrics,
            }
        )

        for name, counter in current.items():
            totals[name].covered += counter.covered
            totals[name].total += counter.total
            components[component][name].covered += counter.covered
            components[component][name].total += counter.total

        current_path = None
        current = {
            "functions": Counter(),
            "lines": Counter(),
            "branches": Counter(),
        }

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("SF:"):
            finish_record()
            current_path = line[3:]
        elif line.startswith("FNF:"):
            current["functions"].total = int(line[4:])
        elif line.startswith("FNH:"):
            current["functions"].covered = int(line[4:])
        elif line.startswith("LF:"):
            current["lines"].total = int(line[3:])
        elif line.startswith("LH:"):
            current["lines"].covered = int(line[3:])
        elif line.startswith("BRF:"):
            current["branches"].total = int(line[4:])
        elif line.startswith("BRH:"):
            current["branches"].covered = int(line[4:])
        elif line == "end_of_record":
            finish_record()
    finish_record()

    return files, totals, components


def metric_payload(counter: Counter) -> dict:
    return {
        "covered": counter.covered,
        "total": counter.total,
        "percent": round(counter.percent, 2),
    }


def render_summary(payload: dict) -> None:
    print("## Coverage")
    print()
    print(f"- Generated: `{payload['generated_at']}`")
    print(f"- Commit: `{payload['commit']}`")
    print(f"- Report: {payload['report_url']}")
    print()
    print("| Metric | Covered | Total | Percent |")
    print("| --- | ---: | ---: | ---: |")
    for label, key in (("Functions", "functions"), ("Lines", "lines"), ("Branches", "branches")):
        metric = payload["totals"][key]
        print(f"| {label} | {metric['covered']} | {metric['total']} | {metric['percent']:.2f}% |")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lcov", required=True, type=pathlib.Path)
    parser.add_argument("--report-url", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--json-out", required=True, type=pathlib.Path)
    args = parser.parse_args()

    files, totals, components = parse_lcov(args.lcov)
    component_rows = [
        {
            "name": name,
            "metrics": {metric: metric_payload(counter) for metric, counter in counters.items()},
        }
        for name, counters in sorted(components.items())
    ]
    uncovered_files = sorted(
        files,
        key=lambda item: (
            item["metrics"]["lines"]["percent"],
            item["metrics"]["branches"]["percent"],
            item["path"],
        ),
    )[:12]

    payload = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event_name": args.event_name,
        "commit": args.commit,
        "report_url": args.report_url,
        "totals": {metric: metric_payload(counter) for metric, counter in totals.items()},
        "components": component_rows,
        "files": files,
        "least_covered_files": uncovered_files,
    }

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    render_summary(payload)


if __name__ == "__main__":
    main()
