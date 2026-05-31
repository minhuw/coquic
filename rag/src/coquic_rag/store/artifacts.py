from __future__ import annotations

import json
from pathlib import Path


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_section_records(path: Path, records: list[dict[str, object]]) -> None:
    _write_jsonl(path, records)


def read_section_records(path: Path) -> list[dict[str, object]]:
    return _read_jsonl(path)


def write_graph_nodes(path: Path, records: list[dict[str, object]]) -> None:
    _write_jsonl(path, records)


def read_graph_nodes(path: Path) -> list[dict[str, object]]:
    return _read_jsonl(path)


def write_graph_edges(path: Path, records: list[dict[str, object]]) -> None:
    _write_jsonl(path, records)


def read_graph_edges(path: Path) -> list[dict[str, object]]:
    return _read_jsonl(path)
