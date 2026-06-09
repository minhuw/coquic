#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$repo_root/fuzz/corpus"
output_dir="${COQUIC_FUZZ_CORPUS_DIR:-$repo_root/.fuzz/corpus}"
target="${1:-}"

python3 - "$source_dir" "$output_dir" "$target" <<'PY'
from pathlib import Path
import shutil
import sys
import tempfile

source_dir = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
requested_target = sys.argv[3]

if not source_dir.is_dir():
    raise SystemExit(f"missing source corpus directory: {source_dir}")

output_dir.mkdir(parents=True, exist_ok=True)

target_dirs = sorted(path for path in source_dir.iterdir() if path.is_dir())
if requested_target:
    target_dirs = [path for path in target_dirs if path.name == requested_target]
    if not target_dirs:
        raise SystemExit(f"missing source corpus target: {requested_target}")

for target_dir in target_dirs:
    target_output = output_dir / target_dir.name
    temp_path = Path(
        tempfile.mkdtemp(prefix=f".{target_dir.name}.", suffix=".tmp", dir=output_dir)
    )

    try:
        for seed in sorted(target_dir.glob("*.hex")):
            hex_text = []
            for line in seed.read_text(encoding="utf-8").splitlines():
                hex_text.append("".join(line.split("#", 1)[0].split()))
            raw = bytes.fromhex("".join(hex_text))
            (temp_path / seed.stem).write_bytes(raw)

        previous_path = target_output.with_name(f".{target_output.name}.previous")
        if target_output.exists():
            if previous_path.exists():
                shutil.rmtree(previous_path)
            target_output.rename(previous_path)
        temp_path.rename(target_output)
        if previous_path.exists():
            shutil.rmtree(previous_path)
    except Exception:
        if "previous_path" in locals() and previous_path.exists() and not target_output.exists():
            previous_path.rename(target_output)
        shutil.rmtree(temp_path, ignore_errors=True)
        raise

    print(f"prepared {target_dir.name} seeds in {target_output}")
PY
