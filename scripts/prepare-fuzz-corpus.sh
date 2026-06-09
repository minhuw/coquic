#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$repo_root/fuzz/corpus"
output_dir="${COQUIC_FUZZ_CORPUS_DIR:-$repo_root/.fuzz/corpus}"
target="${1:-}"
generated_dir="${COQUIC_FUZZ_GENERATED_CORPUS_DIR:-$repo_root/.fuzz/generated-corpus}"
generator="${COQUIC_FUZZ_OUT_DIR:-$repo_root/.fuzz/bin}/generate_corpus"

if [ "${COQUIC_FUZZ_SKIP_GENERATED_CORPUS:-0}" != "1" ]; then
  if [ ! -x "$generator" ]; then
    "$repo_root/scripts/build-fuzzers.sh"
  fi
  rm -rf "$generated_dir"
  "$generator" "$generated_dir"
fi

python3 - "$source_dir" "$generated_dir" "$output_dir" "$target" <<'PY'
from pathlib import Path
import shutil
import sys
import tempfile

source_dir = Path(sys.argv[1])
generated_dir = Path(sys.argv[2])
output_dir = Path(sys.argv[3])
requested_target = sys.argv[4]

if not source_dir.is_dir():
    raise SystemExit(f"missing source corpus directory: {source_dir}")

output_dir.mkdir(parents=True, exist_ok=True)

target_names = {path.name for path in source_dir.iterdir() if path.is_dir()}
if generated_dir.is_dir():
    target_names.update(path.name for path in generated_dir.iterdir() if path.is_dir())

target_dirs = [(source_dir / name, generated_dir / name, name) for name in sorted(target_names)]
if requested_target:
    target_dirs = [entry for entry in target_dirs if entry[2] == requested_target]
    if not target_dirs:
        raise SystemExit(f"missing source corpus target: {requested_target}")

for source_target_dir, generated_target_dir, target_name in target_dirs:
    target_output = output_dir / target_name
    temp_path = Path(
        tempfile.mkdtemp(prefix=f".{target_name}.", suffix=".tmp", dir=output_dir)
    )

    try:
        for seed in sorted(source_target_dir.glob("*.hex")):
            hex_text = []
            for line in seed.read_text(encoding="utf-8").splitlines():
                hex_text.append("".join(line.split("#", 1)[0].split()))
            raw = bytes.fromhex("".join(hex_text))
            (temp_path / seed.stem).write_bytes(raw)

        if generated_target_dir.is_dir():
            for seed in sorted(path for path in generated_target_dir.iterdir() if path.is_file()):
                (temp_path / seed.name).write_bytes(seed.read_bytes())

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

    print(f"prepared {target_name} seeds in {target_output}")
PY
