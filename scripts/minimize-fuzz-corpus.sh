#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: scripts/minimize-fuzz-corpus.sh <target> [options] [candidate-dir...]

Minimize a target corpus with afl-cmin. By default, the script combines the
prepared seed corpus and the latest AFL queue for the target, then writes raw
minimized inputs under .fuzz/minimized/<target>/.

Options:
  --candidate DIR       Add a candidate input directory.
  --output DIR          Raw minimized corpus output directory.
  --promote             Convert minimized raw inputs into checked-in .hex seeds.
  --replace-promoted    Remove existing fuzz/corpus/<target>/afl_*.hex first.
  --tmin                Run afl-tmin on each afl-cmin output.
  -h, --help            Show this help.
EOF
}

if [ "$#" -lt 1 ]; then
  usage
  exit 2
fi

target="$1"
shift

binary="${COQUIC_FUZZ_OUT_DIR:-$repo_root/.fuzz/bin}/$target"
prepared_corpus="${COQUIC_FUZZ_CORPUS_DIR:-$repo_root/.fuzz/corpus}/$target"
afl_output="${COQUIC_AFL_OUTPUT_DIR:-$repo_root/.fuzz/afl/$target}"
output_dir="$repo_root/.fuzz/minimized/$target"
promote=0
replace_promoted=0
tmin=0
candidates=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --candidate)
      if [ "$#" -lt 2 ]; then
        printf 'error: --candidate requires a directory\n' >&2
        exit 2
      fi
      candidates+=("$2")
      shift 2
      ;;
    --output)
      if [ "$#" -lt 2 ]; then
        printf 'error: --output requires a directory\n' >&2
        exit 2
      fi
      output_dir="$2"
      shift 2
      ;;
    --promote)
      promote=1
      shift
      ;;
    --replace-promoted)
      replace_promoted=1
      shift
      ;;
    --tmin)
      tmin=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      printf 'error: unknown option: %s\n' "$1" >&2
      usage
      exit 2
      ;;
    *)
      candidates+=("$1")
      shift
      ;;
  esac
done

if [ ! -x "$binary" ]; then
  "$repo_root/scripts/build-fuzzers.sh"
fi

"$repo_root/scripts/prepare-fuzz-corpus.sh" "$target"

if [ -d "$prepared_corpus" ]; then
  candidates=("$prepared_corpus" "${candidates[@]}")
fi
if [ -d "$afl_output/default/queue" ]; then
  candidates+=("$afl_output/default/queue")
elif [ -d "$afl_output/queue" ]; then
  candidates+=("$afl_output/queue")
fi

if [ "${#candidates[@]}" -eq 0 ]; then
  printf 'error: no candidate corpus directories found for %s\n' "$target" >&2
  exit 1
fi

work_root="$repo_root/.fuzz/minimize/$target"
merged_input="$work_root/input"
cmin_output="$work_root/cmin"
tmin_output="$work_root/tmin"
rm -rf "$work_root"
mkdir -p "$merged_input"

python3 - "$merged_input" "${candidates[@]}" <<'PY'
from pathlib import Path
import hashlib
import shutil
import sys

output = Path(sys.argv[1])
candidate_dirs = [Path(value) for value in sys.argv[2:]]

seen: set[str] = set()
count = 0

def normalized(path: Path) -> Path:
    if (path / "default" / "queue").is_dir():
        return path / "default" / "queue"
    if (path / "queue").is_dir():
        return path / "queue"
    return path

for candidate_dir in candidate_dirs:
    candidate_dir = normalized(candidate_dir)
    if not candidate_dir.is_dir():
        print(f"warning: skipping missing candidate directory: {candidate_dir}", file=sys.stderr)
        continue
    for source in sorted(path for path in candidate_dir.iterdir() if path.is_file()):
        if source.name == "README.txt" or source.name.startswith("."):
            continue
        data = source.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        shutil.copyfile(source, output / f"id_{count:06d}_{digest[:16]}")
        count += 1

print(count)
PY

candidate_count=$(find "$merged_input" -maxdepth 1 -type f | wc -l)
if [ "$candidate_count" -eq 0 ]; then
  printf 'error: no candidate files found for %s\n' "$target" >&2
  exit 1
fi

printf 'merged %s unique candidate inputs for %s\n' "$candidate_count" "$target"
rm -rf "$cmin_output"
mkdir -p "$(dirname "$cmin_output")"

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-1}"
export AFL_NO_UI="${AFL_NO_UI:-1}"

afl-cmin -m none -i "$merged_input" -o "$cmin_output" -- "$binary" @@

final_output="$cmin_output"
if [ "$tmin" -eq 1 ]; then
  rm -rf "$tmin_output"
  mkdir -p "$tmin_output"
  for seed in "$cmin_output"/*; do
    [ -f "$seed" ] || continue
    afl-tmin -m none -i "$seed" -o "$tmin_output/$(basename "$seed")" -- "$binary" @@
  done
  final_output="$tmin_output"
fi

rm -rf "$output_dir"
mkdir -p "$(dirname "$output_dir")"
cp -a "$final_output" "$output_dir"

minimized_count=$(find "$output_dir" -maxdepth 1 -type f | wc -l)
candidate_bytes=$(find "$merged_input" -maxdepth 1 -type f -printf '%s\n' | awk '{s += $1} END {print s + 0}')
minimized_bytes=$(find "$output_dir" -maxdepth 1 -type f -printf '%s\n' | awk '{s += $1} END {print s + 0}')
printf 'minimized %s inputs (%s bytes) to %s inputs (%s bytes) at %s\n' \
  "$candidate_count" "$candidate_bytes" "$minimized_count" "$minimized_bytes" "$output_dir"

if [ "$promote" -eq 1 ]; then
  promote_dir="$repo_root/fuzz/corpus/$target"
  mkdir -p "$promote_dir"
  if [ "$replace_promoted" -eq 1 ]; then
    find "$promote_dir" -maxdepth 1 -type f -name 'afl_*.hex' -delete
  fi
  python3 - "$output_dir" "$promote_dir" <<'PY'
from pathlib import Path
import hashlib
import sys

source_dir = Path(sys.argv[1])
promote_dir = Path(sys.argv[2])

def parse_hex_seed(path: Path) -> bytes:
    text = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text.append("".join(line.split("#", 1)[0].split()))
    return bytes.fromhex("".join(text))

existing: set[str] = set()
for seed in sorted(promote_dir.glob("*.hex")):
    existing.add(hashlib.sha256(parse_hex_seed(seed)).hexdigest())

promoted = 0
for source in sorted(path for path in source_dir.iterdir() if path.is_file()):
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest in existing:
        continue
    lines = [data[i : i + 16].hex(" ") for i in range(0, len(data), 16)]
    if not lines:
        lines = [""]
    output = promote_dir / f"afl_{digest[:16]}.hex"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    existing.add(digest)
    promoted += 1

print(promoted)
PY
  promoted_count=$(find "$promote_dir" -maxdepth 1 -type f -name 'afl_*.hex' | wc -l)
  printf 'promoted minimized seeds into %s (%s afl_*.hex files present)\n' \
    "$promote_dir" "$promoted_count"
fi
