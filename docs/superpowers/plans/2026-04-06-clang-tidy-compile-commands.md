# Clang-Tidy Compile Commands Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the missing `compile_commands.json` path and the serial `clang-tidy` wrapper so local and CI lint use a real compilation database and parallel execution without weakening the configured checks.

**Architecture:** Add a build-only `compdb` Zig step, generate `compile_commands.json` by parsing `zig build compdb --verbose-cc`, then switch the repository wrapper from hand-built per-file flags to `clang-tidy -p .` in parallel. Keep the current check set unchanged and warm the database explicitly in CI before lint.

**Tech Stack:** Zig build graph, Bash, Python 3, Nix dev shell, `clang-tidy`, GitHub Actions

---

## File Map

- Create `scripts/compile-commands-from-verbose-cc.py`: parse `zig --verbose-cc` output into `compile_commands.json`.
- Create `scripts/refresh-compile-commands.sh`: rebuild the compilation database when it is missing or stale.
- Modify `build.zig`: add a `compdb` step that compiles the test binary without running it.
- Modify `scripts/run-clang-tidy.sh`: replace the serial manual-flag path with parallel `clang-tidy -p`.
- Modify `flake.nix`: prefer Nix-provided LLVM clang/clang-tidy tools in the default dev shell.
- Modify `.github/workflows/ci.yml`: refresh `compile_commands.json` before lint.
- Modify `.gitignore`: ignore generated `compile_commands.json`.

### Task 1: Add A Build-Only `compdb` Step

**Files:**
- Modify: `build.zig`

- [ ] **Step 1: Prove the `compdb` step does not exist yet**

Run:

```bash
nix develop -c bash -lc 'zig build -l | rg "^  compdb"'
```

Expected: no output and exit status `1`.

- [ ] **Step 2: Add the new build step**

Update `build.zig` immediately after the existing `test` step definition:

```zig
    const test_step = b.step("test", "Run the GoogleTest suite");
    test_step.dependOn(&smoke_run.step);

    const compdb_step = b.step(
        "compdb",
        "Build the GoogleTest binary without running it",
    );
    compdb_step.dependOn(&smoke.step);
```

- [ ] **Step 3: Verify the new step is discoverable**

Run:

```bash
nix develop -c bash -lc 'zig build -l | rg "^  compdb"'
```

Expected: one matching line for the new `compdb` step.

- [ ] **Step 4: Commit the build-graph change**

Run:

```bash
git add build.zig
git commit -m "build: add compdb step for clang-tidy"
```

### Task 2: Generate `compile_commands.json` From Zig `--verbose-cc`

**Files:**
- Create: `scripts/compile-commands-from-verbose-cc.py`
- Create: `scripts/refresh-compile-commands.sh`
- Modify: `.gitignore`

- [ ] **Step 1: Prove the refresh path is missing**

Run:

```bash
rm -f compile_commands.json
nix develop -c bash -lc './scripts/refresh-compile-commands.sh'
```

Expected: shell error because `scripts/refresh-compile-commands.sh` does not exist yet.

- [ ] **Step 2: Add the verbose-cc parser**

Create `scripts/compile-commands-from-verbose-cc.py`:

```python
#!/usr/bin/env python3

import json
import pathlib
import shlex
import sys


def is_project_file(path: pathlib.Path, repo_root: pathlib.Path) -> bool:
    try:
        relative = path.resolve().relative_to(repo_root)
    except ValueError:
        return False
    return bool(relative.parts) and relative.parts[0] in {"src", "tests"}


def normalize_arguments(argv: list[str]) -> list[str]:
    source_path = pathlib.Path(argv[2])
    driver = "clang" if source_path.suffix == ".c" else "clang++"
    return [driver] + argv[2:]


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: compile-commands-from-verbose-cc.py <repo-root>"
        )

    repo_root = pathlib.Path(sys.argv[1]).resolve()
    entries_by_file: dict[str, dict[str, object]] = {}

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if " zig clang " not in f" {line} ":
            continue

        try:
            argv = shlex.split(line)
        except ValueError:
            continue

        if len(argv) < 4 or argv[1] != "clang" or "-c" not in argv:
            continue

        source_path = pathlib.Path(argv[2]).resolve()
        if not is_project_file(source_path, repo_root):
            continue

        entries_by_file[str(source_path)] = {
            "directory": str(repo_root),
            "file": str(source_path),
            "arguments": normalize_arguments(argv),
        }

    entries = [entries_by_file[key] for key in sorted(entries_by_file)]
    if not entries:
        raise SystemExit(
            "no compile commands captured from zig --verbose-cc output"
        )

    json.dump(entries, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Add the refresh script and ignore the generated database**

Create `scripts/refresh-compile-commands.sh`:

```bash
#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
compile_commands="${repo_root}/compile_commands.json"

inputs=(
    "${repo_root}/build.zig"
    "${repo_root}/flake.nix"
    "${repo_root}/flake.lock"
    "${repo_root}/.clang-tidy"
    "${repo_root}/scripts/compile-commands-from-verbose-cc.py"
    "${repo_root}/scripts/refresh-compile-commands.sh"
    "${repo_root}/scripts/run-clang-tidy.sh"
)

needs_refresh=0
if [ ! -f "${compile_commands}" ]; then
    needs_refresh=1
else
    for input in "${inputs[@]}"; do
        if [ "${input}" -nt "${compile_commands}" ]; then
            needs_refresh=1
            break
        fi
    done
fi

if [ "${needs_refresh}" -eq 0 ]; then
    exit 0
fi

cache_root="${repo_root}/.zig-cache/compile-commands"
local_cache="${cache_root}/local"
global_cache="${cache_root}/global"

rm -rf "${cache_root}"
mkdir -p "${local_cache}" "${global_cache}"

tmp_output="$(mktemp "${repo_root}/compile_commands.json.tmp.XXXXXX")"
trap 'rm -f "${tmp_output}"' EXIT

cd "${repo_root}"
zig build compdb \
    --summary none \
    --verbose-cc \
    --cache-dir "${local_cache}" \
    --global-cache-dir "${global_cache}" \
    2>&1 | python3 "${repo_root}/scripts/compile-commands-from-verbose-cc.py" "${repo_root}" > "${tmp_output}"

mv "${tmp_output}" "${compile_commands}"
```

Append this line to `.gitignore`:

```gitignore
compile_commands.json
```

Then make the refresh script executable:

```bash
chmod +x scripts/refresh-compile-commands.sh
```

- [ ] **Step 4: Verify database generation works and is non-empty**

Run:

```bash
rm -f compile_commands.json
nix develop -c bash -lc './scripts/refresh-compile-commands.sh && python3 - <<'"'"'PY'"'"'
import json
from pathlib import Path

path = Path("compile_commands.json")
assert path.exists(), "compile_commands.json was not created"
entries = json.loads(path.read_text())
assert entries, "compile_commands.json is empty"
assert any(entry["file"].endswith("tests/quic_core_test.cpp") for entry in entries)
assert any(entry["file"].endswith("src/quic/connection.cpp") for entry in entries)
print(len(entries))
PY'
```

Expected: the Python assertion block passes and prints a positive entry count.

- [ ] **Step 5: Commit the compile-database generator**

Run:

```bash
git add .gitignore scripts/compile-commands-from-verbose-cc.py scripts/refresh-compile-commands.sh
git commit -m "build: generate compile commands from zig verbose-cc"
```

### Task 3: Switch The Wrapper To Parallel `clang-tidy -p`

**Files:**
- Modify: `scripts/run-clang-tidy.sh`
- Modify: `flake.nix`

- [ ] **Step 1: Prove the current wrapper is the serial manual-flag version**

Run:

```bash
rg -n 'for file in "\\$@"|clang_extra_args|NIX_CFLAGS_COMPILE=' scripts/run-clang-tidy.sh
```

Expected: matches showing the existing serial loop and manual compiler-flag assembly.

- [ ] **Step 2: Replace the wrapper and prefer Nix LLVM tooling in the dev shell**

Update `scripts/run-clang-tidy.sh` to:

```bash
#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

"${repo_root}/scripts/refresh-compile-commands.sh"

job_count="${COQUIC_CLANG_TIDY_JOBS:-}"
if [ -z "${job_count}" ]; then
    job_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
fi
if [ -z "${job_count}" ]; then
    job_count="$(nproc 2>/dev/null || true)"
fi
if [ -z "${job_count}" ]; then
    job_count=4
fi

export COQUIC_CLANG_TIDY_REPO_ROOT="${repo_root}"

printf '%s\0' "$@" | xargs -0 -P "${job_count}" -I{} bash -lc '
    clang-tidy \
        --quiet \
        --config-file="${COQUIC_CLANG_TIDY_REPO_ROOT}/.clang-tidy" \
        -p "${COQUIC_CLANG_TIDY_REPO_ROOT}" \
        "$1"
' _ {}
```

Update the `defaultShell` `extraPackages` list in `flake.nix` to:

```nix
        extraPackages = [
          llvmPkgs.clang
          llvmPkgs.clang-tools
          pkgs.lldb
          boringssl
          pkgs.python3
          pkgs.qdrant
          pkgs.wireshark
        ];
```

This replaces the current `pkgs.clang-tools` entry with LLVM 20 `clang` and
`clang-tools`, keeping the clang driver and clang-tidy tooling on a matched Nix
toolchain.

- [ ] **Step 3: Verify the shell exposes the expected tools and the wrapper passes**

Run:

```bash
nix develop -c bash -lc 'command -v clang++ && command -v clang-tidy'
nix develop -c ./scripts/run-clang-tidy.sh src/quic/http3_qpack.cpp tests/quic_http3_qpack_test.cpp
```

Expected: `clang++` and `clang-tidy` resolve to Nix store paths, and the wrapper exits successfully.

- [ ] **Step 4: Commit the wrapper/toolchain change**

Run:

```bash
git add flake.nix scripts/run-clang-tidy.sh
git commit -m "build: parallelize clang-tidy wrapper"
```

### Task 4: Warm The Database In CI And Run Full Verification

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Prove CI does not warm the database yet**

Run:

```bash
rg -n 'refresh-compile-commands|compile_commands.json' .github/workflows/ci.yml
```

Expected: no matches.

- [ ] **Step 2: Add the CI warmup step**

Insert this step between `Format Check` and `Lint` in `.github/workflows/ci.yml`:

```yaml
      - name: Refresh compile_commands.json
        run: nix develop -c ./scripts/refresh-compile-commands.sh
```

- [ ] **Step 3: Run the repo verification commands**

Run:

```bash
nix develop -c ./scripts/refresh-compile-commands.sh
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build test
```

Expected: all commands succeed.

- [ ] **Step 4: Commit the CI integration**

Run:

```bash
git add .github/workflows/ci.yml
git commit -m "ci: warm compile commands before lint"
```
