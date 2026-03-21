#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

nix --option eval-cache false build .#coquic-boringssl-musl

binary="$(nix path-info .#coquic-boringssl-musl)/bin/coquic"
file_output="$(file "${binary}")"
ldd_output="$(ldd "${binary}" 2>&1 || true)"

printf 'file: %s\n' "${file_output}"
printf 'ldd: %s\n' "${ldd_output}"

case "${ldd_output}" in
  *"not a dynamic executable"* | *"statically linked"*)
    ;;
  *)
    echo "expected a static musl-linked binary" >&2
    exit 1
    ;;
esac
