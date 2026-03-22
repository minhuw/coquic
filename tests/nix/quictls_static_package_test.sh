#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

nix build .#coquic-quictls >/dev/null
binary="$(readlink -f result/bin/coquic)"
needed="$(readelf -d "${binary}" | grep NEEDED || true)"
runpath="$(readelf -d "${binary}" | grep -E 'RUNPATH|RPATH' || true)"
openssldir="$(strings -a "${binary}" | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p' | head -n 1 || true)"

if grep -Eq 'lib(ssl|crypto|fmt|spdlog)\.so' <<<"${needed}"; then
  echo "expected static TLS/fmt/spdlog linkage, got:" >&2
  echo "${needed}" >&2
  exit 1
fi

if grep -Eq '\[[^]]+\]' <<<"${runpath}"; then
  echo "expected empty RUNPATH/RPATH for static package, got:" >&2
  echo "${runpath}" >&2
  exit 1
fi

if [[ -n "${openssldir}" &&
  "${openssldir}" == /nix/store/* &&
  "${openssldir}" != /nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-* &&
  ! -d "${openssldir}" ]]; then
  echo "binary OPENSSLDIR points at missing store path: ${openssldir}" >&2
  exit 1
fi
