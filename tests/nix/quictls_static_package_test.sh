#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

nix build .#coquic-quictls >/dev/null
binary="$(readlink -f result/bin/coquic)"
needed="$(readelf -d "${binary}" | grep NEEDED || true)"

if grep -Eq 'lib(ssl|crypto|fmt|spdlog)\.so' <<<"${needed}"; then
  echo "expected static TLS/fmt/spdlog linkage, got:" >&2
  echo "${needed}" >&2
  exit 1
fi
