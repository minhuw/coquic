#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

nix --option eval-cache false build .#interop-image-quictls >/dev/null

image_tar="$(nix path-info .#interop-image-quictls)"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
  docker rm -f "${cid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker load -i "${image_tar}" >/dev/null
cid="$(docker create coquic-interop:quictls)"
docker cp -L "${cid}:/usr/local/bin/coquic" "${tmpdir}/coquic"

file_output="$(file "${tmpdir}/coquic")"
echo "${file_output}"

if ! grep -q "statically linked" <<<"${file_output}"; then
  echo "expected /usr/local/bin/coquic to be statically linked" >&2
  exit 1
fi
