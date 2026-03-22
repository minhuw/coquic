#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

for tool in docker file nix; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "error: required tool not found: ${tool}" >&2
    exit 1
  fi
done

if ! docker cp --help 2>&1 | grep -q -- '--follow-link'; then
  echo "error: docker cp does not support -L/--follow-link" >&2
  exit 1
fi

nix --option eval-cache false build .#interop-image-quictls >/dev/null

image_tar="$(nix path-info .#interop-image-quictls)"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
  docker rm -f "${cid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker load -i "${image_tar}" >/dev/null
binary_target="$(docker run --rm --entrypoint /bin/sh coquic-interop:quictls -lc 'readlink -f /usr/local/bin/coquic')"
cid="$(docker create coquic-interop:quictls)"
docker cp -L "${cid}:/usr/local/bin/coquic" "${tmpdir}/coquic"

echo "${binary_target}"
file_output="$(file "${tmpdir}/coquic")"
echo "${file_output}"

if [[ "${binary_target}" != *"coquic-quictls-musl"* ]]; then
  echo "expected /usr/local/bin/coquic to resolve to the musl package, got: ${binary_target}" >&2
  exit 1
fi

if ! grep -q "statically linked" <<<"${file_output}"; then
  echo "expected /usr/local/bin/coquic to be statically linked" >&2
  exit 1
fi
