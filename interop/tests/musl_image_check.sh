#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

image_attr=""
image_tag=""
package_name=""

usage() {
  cat <<'EOF' >&2
Usage:
  musl_image_check.sh --image-attr ATTR --image-tag TAG --package-name NAME
EOF
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --image-attr)
      image_attr="${2:-}"
      shift 2
      ;;
    --image-tag)
      image_tag="${2:-}"
      shift 2
      ;;
    --package-name)
      package_name="${2:-}"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [ -z "${image_attr}" ] || [ -z "${image_tag}" ] || [ -z "${package_name}" ]; then
  usage
fi

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

nix --option eval-cache false build ".#${image_attr}" >/dev/null

image_tar="$(nix path-info ".#${image_attr}")"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
  docker rm -f "${cid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker load -i "${image_tar}" >/dev/null

base_layers="$(docker image inspect martenseemann/quic-network-simulator-endpoint:latest --format '{{json .RootFS.Layers}}')"
image_layers="$(docker image inspect "${image_tag}" --format '{{json .RootFS.Layers}}')"
entrypoint="$(docker image inspect "${image_tag}" --format '{{json .Config.Entrypoint}}')"
binary_target="$(docker run --rm --entrypoint /bin/sh "${image_tag}" -lc 'readlink -f /usr/local/bin/coquic')"
cid="$(docker create "${image_tag}")"
docker cp -L "${cid}:/usr/local/bin/coquic" "${tmpdir}/coquic"
file_output="$(file "${tmpdir}/coquic")"

printf 'binary_target=%s\n' "${binary_target}"
printf 'file=%s\n' "${file_output}"

python3 - "${base_layers}" "${image_layers}" "${entrypoint}" "${binary_target}" "${package_name}" "${file_output}" <<'PY'
import json
import sys

base_layers = json.loads(sys.argv[1])
image_layers = json.loads(sys.argv[2])
entrypoint = json.loads(sys.argv[3])
binary_target = sys.argv[4]
package_name = sys.argv[5]
file_output = sys.argv[6]

if entrypoint != ["/entrypoint.sh"]:
    raise SystemExit(f"unexpected image entrypoint: {entrypoint!r}")

if image_layers[: len(base_layers)] != base_layers:
    raise SystemExit("image does not preserve the official endpoint base layers")

if len(image_layers) <= len(base_layers):
    raise SystemExit("image did not add overlay layers on top of the official base image")

if package_name not in binary_target:
    raise SystemExit(
        f"expected /usr/local/bin/coquic to resolve into {package_name!r}, got: {binary_target}"
    )

if "statically linked" not in file_output:
    raise SystemExit(f"expected a statically linked binary, got: {file_output}")

print(f"base_layers={len(base_layers)}")
print(f"image_layers={len(image_layers)}")
print(f"entrypoint={entrypoint}")
PY
