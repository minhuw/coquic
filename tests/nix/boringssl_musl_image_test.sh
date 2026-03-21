#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

nix --option eval-cache false build .#interop-image-boringssl-musl

image_tar="$(nix path-info .#interop-image-boringssl-musl)"
docker load -i "${image_tar}" >/dev/null

base_layers="$(docker image inspect martenseemann/quic-network-simulator-endpoint:latest --format '{{json .RootFS.Layers}}')"
image_layers="$(docker image inspect coquic-interop:boringssl-musl --format '{{json .RootFS.Layers}}')"
entrypoint="$(docker image inspect coquic-interop:boringssl-musl --format '{{json .Config.Entrypoint}}')"

python3 - "${base_layers}" "${image_layers}" "${entrypoint}" <<'PY'
import json
import sys

base_layers = json.loads(sys.argv[1])
image_layers = json.loads(sys.argv[2])
entrypoint = json.loads(sys.argv[3])

if entrypoint != ["/run_endpoint.sh"]:
    raise SystemExit(f"unexpected image entrypoint: {entrypoint!r}")

if image_layers[: len(base_layers)] != base_layers:
    raise SystemExit("image does not preserve the official endpoint base layers")

if len(image_layers) <= len(base_layers):
    raise SystemExit("image did not add overlay layers on top of the official base image")

print(f"base_layers={len(base_layers)}")
print(f"image_layers={len(image_layers)}")
print(f"entrypoint={entrypoint}")
PY
