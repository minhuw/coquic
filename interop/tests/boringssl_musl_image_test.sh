#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

bash interop/tests/musl_image_check.sh \
  --image-attr interop-image-boringssl-musl \
  --image-tag coquic-interop:boringssl-musl \
  --package-name coquic-boringssl-musl
