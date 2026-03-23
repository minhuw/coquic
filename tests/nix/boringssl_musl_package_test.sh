#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

bash tests/nix/musl_package_check.sh \
  --package-attr coquic-boringssl-musl
