#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

output_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${output_dir}"
}
trap cleanup EXIT

demo/deploy/package-demo.sh "${output_dir}" >/dev/null

if [[ ! -f demo/site/index.html ]]; then
  echo "missing demo/site/index.html" >&2
  exit 1
fi

if [[ ! -f "${output_dir}/index.html" ]]; then
  echo "missing packaged index.html" >&2
  exit 1
fi

if ! cmp -s demo/site/index.html "${output_dir}/index.html"; then
  echo "packaged site does not match demo/site source" >&2
  exit 1
fi

if ! grep -Fq 'COPY demo/site /app/www' docker/h3-server/Dockerfile; then
  echo "docker/h3-server/Dockerfile does not copy demo/site" >&2
  exit 1
fi

for dockerignore_rule in \
  "!demo/" \
  "!demo/site/" \
  "!demo/site/index.html"; do
  if ! grep -Fxq -- "${dockerignore_rule}" .dockerignore; then
    echo ".dockerignore missing required demo whitelist rule: ${dockerignore_rule}" >&2
    exit 1
  fi
done

for marker in \
  "Showcase" \
  "Technical" \
  "Run Live Checks" \
  "Browser Verification" \
  "coquic.minhuw.dev:4433"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/index.html"; then
    echo "packaged demo page missing marker: ${marker}" >&2
    exit 1
  fi
done

echo "demo package contract looks correct"
