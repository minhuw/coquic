#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

output_dir="$(mktemp -d)"
safety_repo="$(mktemp -d)"
cleanup() {
  rm -rf "${output_dir}"
  rm -rf "${safety_repo}"
}
trap cleanup EXIT

packaged_output_dir="$(demo/deploy/package-demo.sh "${output_dir}")"

if [[ "${packaged_output_dir}" != "${output_dir}" ]]; then
  echo "package script reported unexpected output dir: ${packaged_output_dir}" >&2
  exit 1
fi

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
  "!demo/site/**"; do
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
  "coquic.minhuw.dev:4433" \
  "/_coquic/inspect" \
  "/_coquic/echo" \
  "localStorage" \
  "window.location" \
  "How To Verify In Chrome" \
  "safeStorageGet" \
  "safeStorageSet" \
  "safeReadJson" \
  "runProbe"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/index.html"; then
    echo "packaged demo page missing marker: ${marker}" >&2
    exit 1
  fi
done

if [[ -e tests/nix/h3_demo_page_contract_test.sh ]]; then
  echo "obsolete test still present: tests/nix/h3_demo_page_contract_test.sh" >&2
  exit 1
fi

install -d "${safety_repo}/demo/deploy" "${safety_repo}/demo/site"
cp demo/deploy/package-demo.sh "${safety_repo}/demo/deploy/package-demo.sh"
cp demo/site/index.html "${safety_repo}/demo/site/index.html"

set +e
overlap_output="$("${safety_repo}/demo/deploy/package-demo.sh" "${safety_repo}/demo/site" 2>&1)"
overlap_status=$?
set -e

if [[ ${overlap_status} -eq 0 ]]; then
  echo "expected overlap output path to be rejected" >&2
  exit 1
fi

if [[ "${overlap_output}" != *"must not be demo/site or inside it"* ]]; then
  echo "unexpected overlap rejection output: ${overlap_output}" >&2
  exit 1
fi

if [[ ! -f "${safety_repo}/demo/site/index.html" ]]; then
  echo "overlap rejection did not preserve demo/site source content" >&2
  exit 1
fi

echo "demo package contract looks correct"
