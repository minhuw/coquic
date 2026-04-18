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
  "coquic-demo-v1" \
  "https://coquic.minhuw.dev/" \
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

run_rejection_case() {
  local target_suffix="$1"

  local case_repo
  case_repo="$(mktemp -d "${safety_repo}/case.XXXXXX")"
  install -d "${case_repo}/demo/deploy" "${case_repo}/demo/site"
  cp demo/deploy/package-demo.sh "${case_repo}/demo/deploy/package-demo.sh"
  cp demo/site/index.html "${case_repo}/demo/site/index.html"

  local target_path="${case_repo}/${target_suffix}"

  set +e
  local rejection_output
  rejection_output="$("${case_repo}/demo/deploy/package-demo.sh" "${target_path}" 2>&1)"
  local rejection_status=$?
  set -e

  if [[ ${rejection_status} -eq 0 ]]; then
    echo "expected dangerous output path to be rejected: ${target_suffix}" >&2
    exit 1
  fi

  if [[ "${rejection_output}" != *"must not overlap demo/site ancestry"* ]]; then
    echo "unexpected overlap rejection output for ${target_suffix}: ${rejection_output}" >&2
    exit 1
  fi

  if [[ ! -f "${case_repo}/demo/site/index.html" ]]; then
    echo "overlap rejection did not preserve demo/site source content for ${target_suffix}" >&2
    exit 1
  fi
}

run_rejection_case "demo/site"
run_rejection_case "demo"
run_rejection_case "."

run_missing_source_case() {
  local case_repo
  case_repo="$(mktemp -d "${safety_repo}/case.XXXXXX")"
  install -d "${case_repo}/demo/deploy"
  cp demo/deploy/package-demo.sh "${case_repo}/demo/deploy/package-demo.sh"

  set +e
  local failure_output
  failure_output="$("${case_repo}/demo/deploy/package-demo.sh" "${case_repo}/out" 2>&1)"
  local failure_status=$?
  set -e

  if [[ ${failure_status} -eq 0 ]]; then
    echo "expected missing source directory to be rejected" >&2
    exit 1
  fi

  if [[ "${failure_output}" != *"missing demo/site source directory"* ]]; then
    echo "unexpected missing-source rejection output: ${failure_output}" >&2
    exit 1
  fi
}

run_missing_index_case() {
  local case_repo
  case_repo="$(mktemp -d "${safety_repo}/case.XXXXXX")"
  install -d "${case_repo}/demo/deploy" "${case_repo}/demo/site"
  cp demo/deploy/package-demo.sh "${case_repo}/demo/deploy/package-demo.sh"
  printf 'sentinel\n' > "${case_repo}/demo/site/sentinel.txt"

  set +e
  local failure_output
  failure_output="$("${case_repo}/demo/deploy/package-demo.sh" "${case_repo}/out" 2>&1)"
  local failure_status=$?
  set -e

  if [[ ${failure_status} -eq 0 ]]; then
    echo "expected missing index.html in source to be rejected" >&2
    exit 1
  fi

  if [[ "${failure_output}" != *"packaged demo site is missing index.html"* ]]; then
    echo "unexpected missing-index rejection output: ${failure_output}" >&2
    exit 1
  fi

  if [[ ! -f "${case_repo}/demo/site/sentinel.txt" ]]; then
    echo "missing-index rejection did not preserve demo/site contents" >&2
    exit 1
  fi
}

run_missing_source_case
run_missing_index_case

echo "demo package contract looks correct"
