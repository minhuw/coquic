#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

output_dir="$(mktemp -d)"
safety_repo="$(mktemp -d)"
wasm_source_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${output_dir}"
  rm -rf "${safety_repo}"
  rm -rf "${wasm_source_dir}"
}
trap cleanup EXIT

cp -R demo/wasm-quic/. "${wasm_source_dir}/"
printf '\0asm\1\0\0\0' > "${wasm_source_dir}/coquic-wasm-quic.wasm"

packaged_output_dir="$(demo/deploy/package-demo.sh "${output_dir}" "${wasm_source_dir}")"

if [[ "${packaged_output_dir}" != "${output_dir}" ]]; then
  echo "package script reported unexpected output dir: ${packaged_output_dir}" >&2
  exit 1
fi

if [[ -e demo/site/index.html ]]; then
  echo "legacy demo/site/index.html should not exist" >&2
  exit 1
fi

for packaged_file in index.html workbench.html demo-theme.css coquic-logo.svg quic-demo.js perf-comparison.html perf-comparison.js interop-results.html interop-results.js coverage-results.html coverage-results.js coquic-wasm-quic.wasm; do
  if [[ ! -f "${output_dir}/${packaged_file}" ]]; then
    echo "missing packaged wasm demo file: ${packaged_file}" >&2
    exit 1
  fi
  if ! cmp -s "${wasm_source_dir}/${packaged_file}" "${output_dir}/${packaged_file}"; then
    echo "packaged wasm demo file does not match source: ${packaged_file}" >&2
    exit 1
  fi
done

if ! grep -Fq 'requested_source_dir="${2:-${repo_root}/zig-out/share/wasm-quic}"' demo/deploy/package-demo.sh; then
  echo "package script should default to the built wasm demo output" >&2
  exit 1
fi

if ! grep -Fq 'COPY zig-out/share/wasm-quic /app/www' demo/h3-server/Dockerfile; then
  echo "demo/h3-server/Dockerfile does not copy built wasm demo output" >&2
  exit 1
fi

for dockerignore_rule in \
  "!demo/" \
  "!demo/h3-server/" \
  "!demo/h3-server/Dockerfile" \
  "!zig-out/" \
  "!zig-out/bin/" \
  "!zig-out/bin/h3-server" \
  "!zig-out/share/" \
  "!zig-out/share/wasm-quic/" \
  "!zig-out/share/wasm-quic/**"; do
  if ! grep -Fxq -- "${dockerignore_rule}" .dockerignore; then
    echo ".dockerignore missing required demo whitelist rule: ${dockerignore_rule}" >&2
    exit 1
  fi
done

for marker in \
  "coquic-wasm-demo-v1" \
  "coquic-demo-home-v1" \
  "from Prompt to Packet." \
  "codex-word" \
  "quic-word" \
  "slogan-hero" \
  "slogan-logo" \
  "coquic-logo.svg" \
  "demo-theme.css" \
  "workbench.html" \
  "perf-comparison.html" \
  "interop-results.html" \
  "coverage-results.html"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/index.html"; then
    echo "packaged demo homepage missing marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  "coquic-wasm-demo-v1" \
  "coquic wasm QUIC" \
  "coquic-logo.svg" \
  "Datagram And Event Trace" \
  "Packet Log" \
  "Packet Details" \
  "Download PCAP" \
  "demo-theme.css" \
  "perf-comparison.html" \
  "interop-results.html" \
  "coverage-results.html" \
  "global-timer" \
  "module-state" \
  "start-label" \
  "step-label"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/workbench.html"; then
    echo "packaged workbench page missing marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  "coquic-wasm-quic.wasm" \
  "packetDelayMs" \
  "downloadPcap" \
  "runDemo"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/quic-demo.js"; then
    echo "packaged wasm demo script missing marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  "coquic-perf-comparison-v1" \
  "CoQUIC Performance Comparison" \
  "coquic-logo.svg" \
  "demo-theme.css" \
  "perf-results.json" \
  "perf-history.json" \
  "Performance Barplots" \
  "Daily Performance Trends" \
  "plot-tabs" \
  "plot-tab" \
  "rank-badge" \
  "rank-1" \
  "own-impl" \
  "companyCode" \
  "languageCode" \
  "githubAvatar" \
  "sourceUrl" \
  "companyUrl" \
  "noopener noreferrer" \
  "companyIcon" \
  "google.com/s2/favicons" \
  "devicons/devicon@v2.17.0" \
  "identity-group" \
  "identity-icon" \
  "library_version" \
  "bar-version" \
  "quic-go" \
  "quinn" \
  "picoquic" \
  "quiche" \
  "quicly" \
  "google-quiche" \
  "Cloudflare" \
  "Microsoft" \
  "Rust" \
  "throughput_mib_per_s" \
  "requests_per_s" \
  "MiB/s" \
  "Reqs/s"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/perf-comparison.html" "${output_dir}/perf-comparison.js"; then
    echo "packaged perf comparison assets missing marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  "coquic-interop-results-v1" \
  "coquic interop results" \
  "coquic-logo.svg" \
  "demo-theme.css" \
  "interop-results.json" \
  "CoQUIC Interop Matrix" \
  "participant-chip" \
  "participant-fallback" \
  "githubAvatar" \
  "rowResultForTests" \
  "row-status-column" \
  "Overall result across every testcase in this row" \
  "test-cell" \
  "quic-go" \
  "picoquic" \
  "quinn"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/interop-results.html" "${output_dir}/interop-results.js"; then
    echo "packaged interop result assets missing marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  "coquic-coverage-results-v1" \
  "coquic coverage results" \
  "coquic-logo.svg" \
  "demo-theme.css" \
  "coverage-results.json" \
  "coverage/index.html" \
  "CoQUIC Coverage Report" \
  "LLVM source coverage" \
  "Function Coverage" \
  "Line Coverage" \
  "Branch Coverage" \
  "least_covered_files" \
  "component-list" \
  "file-list"; do
  if ! grep -Fq -- "${marker}" "${output_dir}/coverage-results.html" "${output_dir}/coverage-results.js"; then
    echo "packaged coverage result assets missing marker: ${marker}" >&2
    exit 1
  fi
done

for removed_marker in \
  "coquic-demo-v1" \
  "coquic HTTP/3 speed test" \
  "Start test" \
  "runSpeedTest" \
  "Run Live Checks" \
  "How To Verify In Chrome" \
  "/_coquic/inspect" \
  "/_coquic/echo" \
  "safeStorageGet" \
  "safeStorageSet" \
  "safeReadJson" \
  "runProbe" \
  "fonts.googleapis.com" \
  "fonts.gstatic.com"; do
  if grep -Fq -- "${removed_marker}" "${output_dir}/index.html" "${output_dir}/workbench.html"; then
    echo "packaged demo page still contains removed marker: ${removed_marker}" >&2
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
  install -d "${case_repo}/demo/deploy" "${case_repo}/zig-out/share/wasm-quic"
  cp demo/deploy/package-demo.sh "${case_repo}/demo/deploy/package-demo.sh"
  cp -R demo/wasm-quic/. "${case_repo}/zig-out/share/wasm-quic/"
  printf '\0asm\1\0\0\0' > "${case_repo}/zig-out/share/wasm-quic/coquic-wasm-quic.wasm"

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

  if [[ "${rejection_output}" != *"must not overlap wasm demo source ancestry"* ]]; then
    echo "unexpected overlap rejection output for ${target_suffix}: ${rejection_output}" >&2
    exit 1
  fi

  if [[ ! -f "${case_repo}/zig-out/share/wasm-quic/index.html" ]]; then
    echo "overlap rejection did not preserve wasm demo source content for ${target_suffix}" >&2
    exit 1
  fi
}

run_rejection_case "zig-out/share/wasm-quic"
run_rejection_case "zig-out/share"
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

  if [[ "${failure_output}" != *"missing wasm demo build directory"* ]]; then
    echo "unexpected missing-source rejection output: ${failure_output}" >&2
    exit 1
  fi
}

run_missing_index_case() {
  local case_repo
  case_repo="$(mktemp -d "${safety_repo}/case.XXXXXX")"
  install -d "${case_repo}/demo/deploy" "${case_repo}/zig-out/share/wasm-quic"
  cp demo/deploy/package-demo.sh "${case_repo}/demo/deploy/package-demo.sh"
  printf 'sentinel\n' > "${case_repo}/zig-out/share/wasm-quic/sentinel.txt"

  set +e
  local failure_output
  failure_output="$("${case_repo}/demo/deploy/package-demo.sh" "${case_repo}/out" 2>&1)"
  local failure_status=$?
  set -e

  if [[ ${failure_status} -eq 0 ]]; then
    echo "expected missing index.html in source to be rejected" >&2
    exit 1
  fi

  if [[ "${failure_output}" != *"wasm demo source is missing index.html"* ]]; then
    echo "unexpected missing-index rejection output: ${failure_output}" >&2
    exit 1
  fi

  if [[ ! -f "${case_repo}/zig-out/share/wasm-quic/sentinel.txt" ]]; then
    echo "missing-index rejection did not preserve wasm demo source contents" >&2
    exit 1
  fi
}

run_missing_source_case
run_missing_index_case

echo "demo package contract looks correct"
