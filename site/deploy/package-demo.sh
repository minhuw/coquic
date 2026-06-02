#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
requested_output_dir="${1:-${repo_root}/zig-out/demo-app}"
requested_next_dir="${2:-${repo_root}/site/next}"
requested_wasm_module="${3:-${repo_root}/zig-out/share/wasm-quic/coquic-wasm-quic.wasm}"
output_dir="$(realpath -m -- "${requested_output_dir}")"
next_dir="$(realpath -m -- "${requested_next_dir}")"
wasm_module="$(realpath -m -- "${requested_wasm_module}")"

standalone_dir="${next_dir}/.next/standalone"
static_dir="${next_dir}/.next/static"
public_dir="${next_dir}/public"
next_runtime_router_utils_dir="${next_dir}/node_modules/next/dist/server/lib/router-utils"
rag_dir="${repo_root}/rag"
rfc_dir="${repo_root}/references/rfc"
rag_artifacts_dir="${repo_root}/.rag/artifacts"
server_js="${standalone_dir}/server.js"
runtime_public_entries=(
  "perf-results.json"
  "perf-history.json"
  "interop-results.json"
  "coverage-results.json"
  "coverage"
)

if [[ ! -f "${server_js}" ]]; then
  echo "missing Next.js standalone server: ${server_js}" >&2
  echo "run: npm --prefix site/next run build" >&2
  exit 1
fi
if [[ ! -d "${static_dir}" ]]; then
  echo "missing Next.js static assets: ${static_dir}" >&2
  exit 1
fi
if [[ ! -d "${public_dir}" ]]; then
  echo "missing Next.js public directory: ${public_dir}" >&2
  exit 1
fi
if [[ ! -d "${next_runtime_router_utils_dir}" ]]; then
  echo "missing Next.js router runtime directory: ${next_runtime_router_utils_dir}" >&2
  exit 1
fi
if [[ ! -f "${wasm_module}" ]]; then
  echo "missing wasm demo module: ${wasm_module}" >&2
  exit 1
fi
if [[ ! -f "${rag_dir}/src/coquic_rag/qa/app.py" ]]; then
  echo "missing RAG QA API source: ${rag_dir}/src/coquic_rag/qa/app.py" >&2
  exit 1
fi
if [[ ! -d "${rfc_dir}" ]]; then
  echo "missing RFC source directory: ${rfc_dir}" >&2
  exit 1
fi

is_same_or_descendant() {
  local path="$1"
  local root="$2"
  [[ "${path}" == "${root}" || "${path}" == "${root}/"* ]]
}

if is_same_or_descendant "${output_dir}" "${next_dir}" || is_same_or_descendant "${next_dir}" "${output_dir}"; then
  echo "output directory must not overlap site source ancestry: ${output_dir}" >&2
  exit 1
fi

rm -rf -- "${output_dir}"
install -d -m 755 -- "${output_dir}"
cp -R -- "${standalone_dir}/." "${output_dir}/"
install -d -m 755 -- "${output_dir}/node_modules/next/dist/server/lib"
rm -rf -- "${output_dir}/node_modules/next/dist/server/lib/router-utils"
cp -R -- "${next_runtime_router_utils_dir}" "${output_dir}/node_modules/next/dist/server/lib/router-utils"
install -d -m 755 -- "${output_dir}/.next"
cp -R -- "${static_dir}" "${output_dir}/.next/static"
cp -R -- "${public_dir}" "${output_dir}/public"
for entry in "${runtime_public_entries[@]}"; do
  rm -rf -- "${output_dir}/public/${entry}"
done
rm -f -- "${output_dir}/public/coquic-wasm-quic.wasm"
install -m 644 -- "${wasm_module}" "${output_dir}/public/coquic-wasm-quic.wasm"
install -d -m 755 -- "${output_dir}/rag"
install -m 644 -- "${rag_dir}/pyproject.toml" "${output_dir}/rag/pyproject.toml"
install -m 644 -- "${rag_dir}/uv.lock" "${output_dir}/rag/uv.lock"
tar -C "${rag_dir}" \
  --exclude='*/__pycache__' \
  --exclude='*.egg-info' \
  -cf - src | tar -C "${output_dir}/rag" -xf -
install -d -m 755 -- "${output_dir}/references"
cp -R -- "${rfc_dir}" "${output_dir}/references/rfc"
if [[ -d "${rag_artifacts_dir}" ]]; then
  install -d -m 755 -- "${output_dir}/.rag"
  cp -R -- "${rag_artifacts_dir}" "${output_dir}/.rag/artifacts"
fi

if [[ ! -f "${output_dir}/node_modules/next/dist/server/lib/router-utils/is-postpone.js" ]]; then
  echo "packaged Next.js server is missing router-utils/is-postpone.js" >&2
  exit 1
fi

printf '%s\n' "${output_dir}"
