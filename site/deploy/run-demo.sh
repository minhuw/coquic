#!/usr/bin/env bash
set -euo pipefail

release_dir="${COQUIC_DEMO_RELEASE_DIR:-/opt/coquic-demo/current}"
rag_env_file="${COQUIC_DEMO_RAG_ENV_FILE:-/etc/coquic-demo/rag.env}"
if [[ -f "${rag_env_file}" ]]; then
  set -a
  source "${rag_env_file}"
  set +a
fi

host="${COQUIC_DEMO_HOST:-0.0.0.0}"
port="${COQUIC_DEMO_PORT:-443}"
bootstrap_port="${COQUIC_DEMO_BOOTSTRAP_PORT:-443}"
alt_svc_max_age="${COQUIC_DEMO_ALT_SVC_MAX_AGE:-86400}"
next_host="${COQUIC_DEMO_NEXT_HOST:-127.0.0.1}"
next_port="${COQUIC_DEMO_NEXT_PORT:-3001}"
qa_host="${COQUIC_QA_HOST:-127.0.0.1}"
qa_port="${COQUIC_QA_PORT:-8787}"
qa_enabled="${COQUIC_DEMO_QA_ENABLED:-auto}"
cert_chain="${COQUIC_DEMO_CERTIFICATE_CHAIN:-/etc/coquic-demo/tls/fullchain.pem}"
private_key="${COQUIC_DEMO_PRIVATE_KEY:-/etc/coquic-demo/tls/privkey.pem}"
transcript_dataset_dir="${COQUIC_TRANSCRIPT_DATASET_DIR:-/opt/coquic-demo/dataset}"
transcript_archive_name="codex-history-coquic-transcripts-only-20260630.zip"
transcript_archive_path="${COQUIC_TRANSCRIPT_ARCHIVE_PATH:-${transcript_dataset_dir}/${transcript_archive_name}}"
transcript_sqlite_path="${COQUIC_TRANSCRIPT_SQLITE_PATH:-${transcript_dataset_dir}/transcripts.sqlite}"
transcript_archive_url="${COQUIC_TRANSCRIPT_ARCHIVE_URL:-/dataset/${transcript_archive_name}}"

next_root="${release_dir}/app"
rag_root="${COQUIC_DEMO_RAG_ROOT:-${next_root}/rag}"
rag_repo_root="${COQUIC_DEMO_RAG_REPO_ROOT:-${next_root}}"
rag_state_dir="${COQUIC_RAG_STATE_DIR:-${rag_repo_root}/.rag}"
h3_server="${release_dir}/h3-server"

if [[ ! -x "${h3_server}" ]]; then
  echo "missing h3-server: ${h3_server}" >&2
  exit 1
fi
if [[ ! -f "${next_root}/server.js" ]]; then
  echo "missing Next.js server: ${next_root}/server.js" >&2
  exit 1
fi

qa_should_start=0
case "${qa_enabled}" in
  auto)
    if [[ -n "${OPENROUTER_API_KEY:-}" &&
          -n "${DEEPSEEK_API_KEY:-}" &&
          -n "${COQUIC_QDRANT_URL:-}" &&
          -n "${COQUIC_QDRANT_API_KEY:-}" ]]; then
      qa_should_start=1
    fi
    ;;
  1|true|yes|on)
    qa_should_start=1
    ;;
  0|false|no|off)
    qa_should_start=0
    ;;
  *)
    echo "invalid COQUIC_DEMO_QA_ENABLED value: ${qa_enabled}" >&2
    exit 1
    ;;
esac

if [[ "${qa_should_start}" == "1" ]]; then
  if [[ -z "${OPENROUTER_API_KEY:-}" ||
        -z "${DEEPSEEK_API_KEY:-}" ||
        -z "${COQUIC_QDRANT_URL:-}" ||
        -z "${COQUIC_QDRANT_API_KEY:-}" ]]; then
    echo "QA is enabled but OPENROUTER_API_KEY, DEEPSEEK_API_KEY, COQUIC_QDRANT_URL, and COQUIC_QDRANT_API_KEY are required" >&2
    exit 1
  fi
  if [[ ! -f "${rag_root}/src/coquic_rag/qa/app.py" ]]; then
    echo "missing RAG QA API source: ${rag_root}/src/coquic_rag/qa/app.py" >&2
    exit 1
  fi
  if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required to run the RAG QA API" >&2
    exit 1
  fi
fi

qa_pid=""
next_pid=""
h3_pid=""
next_ready=0
qa_ready=0

is_managed_pid() {
  local pid="${1:-}"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && [[ "${pid}" != "1" ]]
}

pid_is_alive() {
  local pid="$1"
  is_managed_pid "${pid}" && kill -0 -- "${pid}" >/dev/null 2>&1
}

stop_pid() {
  local pid="$1"
  if pid_is_alive "${pid}"; then
    kill -- "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  stop_pid "${h3_pid}"
  stop_pid "${next_pid}"
  stop_pid "${qa_pid}"
}
trap cleanup EXIT
trap 'cleanup; exit 143' INT TERM

if [[ "${qa_should_start}" == "1" ]]; then
  (
    cd "${rag_repo_root}"
    PYTHONPATH="${rag_root}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    COQUIC_REPO_ROOT="${rag_repo_root}" \
    COQUIC_RAG_STATE_DIR="${rag_state_dir}" \
    COQUIC_QA_HOST="${qa_host}" \
    COQUIC_QA_PORT="${qa_port}" \
    exec uv run --no-project \
      --with fastapi \
      --with httpx \
      --with 'qdrant-client>=1.18,<1.19' \
      --with 'uvicorn[standard]' \
      uvicorn coquic_rag.qa.app:app \
        --host "${qa_host}" \
        --port "${qa_port}"
  ) &
  qa_pid="$!"

  for _ in $(seq 1 120); do
    if ! pid_is_alive "${qa_pid}"; then
      wait "${qa_pid}" || true
      echo "RAG QA API exited before Next.js startup" >&2
      exit 1
    fi
    if curl -fsS "http://${qa_host}:${qa_port}/api/health" 2>/dev/null | grep -Fq '"ready":true'; then
      qa_ready=1
      break
    fi
    sleep 1
  done
  if [[ "${qa_ready}" != "1" ]]; then
    echo "RAG QA API did not become ready at http://${qa_host}:${qa_port}/api/health" >&2
    exit 1
  fi
fi

(
  cd "${next_root}"
  COQUIC_RAG_API_BASE="http://${qa_host}:${qa_port}" \
  COQUIC_TRANSCRIPT_ARCHIVE_PATH="${transcript_archive_path}" \
  COQUIC_TRANSCRIPT_ARCHIVE_URL="${transcript_archive_url}" \
  COQUIC_TRANSCRIPT_SQLITE_PATH="${transcript_sqlite_path}" \
  HOSTNAME="${next_host}" \
  PORT="${next_port}" \
  NODE_ENV=production \
  exec node server.js
) &
next_pid="$!"

for _ in $(seq 1 50); do
  if ! pid_is_alive "${next_pid}"; then
    wait "${next_pid}" || true
    echo "Next.js server exited before h3-server startup" >&2
    exit 1
  fi
  if curl -fsS "http://${next_host}:${next_port}/" >/dev/null 2>&1; then
    next_ready=1
    break
  fi
  sleep 0.1
done
if [[ "${next_ready}" != "1" ]]; then
  echo "Next.js server did not become ready at http://${next_host}:${next_port}/" >&2
  exit 1
fi

"${h3_server}" \
  --host "${host}" \
  --port "${port}" \
  --bootstrap-port "${bootstrap_port}" \
  --alt-svc-max-age "${alt_svc_max_age}" \
  --reverse-proxy "http://${next_host}:${next_port}" \
  --certificate-chain "${cert_chain}" \
  --private-key "${private_key}" &
h3_pid="$!"

set +e
wait_pids=("${next_pid}" "${h3_pid}")
if [[ -n "${qa_pid}" ]]; then
  wait_pids+=("${qa_pid}")
fi
wait -n "${wait_pids[@]}"
exit_code=$?
set -e
cleanup
trap - EXIT INT TERM
exit "${exit_code}"
