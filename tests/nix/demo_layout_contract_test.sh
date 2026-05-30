#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

required_paths=(
  "demo/wasm-quic/index.html"
  "demo/wasm-quic/workbench.html"
  "demo/wasm-quic/quic-demo.js"
  "demo/wasm-quic/perf-comparison.html"
  "demo/wasm-quic/perf-comparison.js"
  "demo/wasm-quic/interop-results.html"
  "demo/wasm-quic/interop-results.js"
  "demo/wasm-quic/coverage-results.html"
  "demo/wasm-quic/coverage-results.js"
  "demo/h3-server/Dockerfile"
  "demo/deploy/package-demo.sh"
  "demo/deploy/deploy-remote.sh"
  "demo/deploy/coquic-demo.service"
  ".github/workflows/deploy-demo.yml"
  "docs/demo-deployment.md"
)

for path in "${required_paths[@]}"; do
  if [[ ! -e "${path}" ]]; then
    echo "missing required demo path: ${path}" >&2
    exit 1
  fi
done

removed_paths=(
  "demo/site/index.html"
  "tests/nix/h3_demo_page_contract_test.sh"
  "tests/nix/h3_server_container_smoke_test.sh"
  "docs/h3-server-container.md"
  "docker/h3-server/Dockerfile"
  "docker/h3-server/www/index.html"
)

for path in "${removed_paths[@]}"; do
  if [[ -e "${path}" ]]; then
    echo "expected path to be removed: ${path}" >&2
    exit 1
  fi
done

python3 - <<'PY'
import pathlib

doc = pathlib.Path("docs/demo-deployment.md").read_text()

required_doc_markers = [
    "demo/wasm-quic/",
    "zig-out/share/wasm-quic/",
    "coquic-wasm-demo-v1",
    "coquic-wasm-quic.wasm",
    "application/wasm",
    "demo/deploy/package-demo.sh",
    "demo/deploy/deploy-remote.sh",
    "demo/deploy/coquic-demo.service",
    ".github/workflows/deploy-demo.yml",
    ".github/workflows/perf.yml",
    ".github/workflows/interop.yml",
    ".github/workflows/test.yml",
    "COQUIC_DEMO_REMOTE_SSH_KEY",
    "perf-results.json",
    "/opt/coquic-demo/current/site/perf-results.json",
    "perf-history.json",
    "/opt/coquic-demo/current/site/perf-history.json",
    "interop-results.json",
    "/opt/coquic-demo/current/site/interop-results.json",
    "coverage-results.json",
    "/opt/coquic-demo/current/site/coverage-results.json",
    "/opt/coquic-demo/current/site/coverage/",
    "COQUIC_DEMO_CERT_CHAIN_PEM",
    "COQUIC_DEMO_PRIVATE_KEY_PEM",
    "coquic.minhuw.dev",
    "minhuw",
    "22",
    "443",
    "coquic-demo.key",
    "known_hosts",
    "ssh-ed25519",
    "/opt/coquic-demo/releases/<git-sha>/h3-server",
    "/opt/coquic-demo/current",
    "/etc/coquic-demo/tls/fullchain.pem",
    "/etc/coquic-demo/tls/privkey.pem",
    "workflow_dispatch",
    "manual certificate refresh",
]

for marker in required_doc_markers:
    if marker not in doc:
        raise SystemExit(f"demo deployment doc missing marker: {marker}")

removed_doc_markers = [
    "COQUIC_DEMO_REMOTE_HOST",
    "COQUIC_DEMO_REMOTE_USER",
    "COQUIC_DEMO_REMOTE_SSH_PORT",
    "COQUIC_DEMO_REMOTE_SSH_KEY_PATH",
    "COQUIC_DEMO_REMOTE_KNOWN_HOSTS",
    "COQUIC_DEMO_PUBLIC_HOST",
    "COQUIC_DEMO_PUBLIC_PORT",
]

for marker in removed_doc_markers:
    if marker in doc:
        raise SystemExit(f"demo deployment doc should not mention removed config marker: {marker}")
PY

if [[ ! -x tests/nix/demo_layout_contract_test.sh ]]; then
  echo "demo layout contract test must be executable" >&2
  exit 1
fi

echo "demo layout contract looks correct"
