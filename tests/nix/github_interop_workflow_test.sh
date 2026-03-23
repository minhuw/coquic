#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

workflow=.github/workflows/interop.yml

if [ ! -f "${workflow}" ]; then
  echo "missing workflow: ${workflow}" >&2
  exit 1
fi

python3 - "${workflow}" <<'PY'
import pathlib
import sys

workflow = pathlib.Path(sys.argv[1]).read_text()

required_fragments = [
    "pull_request:",
    "push:",
    "workflow_dispatch:",
    "jobs:",
    "  interop-quicgo:",
    "    name: quic-go Official Runner",
    "  interop-picoquic:",
    "    name: picoquic Official Runner",
    "      - name: Set up Docker 29.1",
    "        uses: docker/setup-docker-action@v5",
    "          version: v29.1.5",
    "      - name: Show Docker Version",
    "          docker version",
    "          docker compose version",
    "INTEROP_TESTCASES: handshake,handshakeloss,transfer,transferloss,handshakecorruption,transfercorruption,chacha20,longrtt,goodput,crosstraffic",
    "INTEROP_PEER_IMPL: quic-go",
    "INTEROP_PEER_IMAGE: martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424",
    "INTEROP_PEER_IMPL: picoquic",
    "INTEROP_PEER_IMAGE: privateoctopus/picoquic:latest",
    "name: interop-logs-quicgo",
    "name: interop-logs-picoquic",
    "nix develop -c bash tests/nix/interop_runner_test.sh",
]

missing = [fragment for fragment in required_fragments if fragment not in workflow]
if missing:
    raise SystemExit(f"workflow missing fragments: {missing!r}")

forbidden_fragments = [
    "INTEROP_WAIT_FOR_SERVER:",
]

present_forbidden = [fragment for fragment in forbidden_fragments if fragment in workflow]
if present_forbidden:
    raise SystemExit(f"workflow still contains deprecated fragments: {present_forbidden!r}")
PY
