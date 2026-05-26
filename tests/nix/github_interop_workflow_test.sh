#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

workflow=".github/workflows/interop.yml"

grep -F 'schedule:' "${workflow}" >/dev/null || {
  echo 'missing interop schedule trigger' >&2
  exit 1
}

grep -F 'cron: "0 3 * * *"' "${workflow}" >/dev/null || {
  echo 'missing daily interop cron trigger' >&2
  exit 1
}

grep -F 'workflow_dispatch:' "${workflow}" >/dev/null || {
  echo 'missing interop workflow_dispatch trigger' >&2
  exit 1
}

if grep -F 'pull_request:' "${workflow}" >/dev/null; then
  echo 'interop workflow must not use pull_request trigger' >&2
  exit 1
fi

if grep -F 'push:' "${workflow}" >/dev/null; then
  echo 'interop workflow must not use push trigger' >&2
  exit 1
fi

if grep -q 'DeterminateSystems/magic-nix-cache-action@main' "${workflow}"; then
  echo "interop workflow must not use DeterminateSystems/magic-nix-cache-action@main" >&2
  exit 1
fi

required_lines=(
  "  interop-peer:"
  "    name: \${{ matrix.display_name }} Official Runner"
  "      fail-fast: false"
  "          - peer: quicgo"
  "            impl: quic-go"
  "            image: martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424"
  "          - peer: picoquic"
  "            impl: picoquic"
  "            image: privateoctopus/picoquic@sha256:7e4110e3260cd9d4f815ad63ca1d93e020e94d3a8d3cb6cb9cc5c59d97999b05"
  "          - peer: quinn"
  "            impl: quinn"
  "            image: stammw/quinn-interop@sha256:5205c84e200ef1a999be602ed6eeec9a216f25ce27d5eac690fa1540ec73f355"
  "          INTEROP_TESTCASES: \${{ matrix.testcases }}"
  "          INTEROP_PEER_IMPL: \${{ matrix.impl }}"
  "          INTEROP_PEER_IMAGE: \${{ matrix.image }}"
  "          COQUIC_CONGESTION_CONTROL: \${{ matrix.congestion_control || '' }}"
  "            --json-out .interop-logs/interop-results-\${{ matrix.peer }}.json >> \"\${GITHUB_STEP_SUMMARY}\""
  "          name: interop-logs-\${{ matrix.peer }}"
  "          name: interop-results-\${{ matrix.peer }}"
  "  interop-self:"
  "          INTEROP_PEER_IMPL: coquic"
  "          INTEROP_PEER_IMAGE: coquic-interop:quictls-musl"
  "          INTEROP_DIRECTIONS: coquic-server"
  "            --json-out .interop-logs/interop-results-self.json >> \"\${GITHUB_STEP_SUMMARY}\""
  "          name: interop-logs-self"
  "          name: interop-results-self"
  "  publish-interop-results:"
  "      - interop-peer"
  "      - interop-self"
  "          pattern: interop-results-*"
  "            --json-out .interop-results/interop-results.json >> \"\${GITHUB_STEP_SUMMARY}\""
  "      - name: Configure Demo SSH"
  "      - name: Upload Interop Results To Demo"
  "            minhuw@coquic.minhuw.dev:/tmp/coquic-interop-results.json"
  "            \"sudo install -m 644 /tmp/coquic-interop-results.json /opt/coquic-demo/current/site/interop-results.json && rm -f /tmp/coquic-interop-results.json\""
)

for line in "${required_lines[@]}"; do
  if ! grep -Fx -- "${line}" "${workflow}" >/dev/null; then
    echo "missing interop workflow contract line: ${line}" >&2
    exit 1
  fi
done

peer_count="$(
  awk '
    /^  interop-peer:$/ {
      capture = 1
    }
    capture && /^  interop-self:$/ {
      capture = 0
    }
    capture && /^[[:space:]]+- peer: / {
      count += 1
    }
    END {
      print count + 0
    }
  ' "${workflow}"
)"

if [[ "${peer_count}" != "3" ]]; then
  echo "interop-peer matrix must contain exactly 3 peers, got ${peer_count}" >&2
  exit 1
fi

if grep -F -- "peer: msquic" "${workflow}" >/dev/null; then
  echo "interop-peer matrix must not include msquic while its zerortt client is broken" >&2
  exit 1
fi

grep -F 'python3 scripts/render-interop-results.py' "${workflow}" >/dev/null || {
  echo 'missing interop result renderer step' >&2
  exit 1
}

grep -F 'github.ref == '\''refs/heads/main'\''' "${workflow}" >/dev/null || {
  echo 'missing main branch guard for demo interop upload' >&2
  exit 1
}

echo "interop workflow contract looks correct"
