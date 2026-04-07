#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if grep -q 'DeterminateSystems/magic-nix-cache-action@main' .github/workflows/interop.yml; then
  echo "interop workflow must not use DeterminateSystems/magic-nix-cache-action@main" >&2
  exit 1
fi

actual_block="$(
  awk '
    /^  interop-self:$/ {
      capture = 1
    }
    capture && /^  [^[:space:]][^:]*:$/ && $0 != "  interop-self:" {
      exit
    }
    capture {
      print
    }
  ' .github/workflows/interop.yml
)"

if [[ -z "${actual_block}" ]]; then
  echo "missing job: interop-self" >&2
  exit 1
fi

expected_block="$(cat <<'EOF'
  interop-self:
    name: Self Official Runner
    runs-on: ubuntu-latest
    timeout-minutes: 90

    steps:
      - name: Checkout
        uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Nix
        uses: DeterminateSystems/nix-installer-action@main

      - name: Set up Docker 29.1
        uses: docker/setup-docker-action@v5
        with:
          version: v29.1.5

      - name: Show Docker Version
        run: |
          docker version
          docker compose version

      - name: Run Official self Interop Tests
        env:
          INTEROP_TESTCASES: handshake,handshakeloss,transfer,keyupdate,transferloss,handshakecorruption,transfercorruption,blackhole,chacha20,longrtt,goodput,crosstraffic,ipv6,multiplexing,retry,resumption,zerortt,v2,amplificationlimit,rebind-port,rebind-addr,connectionmigration,ecn
          INTEROP_PEER_IMPL: coquic
          INTEROP_PEER_IMAGE: coquic-interop:quictls-musl
          INTEROP_DIRECTIONS: coquic-server
        run: nix develop -c bash interop/run-official.sh

      - name: Upload Interop Logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: interop-logs-self
          path: .interop-logs/official
          if-no-files-found: warn
EOF
)"

if [[ "${actual_block}" != "${expected_block}" ]]; then
  diff -u <(printf '%s\n' "${expected_block}") <(printf '%s\n' "${actual_block}") || true
  echo "interop-self workflow contract mismatch" >&2
  exit 1
fi

echo "interop-self workflow contract looks correct"
