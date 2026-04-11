#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

actual_block="$(
  awk '
    /^  interop-picoquic:$/ {
      capture = 1
    }
    capture && /^  [^[:space:]][^:]*:$/ && $0 != "  interop-picoquic:" {
      exit
    }
    capture {
      print
    }
  ' .github/workflows/interop.yml
)"

if [[ -z "${actual_block}" ]]; then
  echo "missing job: interop-picoquic" >&2
  exit 1
fi

expected_block="$(cat <<'EOF'
  interop-picoquic:
    name: picoquic Official Runner
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

      - name: Run Official picoquic Interop Tests
        id: interop_picoquic
        continue-on-error: true
        env:
          INTEROP_TESTCASES: handshake,handshakeloss,transfer,keyupdate,transferloss,handshakecorruption,transfercorruption,blackhole,chacha20,longrtt,goodput,crosstraffic,ipv6,multiplexing,retry,resumption,zerortt,v2,amplificationlimit,rebind-port,rebind-addr,connectionmigration
          INTEROP_PEER_IMPL: picoquic
          INTEROP_PEER_IMAGE: privateoctopus/picoquic@sha256:7e4110e3260cd9d4f815ad63ca1d93e020e94d3a8d3cb6cb9cc5c59d97999b05
        run: nix develop -c bash interop/run-official.sh

      - name: Preserve First Attempt Logs
        if: steps.interop_picoquic.outcome == 'failure'
        run: |
          rm -rf .interop-logs/official-first-attempt
          if [ -d .interop-logs/official ]; then
            cp -R .interop-logs/official .interop-logs/official-first-attempt
          fi

      - name: Retry Official picoquic Interop Tests Once
        id: interop_picoquic_retry
        if: steps.interop_picoquic.outcome == 'failure'
        continue-on-error: true
        env:
          INTEROP_TESTCASES: handshake,handshakeloss,transfer,keyupdate,transferloss,handshakecorruption,transfercorruption,blackhole,chacha20,longrtt,goodput,crosstraffic,ipv6,multiplexing,retry,resumption,zerortt,v2,amplificationlimit,rebind-port,rebind-addr,connectionmigration
          INTEROP_PEER_IMPL: picoquic
          INTEROP_PEER_IMAGE: privateoctopus/picoquic@sha256:7e4110e3260cd9d4f815ad63ca1d93e020e94d3a8d3cb6cb9cc5c59d97999b05
        run: nix develop -c bash interop/run-official.sh

      - name: Fail If Official picoquic Interop Retry Fails
        if: steps.interop_picoquic.outcome == 'failure' && steps.interop_picoquic_retry.outcome == 'failure'
        run: exit 1

      - name: Upload Interop Logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: interop-logs-picoquic
          path: |
            .interop-logs/official
            .interop-logs/official-first-attempt
          if-no-files-found: warn
EOF
)"

if [[ "${actual_block}" != "${expected_block}" ]]; then
  diff -u <(printf '%s\n' "${expected_block}") <(printf '%s\n' "${actual_block}") || true
  echo "interop-picoquic workflow retry contract mismatch" >&2
  exit 1
fi

echo "interop-picoquic workflow retry contract looks correct"
