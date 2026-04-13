#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

cat > "${tmpdir}/fake-run-official.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'INTEROP_TESTCASES=%s\n' "${INTEROP_TESTCASES:-}" > "${TEST_OUTPUT}"
printf 'INTEROP_PEER_IMPL=%s\n' "${INTEROP_PEER_IMPL:-}" >> "${TEST_OUTPUT}"
printf 'INTEROP_PEER_IMAGE=%s\n' "${INTEROP_PEER_IMAGE:-}" >> "${TEST_OUTPUT}"
printf 'INTEROP_DIRECTIONS=%s\n' "${INTEROP_DIRECTIONS:-}" >> "${TEST_OUTPUT}"
printf 'INTEROP_LOG_ROOT=%s\n' "${INTEROP_LOG_ROOT:-}" >> "${TEST_OUTPUT}"
EOF
chmod +x "${tmpdir}/fake-run-official.sh"

TEST_OUTPUT="${tmpdir}/defaults.txt" \
RUN_OFFICIAL_BIN="${tmpdir}/fake-run-official.sh" \
bash tests/nix/chrome_http3_interop_smoke_test.sh

grep -qx 'INTEROP_TESTCASES=http3' "${tmpdir}/defaults.txt"
grep -qx 'INTEROP_PEER_IMPL=chrome' "${tmpdir}/defaults.txt"
grep -qx 'INTEROP_PEER_IMAGE=martenseemann/chrome-quic-interop-runner@sha256:5f0762811a21631d656a8e321e577538e1a0ef8541967f7db346a8eadbf1491a' "${tmpdir}/defaults.txt"
grep -qx 'INTEROP_DIRECTIONS=coquic-server' "${tmpdir}/defaults.txt"
grep -qx "INTEROP_LOG_ROOT=${repo_root}/.interop-logs/chrome-http3" "${tmpdir}/defaults.txt"

if TEST_OUTPUT="${tmpdir}/bad-direction.txt" \
  RUN_OFFICIAL_BIN="${tmpdir}/fake-run-official.sh" \
  INTEROP_DIRECTIONS=both \
  bash tests/nix/chrome_http3_interop_smoke_test.sh >"${tmpdir}/bad-direction.stdout" 2>"${tmpdir}/bad-direction.stderr"; then
  echo "expected chrome harness to reject INTEROP_DIRECTIONS=both" >&2
  exit 1
fi
grep -q 'INTEROP_DIRECTIONS must be coquic-server' "${tmpdir}/bad-direction.stderr"

if TEST_OUTPUT="${tmpdir}/bad-testcase.txt" \
  RUN_OFFICIAL_BIN="${tmpdir}/fake-run-official.sh" \
  INTEROP_TESTCASES=transfer \
  bash tests/nix/chrome_http3_interop_smoke_test.sh >"${tmpdir}/bad-testcase.stdout" 2>"${tmpdir}/bad-testcase.stderr"; then
  echo "expected chrome harness to reject INTEROP_TESTCASES=transfer" >&2
  exit 1
fi
grep -q 'INTEROP_TESTCASES must be http3' "${tmpdir}/bad-testcase.stderr"

echo "chrome HTTP/3 harness contract looks correct"
