#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

cat > "${tmpdir}/fake-coquic" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${TEST_OUTPUT}"
EOF
chmod +x "${tmpdir}/fake-coquic"

TEST_OUTPUT="${tmpdir}/server-http3.txt" \
COQUIC_BIN="${tmpdir}/fake-coquic" \
COQUIC_SKIP_SETUP=1 \
ROLE=server \
TESTCASE=http3 \
bash interop/entrypoint.sh
grep -qx 'h3-interop-server' "${tmpdir}/server-http3.txt"

TEST_OUTPUT="${tmpdir}/client-http3.txt" \
COQUIC_BIN="${tmpdir}/fake-coquic" \
COQUIC_SKIP_SETUP=1 \
COQUIC_SKIP_WAIT=1 \
ROLE=client \
TESTCASE=http3 \
REQUESTS="https://server/a.txt https://server/b.txt" \
bash interop/entrypoint.sh
grep -qx 'h3-interop-client' "${tmpdir}/client-http3.txt"

TEST_OUTPUT="${tmpdir}/client-transfer.txt" \
COQUIC_BIN="${tmpdir}/fake-coquic" \
COQUIC_SKIP_SETUP=1 \
COQUIC_SKIP_WAIT=1 \
ROLE=client \
TESTCASE=transfer \
REQUESTS="https://server/a.txt" \
bash interop/entrypoint.sh
grep -qx 'interop-client' "${tmpdir}/client-transfer.txt"

echo "http3 interop entrypoint dispatch looks correct"
