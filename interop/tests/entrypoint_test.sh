#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

cat >"${tmpdir}/coquic-interop" <<'SH'
#!/usr/bin/env sh
printf 'subcommand=%s\n' "$1"
printf 'TESTCASE=%s\n' "${TESTCASE:-}"
printf 'HOST=%s\n' "${HOST:-}"
printf 'PORT=%s\n' "${PORT:-}"
printf 'DOCUMENT_ROOT=%s\n' "${DOCUMENT_ROOT:-}"
printf 'DOWNLOAD_ROOT=%s\n' "${DOWNLOAD_ROOT:-}"
SH
chmod +x "${tmpdir}/coquic-interop"

run_entrypoint() {
  env COQUIC_SKIP_SETUP=1 COQUIC_SKIP_WAIT=1 COQUIC_BIN="${tmpdir}/coquic-interop" "$@" \
    bash interop/entrypoint.sh
}

server_output="$(
  run_entrypoint ROLE=server TESTCASE_SERVER=transfer TESTCASE_CLIENT=handshake
)"
grep -q '^subcommand=interop-server$' <<<"${server_output}"
grep -q '^TESTCASE=transfer$' <<<"${server_output}"
grep -q '^DOCUMENT_ROOT=/www$' <<<"${server_output}"

client_output="$(
  run_entrypoint ROLE=client TESTCASE_SERVER=handshake TESTCASE_CLIENT=chacha20
)"
grep -q '^subcommand=interop-client$' <<<"${client_output}"
grep -q '^TESTCASE=chacha20$' <<<"${client_output}"
grep -q '^DOWNLOAD_ROOT=/downloads$' <<<"${client_output}"

explicit_output="$(
  run_entrypoint ROLE=server TESTCASE=retry TESTCASE_SERVER=longrtt
)"
grep -q '^TESTCASE=retry$' <<<"${explicit_output}"

invalid_output="${tmpdir}/invalid.out"
if run_entrypoint ROLE=client TESTCASE_CLIENT=not-a-case >"${invalid_output}" 2>&1; then
  echo "expected unsupported role-specific TESTCASE to fail" >&2
  exit 1
fi
grep -q 'unsupported TESTCASE=not-a-case' "${invalid_output}"

echo "entrypoint testcase mapping ok"
