#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

curl_bin="${CURL_BIN:-curl}"
h3_server_bin="${H3_SERVER_BIN:-./zig-out/bin/h3-server}"

if ! "${curl_bin}" --version | grep -Eq '^Features: .*HTTP3($| )'; then
  echo "expected ${curl_bin} to report HTTP3 support in curl --version" >&2
  exit 1
fi

zig build >/dev/null

tmpdir="$(mktemp -d)"
server_pid=""
cleanup() {
  if [ -n "${server_pid}" ]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

mkdir -p "${tmpdir}/www"
printf 'hello-http3\n' > "${tmpdir}/www/hello.txt"

port="$(
  python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)"

"${h3_server_bin}" \
  --host 127.0.0.1 \
  --port "${port}" \
  --bootstrap-port "${port}" \
  --document-root "${tmpdir}/www" \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem \
  >"${tmpdir}/server.log" 2>&1 &
server_pid="$!"

bootstrap_headers="${tmpdir}/bootstrap-headers.txt"
bootstrap_headers_normalized="${tmpdir}/bootstrap-headers-normalized.txt"
for _ in $(seq 1 100); do
  if "${curl_bin}" -k -sS -I --connect-timeout 1 --max-time 2 \
      "https://localhost:${port}/hello.txt" >"${bootstrap_headers}"; then
    break
  fi
  sleep 0.1
done

tr -d '\r' < "${bootstrap_headers}" > "${bootstrap_headers_normalized}"

grep -iq '^alt-svc: h3=":'"${port}"'"; ma=60$' "${bootstrap_headers_normalized}" || {
  echo "expected bootstrap response to advertise Alt-Svc for h3 on :${port}" >&2
  cat "${bootstrap_headers_normalized}" >&2
  exit 1
}

http3_body="${tmpdir}/http3-body.txt"
for _ in $(seq 1 50); do
  if "${curl_bin}" --http3-only -k -sS --connect-timeout 1 --max-time 2 \
      -o "${http3_body}" "https://localhost:${port}/hello.txt"; then
    break
  fi
  sleep 0.1
done

expected_body='hello-http3'
actual_body="$(tr -d '\r\n' < "${http3_body}")"
if [ "${actual_body}" != "${expected_body}" ]; then
  echo "expected HTTP/3 body '${expected_body}', got '${actual_body}'" >&2
  exit 1
fi

printf 'http3 browser discovery smoke passed on port %s\n' "${port}"
