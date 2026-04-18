#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <binary-path> <site-dir>" >&2
  exit 1
fi

binary_path="$1"
site_dir="$2"

if [[ ! -f "${binary_path}" ]]; then
  echo "missing binary path: ${binary_path}" >&2
  exit 1
fi
if [[ ! -d "${site_dir}" ]]; then
  echo "missing site dir: ${site_dir}" >&2
  exit 1
fi

required_env_vars=(
  COQUIC_DEMO_REMOTE_HOST
  COQUIC_DEMO_REMOTE_USER
  COQUIC_DEMO_REMOTE_SSH_KEY_PATH
  COQUIC_DEMO_CERT_CHAIN_PEM
  COQUIC_DEMO_PRIVATE_KEY_PEM
  COQUIC_DEMO_PUBLIC_HOST
)
for env_var in "${required_env_vars[@]}"; do
  if [[ -z "${!env_var:-}" ]]; then
    echo "missing required environment variable: ${env_var}" >&2
    exit 1
  fi
done

ssh_port="${COQUIC_DEMO_REMOTE_SSH_PORT:-22}"
public_port="${COQUIC_DEMO_PUBLIC_PORT:-4433}"
release_id="$(date -u +%Y%m%d%H%M%S)"

remote_releases_root="/opt/coquic-demo/releases"
remote_release_dir="${remote_releases_root}/${release_id}"
remote_upload_dir="/tmp/coquic-demo-release-${release_id}"
remote_current_link="/opt/coquic-demo/current"
remote_target="${COQUIC_DEMO_REMOTE_USER}@${COQUIC_DEMO_REMOTE_HOST}"

ssh_opts=(
  -p "${ssh_port}"
  -i "${COQUIC_DEMO_REMOTE_SSH_KEY_PATH}"
  -o BatchMode=yes
)
scp_opts=(
  -P "${ssh_port}"
  -i "${COQUIC_DEMO_REMOTE_SSH_KEY_PATH}"
)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
staging_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${staging_dir}"
}
trap cleanup EXIT

install -m 755 "${binary_path}" "${staging_dir}/h3-server"
tar -C "${site_dir}" -cf "${staging_dir}/site.tar" .
install -m 644 "${script_dir}/coquic-demo.service" "${staging_dir}/coquic-demo.service"
printf '%s' "${COQUIC_DEMO_CERT_CHAIN_PEM}" > "${staging_dir}/fullchain.pem"
printf '%s' "${COQUIC_DEMO_PRIVATE_KEY_PEM}" > "${staging_dir}/privkey.pem"

previous_release_target="$(
  ssh "${ssh_opts[@]}" "${remote_target}" \
    "if [ -L '${remote_current_link}' ]; then readlink '${remote_current_link}'; fi"
)"

ssh "${ssh_opts[@]}" "${remote_target}" "rm -rf '${remote_upload_dir}' && mkdir -p '${remote_upload_dir}'"
scp "${scp_opts[@]}" "${staging_dir}/h3-server" "${remote_target}:${remote_upload_dir}/h3-server"
scp "${scp_opts[@]}" "${staging_dir}/site.tar" "${remote_target}:${remote_upload_dir}/site.tar"
scp "${scp_opts[@]}" "${staging_dir}/coquic-demo.service" "${remote_target}:${remote_upload_dir}/coquic-demo.service"
scp "${scp_opts[@]}" "${staging_dir}/fullchain.pem" "${remote_target}:${remote_upload_dir}/fullchain.pem"
scp "${scp_opts[@]}" "${staging_dir}/privkey.pem" "${remote_target}:${remote_upload_dir}/privkey.pem"

ssh "${ssh_opts[@]}" "${remote_target}" bash -s -- "${remote_release_dir}" "${remote_upload_dir}" "${remote_current_link}" <<'EOF'
set -euo pipefail

remote_release_dir="$1"
remote_upload_dir="$2"
remote_current_link="$3"

sudo install -d -m 755 /opt/coquic-demo/releases
sudo install -d -m 755 /etc/coquic-demo/tls

sudo rm -rf "${remote_release_dir}"
sudo install -d -m 755 "${remote_release_dir}"
sudo install -m 755 "${remote_upload_dir}/h3-server" "${remote_release_dir}/h3-server"
sudo install -d -m 755 "${remote_release_dir}/site"
sudo tar -xf "${remote_upload_dir}/site.tar" -C "${remote_release_dir}/site"

sudo install -m 644 "${remote_upload_dir}/coquic-demo.service" /etc/systemd/system/coquic-demo.service
sudo install -m 644 "${remote_upload_dir}/fullchain.pem" /etc/coquic-demo/tls/fullchain.pem
sudo install -m 600 "${remote_upload_dir}/privkey.pem" /etc/coquic-demo/tls/privkey.pem

sudo ln -sfn "${remote_release_dir}" "${remote_current_link}"
sudo systemctl daemon-reload
sudo systemctl enable --now coquic-demo.service
sudo systemctl is-active --quiet coquic-demo.service
sudo rm -rf "${remote_upload_dir}"
EOF

rollback_release() {
  if [[ -z "${previous_release_target}" ]]; then
    echo "verification failed and rollback target is unavailable" >&2
    return
  fi

  ssh "${ssh_opts[@]}" "${remote_target}" bash -s -- "${previous_release_target}" "${remote_current_link}" <<'EOF'
set -euo pipefail
previous_release_target="$1"
remote_current_link="$2"

sudo ln -sfn "${previous_release_target}" "${remote_current_link}"
sudo systemctl restart coquic-demo.service
sudo systemctl is-active --quiet coquic-demo.service
EOF
}

verify_or_rollback() {
  local message="$1"
  echo "${message}" >&2
  rollback_release
  exit 1
}

url="https://${COQUIC_DEMO_PUBLIC_HOST}:${public_port}/"
headers="$(nix run .#curl-http3 -- -I "${url}")"

if ! grep -Fq 'HTTP/1.1 200 OK' <<<"${headers}"; then
  verify_or_rollback "deployment verification failed: missing HTTP/1.1 200 OK"
fi

if ! grep -Fq "Alt-Svc: h3=\":${public_port}\"; ma=60" <<<"${headers}"; then
  verify_or_rollback "deployment verification failed: missing Alt-Svc header"
fi

http3_version="$(nix run .#curl-http3 -- --http3-only -sS -o /dev/null -w '%{http_version}' "${url}")"
if [[ "${http3_version}" != "3" ]]; then
  verify_or_rollback "deployment verification failed: expected HTTP/3, got ${http3_version}"
fi

page="$(nix run .#curl-http3 -- --http3-only -sS "${url}")"
for marker in "Showcase" "Technical" "Run Live Checks" "Browser Verification"; do
  if ! grep -Fq "${marker}" <<<"${page}"; then
    verify_or_rollback "deployment verification failed: missing marker ${marker}"
  fi
done

echo "remote demo deploy verified"
