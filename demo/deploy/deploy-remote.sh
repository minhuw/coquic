#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

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
if [[ "${public_port}" != "4433" ]]; then
  echo "COQUIC_DEMO_PUBLIC_PORT must be 4433 for the current service template" >&2
  exit 1
fi
release_id_source="${GITHUB_SHA:-$(git -C "${repo_root}" rev-parse --short=12 HEAD)}"
release_id="${release_id_source:0:12}"
if [[ -z "${release_id}" ]]; then
  echo "failed to resolve release id" >&2
  exit 1
fi

remote_releases_root="/opt/coquic-demo/releases"
remote_release_dir="${remote_releases_root}/${release_id}"
remote_current_link="/opt/coquic-demo/current"
remote_target="${COQUIC_DEMO_REMOTE_USER}@${COQUIC_DEMO_REMOTE_HOST}"

ssh_opts=(
  -p "${ssh_port}"
  -i "${COQUIC_DEMO_REMOTE_SSH_KEY_PATH}"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ServerAliveInterval=10
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="${HOME}/.ssh/known_hosts"
)
scp_opts=(
  -P "${ssh_port}"
  -i "${COQUIC_DEMO_REMOTE_SSH_KEY_PATH}"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ServerAliveInterval=10
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="${HOME}/.ssh/known_hosts"
)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
staging_dir="$(mktemp -d)"
remote_upload_dir=""
previous_release_target=""
rollback_armed=0
rollback_performed=0
deploy_succeeded=0
verification_attempts=5
same_release_repair_mode=0

cleanup_local() {
  rm -rf "${staging_dir}"
}

remote_cleanup() {
  if [[ -z "${remote_upload_dir}" ]]; then
    return
  fi
  ssh "${ssh_opts[@]}" "${remote_target}" "sudo rm -rf '${remote_upload_dir}'" >/dev/null 2>&1 || true
}

rollback_remote() {
  if [[ ${rollback_performed} -eq 1 ]]; then
    return
  fi
  rollback_performed=1

  if [[ -z "${remote_upload_dir}" ]]; then
    rollback_armed=0
    return
  fi

  ssh "${ssh_opts[@]}" "${remote_target}" bash -s -- "${remote_upload_dir}" "${remote_current_link}" "${previous_release_target}" "${remote_release_dir}" "${same_release_repair_mode}" <<'EOF'
set -euo pipefail
remote_upload_dir="$1"
remote_current_link="$2"
previous_release_target="$3"
remote_release_dir="$4"
same_release_repair_mode="$5"

restore_or_remove() {
  local destination="$1"
  local backup_path="$2"
  local absent_marker="$3"
  local mode="$4"

  if sudo test -f "${backup_path}"; then
    sudo install -D -m "${mode}" "${backup_path}" "${destination}"
  elif sudo test -f "${absent_marker}"; then
    sudo rm -f "${destination}"
  fi
}

restore_dir_or_remove() {
  local destination="$1"
  local backup_path="$2"
  local absent_marker="$3"

  if sudo test -d "${backup_path}"; then
    sudo rm -rf "${destination}"
    sudo install -d -m 755 "${destination}"
    sudo cp -a "${backup_path}/." "${destination}/"
  elif sudo test -f "${absent_marker}"; then
    sudo rm -rf "${destination}"
  fi
}

# rollback: restore /opt/coquic-demo/current
if [[ -n "${previous_release_target}" ]]; then
  sudo ln -sfnT "${previous_release_target}" "${remote_current_link}"
else
  sudo rm -f "${remote_current_link}"
fi

# rollback: restore same-release /opt/coquic-demo/current/h3-server
if [[ "${same_release_repair_mode}" == "1" ]]; then
  restore_or_remove \
    "/opt/coquic-demo/current/h3-server" \
    "${remote_upload_dir}/current.h3-server.bak" \
    "${remote_upload_dir}/current.h3-server.absent" \
    "755"
  # rollback: restore same-release /opt/coquic-demo/current/site
  restore_dir_or_remove \
    "/opt/coquic-demo/current/site" \
    "${remote_upload_dir}/current.site.bak" \
    "${remote_upload_dir}/current.site.absent"
fi

# rollback: cleanup failed ${remote_release_dir}
if [[ "${same_release_repair_mode}" != "1" &&
      -n "${remote_release_dir}" &&
      "${remote_release_dir}" != "${previous_release_target}" ]]; then
  sudo rm -rf "${remote_release_dir}"
fi

# rollback: restore /etc/systemd/system/coquic-demo.service
restore_or_remove \
  "/etc/systemd/system/coquic-demo.service" \
  "${remote_upload_dir}/coquic-demo.service.bak" \
  "${remote_upload_dir}/coquic-demo.service.absent" \
  "644"
restore_or_remove \
  "/etc/coquic-demo/tls/fullchain.pem" \
  "${remote_upload_dir}/fullchain.pem.bak" \
  "${remote_upload_dir}/fullchain.pem.absent" \
  "644"
# rollback: restore /etc/coquic-demo/tls/privkey.pem
restore_or_remove \
  "/etc/coquic-demo/tls/privkey.pem" \
  "${remote_upload_dir}/privkey.pem.bak" \
  "${remote_upload_dir}/privkey.pem.absent" \
  "600"

sudo systemctl daemon-reload

service_was_active=0
service_was_enabled=0
if sudo test -f "${remote_upload_dir}/service.was_active"; then
  service_was_active=1
fi
if sudo test -f "${remote_upload_dir}/service.was_enabled"; then
  service_was_enabled=1
fi

if [[ "${service_was_enabled}" == "1" ]]; then
  sudo systemctl enable coquic-demo.service || true
else
  sudo systemctl disable coquic-demo.service || true
fi

if [[ "${service_was_active}" == "1" ]]; then
  if ! sudo systemctl restart coquic-demo.service; then
    sudo systemctl start coquic-demo.service
  fi
  sudo systemctl is-active --quiet coquic-demo.service
else
  sudo systemctl stop coquic-demo.service || true
  if sudo systemctl is-active --quiet coquic-demo.service; then
    echo "rollback failed: coquic-demo.service should be inactive" >&2
    exit 1
  fi
fi
EOF

  rollback_armed=0
  remote_cleanup
}

fail_with_rollback() {
  local message="$1"
  echo "${message}" >&2

  if [[ ${rollback_armed} -eq 1 ]]; then
    rollback_remote || echo "rollback failed" >&2
  fi

  exit 1
}

on_exit() {
  local status=$?
  set +e

  if [[ ${rollback_armed} -eq 1 && ${deploy_succeeded} -eq 0 ]]; then
    echo "deployment failed; running rollback" >&2
    rollback_remote || echo "rollback failed" >&2
    status=1
  fi

  remote_cleanup
  cleanup_local
  exit "${status}"
}
trap on_exit EXIT

install -m 755 "${binary_path}" "${staging_dir}/h3-server"
tar -C "${site_dir}" -cf "${staging_dir}/site.tar" .
install -m 644 "${script_dir}/coquic-demo.service" "${staging_dir}/coquic-demo.service"
printf '%s' "${COQUIC_DEMO_CERT_CHAIN_PEM}" > "${staging_dir}/fullchain.pem"
printf '%s' "${COQUIC_DEMO_PRIVATE_KEY_PEM}" > "${staging_dir}/privkey.pem"

previous_release_target="$(
  ssh "${ssh_opts[@]}" "${remote_target}" bash -s -- "${remote_current_link}" "${remote_releases_root}" <<'EOF'
set -euo pipefail
remote_current_link="$1"
remote_releases_root="$2"

# preflight: current must be symlink if present
if [[ ! -e "${remote_current_link}" ]]; then
  exit 0
fi

if [[ ! -L "${remote_current_link}" ]]; then
  echo "remote preflight failed: ${remote_current_link} exists but is not a symlink" >&2
  exit 1
fi

# preflight: current target must resolve to existing directory
canonical_target="$(readlink -f "${remote_current_link}" || true)"
if [[ -z "${canonical_target}" || ! -d "${canonical_target}" ]]; then
  echo "remote preflight failed: ${remote_current_link} target is missing or not a directory" >&2
  exit 1
fi

# preflight: current target must resolve within /opt/coquic-demo/releases
case "${canonical_target}" in
  "${remote_releases_root}/"*) ;;
  *)
    echo "remote preflight failed: ${remote_current_link} target resolves outside ${remote_releases_root}: ${canonical_target}" >&2
    exit 1
    ;;
esac

printf '%s\n' "${canonical_target}"
EOF
)"

if [[ "${previous_release_target}" == "${remote_release_dir}" ]]; then
  # same-release repair mode
  same_release_repair_mode=1
fi

remote_upload_dir="$(
  ssh "${ssh_opts[@]}" "${remote_target}" \
    "umask 077 && mktemp -d /tmp/coquic-demo-release-${release_id}-XXXXXX"
)"

scp "${scp_opts[@]}" "${staging_dir}/h3-server" "${remote_target}:${remote_upload_dir}/h3-server"
scp "${scp_opts[@]}" "${staging_dir}/site.tar" "${remote_target}:${remote_upload_dir}/site.tar"
scp "${scp_opts[@]}" "${staging_dir}/coquic-demo.service" "${remote_target}:${remote_upload_dir}/coquic-demo.service"
scp "${scp_opts[@]}" "${staging_dir}/fullchain.pem" "${remote_target}:${remote_upload_dir}/fullchain.pem"
scp "${scp_opts[@]}" "${staging_dir}/privkey.pem" "${remote_target}:${remote_upload_dir}/privkey.pem"

rollback_armed=1

if ! ssh "${ssh_opts[@]}" "${remote_target}" bash -s -- "${remote_release_dir}" "${remote_upload_dir}" "${remote_current_link}" "${same_release_repair_mode}" <<'EOF'
set -euo pipefail

remote_release_dir="$1"
remote_upload_dir="$2"
remote_current_link="$3"
same_release_repair_mode="$4"

backup_or_mark_absent() {
  local source_path="$1"
  local backup_path="$2"
  local absent_marker="$3"

  if sudo test -e "${source_path}"; then
    sudo cp -a "${source_path}" "${backup_path}"
    sudo rm -f "${absent_marker}"
  else
    sudo rm -f "${backup_path}"
    sudo touch "${absent_marker}"
  fi
}

service_was_active=0
if sudo systemctl is-active --quiet coquic-demo.service; then
  service_was_active=1
fi
service_was_enabled=0
if sudo systemctl is-enabled --quiet coquic-demo.service; then
  service_was_enabled=1
fi

sudo install -d -m 755 /opt/coquic-demo/releases
sudo install -d -m 755 /etc/coquic-demo/tls

if [[ "${service_was_active}" == "1" ]]; then
  sudo touch "${remote_upload_dir}/service.was_active"
else
  sudo rm -f "${remote_upload_dir}/service.was_active"
fi
if [[ "${service_was_enabled}" == "1" ]]; then
  sudo touch "${remote_upload_dir}/service.was_enabled"
else
  sudo rm -f "${remote_upload_dir}/service.was_enabled"
fi

backup_or_mark_absent \
  "/etc/systemd/system/coquic-demo.service" \
  "${remote_upload_dir}/coquic-demo.service.bak" \
  "${remote_upload_dir}/coquic-demo.service.absent"
backup_or_mark_absent \
  "/etc/coquic-demo/tls/fullchain.pem" \
  "${remote_upload_dir}/fullchain.pem.bak" \
  "${remote_upload_dir}/fullchain.pem.absent"
backup_or_mark_absent \
  "/etc/coquic-demo/tls/privkey.pem" \
  "${remote_upload_dir}/privkey.pem.bak" \
  "${remote_upload_dir}/privkey.pem.absent"

if [[ "${same_release_repair_mode}" != "1" ]]; then
  sudo rm -rf "${remote_release_dir}"
  sudo install -d -m 755 "${remote_release_dir}"
else
  # same-release backup /opt/coquic-demo/current/h3-server
  backup_or_mark_absent \
    "/opt/coquic-demo/current/h3-server" \
    "${remote_upload_dir}/current.h3-server.bak" \
    "${remote_upload_dir}/current.h3-server.absent"
  # same-release backup /opt/coquic-demo/current/site
  backup_or_mark_absent \
    "/opt/coquic-demo/current/site" \
    "${remote_upload_dir}/current.site.bak" \
    "${remote_upload_dir}/current.site.absent"
  sudo systemctl stop coquic-demo.service || true
  sudo install -d -m 755 "${remote_release_dir}"
fi

sudo install -m 755 "${remote_upload_dir}/h3-server" "${remote_release_dir}/h3-server"
sudo rm -rf "${remote_release_dir}/site"
sudo install -d -m 755 "${remote_release_dir}/site"
sudo tar -xf "${remote_upload_dir}/site.tar" -C "${remote_release_dir}/site"

sudo install -m 644 "${remote_upload_dir}/coquic-demo.service" /etc/systemd/system/coquic-demo.service
sudo install -m 644 "${remote_upload_dir}/fullchain.pem" /etc/coquic-demo/tls/fullchain.pem
sudo install -m 600 "${remote_upload_dir}/privkey.pem" /etc/coquic-demo/tls/privkey.pem

sudo ln -sfnT "${remote_release_dir}" "${remote_current_link}"
sudo systemctl daemon-reload
# install: restart existing service if already active
if [[ "${service_was_active}" == "1" ]]; then
  sudo systemctl restart coquic-demo.service
else
  sudo systemctl enable --now coquic-demo.service
fi
sudo systemctl is-active --quiet coquic-demo.service
EOF
then
  fail_with_rollback "deployment failed during remote install"
fi

url="https://${COQUIC_DEMO_PUBLIC_HOST}:${public_port}/"
headers_verified=0
for attempt in $(seq 1 "${verification_attempts}"); do
  # verification retry loop: headers
  headers=""
  if headers="$(timeout 20s nix run .#curl-http3 -- -I "${url}" 2>/dev/null)"; then
    if grep -Fq 'HTTP/1.1 200 OK' <<<"${headers}" &&
       grep -Fq "Alt-Svc: h3=\":${public_port}\"; ma=60" <<<"${headers}"; then
      headers_verified=1
      break
    fi
  fi
  if [[ "${attempt}" -lt "${verification_attempts}" ]]; then
    sleep "${attempt}"
  fi
done
if [[ ${headers_verified} -ne 1 ]]; then
  fail_with_rollback "deployment verification failed: headers did not converge after retries"
fi

http3_verified=0
for attempt in $(seq 1 "${verification_attempts}"); do
  # verification retry loop: http3-version
  http3_version=""
  if http3_version="$(timeout 20s nix run .#curl-http3 -- --http3-only -sS -o /dev/null -w '%{http_version}' "${url}" 2>/dev/null)"; then
    if [[ "${http3_version}" == "3" ]]; then
      http3_verified=1
      break
    fi
  fi
  if [[ "${attempt}" -lt "${verification_attempts}" ]]; then
    sleep "${attempt}"
  fi
done
if [[ ${http3_verified} -ne 1 ]]; then
  fail_with_rollback "deployment verification failed: HTTP/3 version did not converge after retries"
fi

page_verified=0
for attempt in $(seq 1 "${verification_attempts}"); do
  # verification retry loop: page-markers
  page=""
  if page="$(timeout 20s nix run .#curl-http3 -- --http3-only -sS "${url}" 2>/dev/null)"; then
    missing_marker=""
    for marker in "Showcase" "Technical" "Run Live Checks" "Browser Verification"; do
      if ! grep -Fq "${marker}" <<<"${page}"; then
        missing_marker="${marker}"
        break
      fi
    done
    if [[ -z "${missing_marker}" ]]; then
      page_verified=1
      break
    fi
  fi
  if [[ "${attempt}" -lt "${verification_attempts}" ]]; then
    sleep "${attempt}"
  fi
done
if [[ ${page_verified} -ne 1 ]]; then
  fail_with_rollback "deployment verification failed: page markers did not converge after retries"
fi

rollback_armed=0
deploy_succeeded=1
echo "remote demo deploy verified"
