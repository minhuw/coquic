#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s <mode-0600-cloud-input>\n' "$0" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

input_path="$1"
if [[ ! -f "${input_path}" || -L "${input_path}" ]]; then
  echo "cloud configuration input must be a regular file" >&2
  exit 1
fi
if [[ "$(stat -c '%a' -- "${input_path}")" != "600" ]]; then
  echo "cloud configuration input must have mode 0600" >&2
  exit 1
fi
if [[ "$(stat -c '%u' -- "${input_path}")" != "$(id -u)" ]]; then
  echo "cloud configuration input must be owned by the invoking user" >&2
  exit 1
fi

readonly ssh_port="22"
readonly remote_user="minhuw"
readonly remote_host="coquic.minhuw.dev"
readonly remote_target="${remote_user}@${remote_host}"
readonly remote_config_relative="/etc/coquic-demo"
readonly remote_app_env_relative="${remote_config_relative}/app.env"
readonly site_service="coquic-demo.service"

ssh_key_path="${COQUIC_DEMO_REMOTE_SSH_KEY_PATH:-${RUNNER_TEMP:-/tmp}/coquic-demo.key}"
if [[ ! -f "${ssh_key_path}" ]]; then
  echo "missing SSH key path: ${ssh_key_path}" >&2
  exit 1
fi

remote_prefix="${COQUIC_DEPLOY_OFFLINE_ROOT:-}"
if [[ -n "${remote_prefix}" ]]; then
  if [[ "${remote_prefix}" != /* || ! -f "${remote_prefix}/.coquic-deploy-test-root" ]]; then
    echo "offline deploy root is missing its ownership marker" >&2
    exit 1
  fi
  remote_prefix="$(cd "${remote_prefix}" && pwd -P)"
fi
remote_config_root="${remote_prefix}${remote_config_relative}"
remote_app_env="${remote_prefix}${remote_app_env_relative}"
remote_tmp_root="${remote_prefix}/tmp"

ssh_opts=(
  -p "${ssh_port}"
  -i "${ssh_key_path}"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ConnectionAttempts=3
  -o ServerAliveInterval=10
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="${HOME}/.ssh/known_hosts"
)
scp_opts=(
  -P "${ssh_port}"
  -i "${ssh_key_path}"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ConnectionAttempts=3
  -o ServerAliveInterval=10
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="${HOME}/.ssh/known_hosts"
)

cloud_fields=(
  CLOUDFLARE_ACCOUNT_ID
  COQUIC_STEWARD_D1_DATABASE_ID
  COQUIC_STEWARD_D1_READ_TOKEN
  COQUIC_STEWARD_PUBLIC_R2_BASE_URL
)
declare -A allowed_fields=()
declare -A seen_fields=()
declare -A cloud_values=()
for field in "${cloud_fields[@]}"; do
  allowed_fields["${field}"]=1
done

shopt -s extglob
trim_value() {
  local value="$1"
  value="${value##+([[:space:]])}"
  value="${value%%+([[:space:]])}"
  printf '%s' "${value}"
}

reject_input() {
  echo "invalid cloud configuration input: $1" >&2
  exit 1
}

validate_field() {
  local field="$1"
  local value="$2"
  local authority path segment lower_segment encoded decoded
  normalized_value="${value}"

  if [[ "${value}" =~ [[:cntrl:]] ]]; then
    reject_input "malformed ${field} value"
  fi

  case "${field}" in
    CLOUDFLARE_ACCOUNT_ID)
      normalized_value="$(trim_value "${value}")"
      [[ "${normalized_value}" =~ ^[[:xdigit:]]{32}$ ]] || reject_input "malformed ${field} value"
      normalized_value="${normalized_value,,}"
      ;;
    COQUIC_STEWARD_D1_DATABASE_ID)
      normalized_value="$(trim_value "${value}")"
      [[ "${normalized_value}" =~ ^[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$ ]] || reject_input "malformed ${field} value"
      normalized_value="${normalized_value,,}"
      ;;
    COQUIC_STEWARD_D1_READ_TOKEN)
      normalized_value="$(trim_value "${value}")"
      [[ -n "${normalized_value}" && ${#normalized_value} -le 4096 ]] || reject_input "malformed ${field} value"
      ;;
    COQUIC_STEWARD_PUBLIC_R2_BASE_URL)
      normalized_value="$(trim_value "${value}")"
      [[ -n "${normalized_value}" && "${normalized_value}" == https://* ]] || reject_input "malformed ${field} value"
      [[ "${normalized_value}" != *'?'* && "${normalized_value}" != *'#'* && "${normalized_value}" != *'\\'* ]] || reject_input "malformed ${field} value"
      authority="${normalized_value#https://}"
      path="/"
      if [[ "${authority}" == */* ]]; then
        path="/${authority#*/}"
        authority="${authority%%/*}"
      fi
      [[ -n "${authority}" && "${authority}" != *'@'* ]] || reject_input "malformed ${field} value"
      [[ "${authority}" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || reject_input "malformed ${field} value"
      IFS='/' read -r -a path_segments <<< "${path}"
      for segment in "${path_segments[@]}"; do
        [[ -z "${segment}" ]] && continue
        [[ "${segment}" != *'\\'* ]] || reject_input "malformed ${field} value"
        [[ "${segment}" =~ ^([^%]|%[[:xdigit:]]{2})*$ ]] || reject_input "malformed ${field} value"
        encoded="${segment//%/\\x}"
        printf -v decoded '%b' "${encoded}"
        lower_segment="${segment,,}"
        [[ "${lower_segment}" != "." && "${lower_segment}" != ".." && "${decoded}" != "." && "${decoded}" != ".." ]] || reject_input "malformed ${field} value"
        [[ ! "${lower_segment}" =~ %(0[0-9a-f]|1[0-9a-f]|7f) ]] || reject_input "malformed ${field} value"
        [[ ! "${decoded}" =~ [[:cntrl:]] ]] || reject_input "malformed ${field} value"
        [[ "${decoded}" != *'/'* && "${decoded}" != *'\\'* && "${decoded}" != *$'\n'* && "${decoded}" != *$'\r'* ]] || reject_input "malformed ${field} value"
      done
      [[ "${normalized_value}" == */ ]] || normalized_value+="/"
      ;;
    *)
      reject_input "unsupported field ${field}"
      ;;
  esac
}

line_number=0
while IFS= read -r line || [[ -n "${line}" ]]; do
  line_number=$((line_number + 1))
  [[ -n "${line}" ]] || reject_input "blank line at ${line_number}"
  if [[ ! "${line}" =~ ^(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
    reject_input "malformed line ${line_number}"
  fi
  field="${BASH_REMATCH[2]}"
  value="${BASH_REMATCH[3]}"
  [[ ${allowed_fields["${field}"]+present} == present ]] || reject_input "unsupported field ${field}"
  [[ ${seen_fields["${field}"]+present} != present ]] || reject_input "duplicate field ${field}"
  validate_field "${field}" "${value}"
  seen_fields["${field}"]=1
  cloud_values["${field}"]="${normalized_value}"
done < "${input_path}"

for field in "${cloud_fields[@]}"; do
  [[ ${seen_fields["${field}"]+present} == present ]] || reject_input "missing field ${field}"
done

staging_dir="$(mktemp -d)"
cleanup_local() {
  rm -rf -- "${staging_dir}"
}
remote_upload_dir=""
cleanup_remote() {
  if [[ -n "${remote_upload_dir}" ]]; then
    ssh "${ssh_opts[@]}" "${remote_target}" "sudo rm -rf -- '${remote_upload_dir}'" >/dev/null 2>&1 || true
  fi
}
on_exit() {
  local status=$?
  set +e
  cleanup_remote
  cleanup_local
  exit "${status}"
}
trap on_exit EXIT

normalized_input="${staging_dir}/cloud.env"
{
  for field in "${cloud_fields[@]}"; do
    printf '%s=%s\n' "${field}" "${cloud_values["${field}"]}"
  done
} > "${normalized_input}"
chmod 600 "${normalized_input}"

if ! ssh "${ssh_opts[@]}" "${remote_target}" true; then
  echo "remote SSH preflight failed" >&2
  exit 1
fi

remote_upload_dir="$(ssh "${ssh_opts[@]}" "${remote_target}" "umask 077 && mkdir -p '${remote_tmp_root}' && mktemp -d '${remote_tmp_root}/coquic-cloud-config-XXXXXX'")"
if [[ "${remote_upload_dir}" != "${remote_tmp_root}/"* ]]; then
  echo "remote upload directory is outside the offline temporary root" >&2
  exit 1
fi
scp "${scp_opts[@]}" "${normalized_input}" "${remote_target}:${remote_upload_dir}/cloud.env"

remote_status=0
ssh "${ssh_opts[@]}" "${remote_target}" bash -s -- \
  "${remote_upload_dir}" "${remote_config_root}" "${remote_app_env}" "${site_service}" <<'EOF' || remote_status=$?
set -euo pipefail

remote_upload_dir="$1"
remote_config_root="$2"
remote_app_env="$3"
site_service="$4"
input_path="${remote_upload_dir}/cloud.env"
candidate_path="${remote_upload_dir}/app.env.new"
backup_path="${remote_upload_dir}/app.env.bak"
absent_marker="${remote_upload_dir}/app.env.absent"
transaction_armed=0
transaction_succeeded=0

cloud_fields=(
  CLOUDFLARE_ACCOUNT_ID
  COQUIC_STEWARD_D1_DATABASE_ID
  COQUIC_STEWARD_D1_READ_TOKEN
  COQUIC_STEWARD_PUBLIC_R2_BASE_URL
)
declare -A allowed_fields=()
declare -A seen_fields=()
declare -A cloud_values=()
for field in "${cloud_fields[@]}"; do
  allowed_fields["${field}"]=1
done

shopt -s extglob
trim_value() {
  local value="$1"
  value="${value##+([[:space:]])}"
  value="${value%%+([[:space:]])}"
  printf '%s' "${value}"
}

reject_input() {
  echo "invalid cloud configuration input: $1" >&2
  exit 1
}

validate_field() {
  local field="$1"
  local value="$2"
  local authority path segment lower_segment encoded decoded
  normalized_value="${value}"
  if [[ "${value}" =~ [[:cntrl:]] ]]; then
    reject_input "malformed ${field} value"
  fi
  case "${field}" in
    CLOUDFLARE_ACCOUNT_ID)
      normalized_value="$(trim_value "${value}")"
      [[ "${normalized_value}" =~ ^[[:xdigit:]]{32}$ ]] || reject_input "malformed ${field} value"
      normalized_value="${normalized_value,,}"
      ;;
    COQUIC_STEWARD_D1_DATABASE_ID)
      normalized_value="$(trim_value "${value}")"
      [[ "${normalized_value}" =~ ^[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$ ]] || reject_input "malformed ${field} value"
      normalized_value="${normalized_value,,}"
      ;;
    COQUIC_STEWARD_D1_READ_TOKEN)
      normalized_value="$(trim_value "${value}")"
      [[ -n "${normalized_value}" && ${#normalized_value} -le 4096 ]] || reject_input "malformed ${field} value"
      ;;
    COQUIC_STEWARD_PUBLIC_R2_BASE_URL)
      normalized_value="$(trim_value "${value}")"
      [[ -n "${normalized_value}" && "${normalized_value}" == https://* ]] || reject_input "malformed ${field} value"
      [[ "${normalized_value}" != *'?'* && "${normalized_value}" != *'#'* && "${normalized_value}" != *'\\'* ]] || reject_input "malformed ${field} value"
      authority="${normalized_value#https://}"
      path="/"
      if [[ "${authority}" == */* ]]; then
        path="/${authority#*/}"
        authority="${authority%%/*}"
      fi
      [[ -n "${authority}" && "${authority}" != *'@'* ]] || reject_input "malformed ${field} value"
      [[ "${authority}" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || reject_input "malformed ${field} value"
      IFS='/' read -r -a path_segments <<< "${path}"
      for segment in "${path_segments[@]}"; do
        [[ -z "${segment}" ]] && continue
        [[ "${segment}" != *'\\'* ]] || reject_input "malformed ${field} value"
        [[ "${segment}" =~ ^([^%]|%[[:xdigit:]]{2})*$ ]] || reject_input "malformed ${field} value"
        encoded="${segment//%/\\x}"
        printf -v decoded '%b' "${encoded}"
        lower_segment="${segment,,}"
        [[ "${lower_segment}" != "." && "${lower_segment}" != ".." && "${decoded}" != "." && "${decoded}" != ".." ]] || reject_input "malformed ${field} value"
        [[ ! "${lower_segment}" =~ %(0[0-9a-f]|1[0-9a-f]|7f) ]] || reject_input "malformed ${field} value"
        [[ ! "${decoded}" =~ [[:cntrl:]] ]] || reject_input "malformed ${field} value"
        [[ "${decoded}" != *'/'* && "${decoded}" != *'\\'* && "${decoded}" != *$'\n'* && "${decoded}" != *$'\r'* ]] || reject_input "malformed ${field} value"
      done
      [[ "${normalized_value}" == */ ]] || normalized_value+="/"
      ;;
    *)
      reject_input "unsupported field ${field}"
      ;;
  esac
}

if ! sudo test -f "${input_path}" || sudo test -L "${input_path}"; then
  echo "cloud configuration input transfer failed" >&2
  exit 1
fi
if [[ "$(stat -c '%a' -- "${input_path}")" != "600" ]]; then
  echo "cloud configuration input transfer has unsafe mode" >&2
  exit 1
fi

line_number=0
while IFS= read -r line || [[ -n "${line}" ]]; do
  line_number=$((line_number + 1))
  [[ -n "${line}" ]] || reject_input "blank line at ${line_number}"
  if [[ ! "${line}" =~ ^(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
    reject_input "malformed line ${line_number}"
  fi
  field="${BASH_REMATCH[2]}"
  value="${BASH_REMATCH[3]}"
  [[ ${allowed_fields["${field}"]+present} == present ]] || reject_input "unsupported field ${field}"
  [[ ${seen_fields["${field}"]+present} != present ]] || reject_input "duplicate field ${field}"
  validate_field "${field}" "${value}"
  seen_fields["${field}"]=1
  cloud_values["${field}"]="${normalized_value}"
done < "${input_path}"
for field in "${cloud_fields[@]}"; do
  [[ ${seen_fields["${field}"]+present} == present ]] || reject_input "missing field ${field}"
done

sudo install -d -m 755 "${remote_config_root}"
if sudo test -L "${remote_app_env}"; then
  echo "remote app.env must not be a symlink" >&2
  exit 1
fi
if sudo test -e "${remote_app_env}" && ! sudo test -f "${remote_app_env}"; then
  echo "remote app.env must be a regular file" >&2
  exit 1
fi

if sudo test -f "${remote_app_env}"; then
  sudo awk '
    /^[[:space:]]*(export[[:space:]]+)?(CLOUDFLARE_ACCOUNT_ID|COQUIC_STEWARD_D1_DATABASE_ID|COQUIC_STEWARD_D1_READ_TOKEN|COQUIC_STEWARD_PUBLIC_R2_BASE_URL)=/ { next }
    { print }
  ' "${remote_app_env}" > "${candidate_path}"
else
  : > "${candidate_path}"
fi

for field in "${cloud_fields[@]}"; do
  printf -v escaped '%q' "${cloud_values["${field}"]}"
  printf 'export %s=%s\n' "${field}" "${escaped}" >> "${candidate_path}"
done
chmod 600 "${candidate_path}"

changed=1
if sudo test -f "${remote_app_env}" && sudo cmp -s "${candidate_path}" "${remote_app_env}"; then
  changed=0
fi

if [[ "${changed}" == "0" ]]; then
  sudo chown root:root "${remote_app_env}"
  sudo chmod 600 "${remote_app_env}"
  transaction_succeeded=1
  exit 0
fi

service_was_active=0
if sudo systemctl is-active --quiet "${site_service}"; then
  service_was_active=1
fi
service_was_enabled=0
if sudo systemctl is-enabled --quiet "${site_service}"; then
  service_was_enabled=1
fi

if sudo test -e "${remote_app_env}"; then
  sudo cp -a "${remote_app_env}" "${backup_path}"
  sudo rm -f "${absent_marker}"
else
  sudo rm -f "${backup_path}"
  sudo touch "${absent_marker}"
fi
transaction_armed=1

atomic_install() {
  local source_path="$1"
  local destination_path="$2"
  local temporary_path="${destination_path}.tmp.$$"
  sudo install -m 600 "${source_path}" "${temporary_path}"
  sudo mv -f "${temporary_path}" "${destination_path}"
  sudo chown root:root "${destination_path}"
  sudo chmod 600 "${destination_path}"
}

restore_file() {
  if sudo test -f "${backup_path}"; then
    sudo rm -f "${remote_app_env}"
    sudo cp -a "${backup_path}" "${remote_app_env}"
  elif sudo test -f "${absent_marker}"; then
    sudo rm -f "${remote_app_env}"
  fi
}

restore_service() {
  if [[ "${service_was_enabled}" == "1" ]]; then
    sudo systemctl enable "${site_service}" >/dev/null 2>&1 || true
  else
    sudo systemctl disable "${site_service}" >/dev/null 2>&1 || true
  fi
  if [[ "${service_was_active}" == "1" ]]; then
    if ! sudo systemctl is-active --quiet "${site_service}"; then
      sudo systemctl start "${site_service}" >/dev/null 2>&1 || true
    fi
    sudo systemctl is-active --quiet "${site_service}" || return 1
  else
    sudo systemctl stop "${site_service}" >/dev/null 2>&1 || true
    if sudo systemctl is-active --quiet "${site_service}"; then
      return 1
    fi
  fi
}

rollback() {
  local rollback_status=0
  set +e
  restore_file || rollback_status=1
  restore_service || rollback_status=1
  return "${rollback_status}"
}

on_exit() {
  local status=$?
  trap - EXIT
  set +e
  if [[ "${transaction_armed}" == "1" && "${transaction_succeeded}" != "1" ]]; then
    rollback || status=1
  fi
  rm -f -- "${candidate_path}"
  exit "${status}"
}
trap on_exit EXIT

atomic_install "${candidate_path}" "${remote_app_env}"
if [[ "${service_was_active}" == "1" ]]; then
  sudo systemctl restart "${site_service}"
  sudo systemctl is-active --quiet "${site_service}"
fi
transaction_succeeded=1
EOF
if [[ ${remote_status} -ne 0 ]]; then
  echo "cloud configuration install failed" >&2
  exit "${remote_status}"
fi

echo "cloud configuration installed"
