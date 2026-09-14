#!/usr/bin/env bash
set -euo pipefail

# This command is an operator-local boundary. It never prints provider output:
# Pulumi, Wrangler, and the Site handoff are captured below a private temporary
# directory and reduced to value-free status messages. Accepted plans remain in
# a separate private review directory until the explicit apply.
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly cloudflare_dir="$(cd -- "${script_dir}/.." && pwd -P)"
readonly repository_root="$(cd -- "${cloudflare_dir}/../.." && pwd -P)"
readonly schema_path="${repository_root}/contracts/steward-cloud/d1.sql"

usage() {
  cat >&2 <<'EOF'
usage: deploy-production.sh --stack coquic-production --credentials-dir DIR [--plan-dir DIR] [--apply]

Preview is read-only and retains an accepted plan in the private plan directory.
Review that plan, then rerun with --apply to consume exactly that plan; --apply
never creates a replacement preview. A blank D1 is initialized, an exact schema
is reused, and schema drift fails closed.
EOF
}

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

stack="${PULUMI_STACK:-}"
credentials_dir="${COQUIC_STEWARD_CREDENTIAL_DIR:-}"
state_home="${XDG_STATE_HOME:-${HOME:-}}"
plan_dir="${COQUIC_CLOUDFLARE_PLAN_DIR:-${state_home}/coquic-cloudflare-bootstrap}"
site_installer="${COQUIC_SITE_INSTALLER:-${SITE_INSTALLER:-${repository_root}/site/deploy/install-cloud-config.sh}}"
pulumi_bin="${PULUMI_BIN:-pulumi}"
wrangler_bin="${WRANGLER_BIN:-wrangler}"
apply=0

while (($#)); do
  case "$1" in
    --apply)
      apply=1
      shift
      ;;
    --stack)
      (($# >= 2)) || fail "--stack requires a value"
      stack="$2"
      shift 2
      ;;
    --stack=*)
      stack="${1#*=}"
      shift
      ;;
    --credentials-dir)
      (($# >= 2)) || fail "--credentials-dir requires a value"
      credentials_dir="$2"
      shift 2
      ;;
    --credentials-dir=*)
      credentials_dir="${1#*=}"
      shift
      ;;
    --plan-dir)
      (($# >= 2)) || fail "--plan-dir requires a value"
      plan_dir="$2"
      shift 2
      ;;
    --plan-dir=*)
      plan_dir="${1#*=}"
      shift
      ;;
    --site-installer)
      (($# >= 2)) || fail "--site-installer requires a value"
      site_installer="$2"
      shift 2
      ;;
    --site-installer=*)
      site_installer="${1#*=}"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      fail "unknown argument"
      ;;
  esac
done

[[ -n "${stack}" ]] || fail "--stack is required"
[[ "${stack}" == "coquic-production" ]] || fail "only the coquic-production stack is allowed"
[[ -n "${credentials_dir}" ]] || fail "--credentials-dir is required"
[[ "${credentials_dir}" == /* ]] || fail "--credentials-dir must be absolute"
if [[ -z "${state_home}" && -z "${COQUIC_CLOUDFLARE_PLAN_DIR:-}" ]]; then
  fail "XDG_STATE_HOME or HOME is required"
fi
[[ "${plan_dir}" == /* ]] || fail "--plan-dir must be absolute"
[[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || fail "CLOUDFLARE_API_TOKEN is required"
[[ -f "${schema_path}" && ! -L "${schema_path}" ]] || fail "canonical D1 schema is missing"

if [[ "${pulumi_bin}" == */* ]]; then
  [[ -x "${pulumi_bin}" && ! -L "${pulumi_bin}" ]] || fail "Pulumi executable is unavailable"
else
  pulumi_bin="$(command -v "${pulumi_bin}")" || fail "Pulumi executable is unavailable"
fi
if [[ "${wrangler_bin}" == */* ]]; then
  [[ -x "${wrangler_bin}" && ! -L "${wrangler_bin}" ]] || fail "Wrangler executable is unavailable"
else
  wrangler_bin="$(command -v "${wrangler_bin}")" || fail "Wrangler executable is unavailable"
fi
[[ -f "${site_installer}" && ! -L "${site_installer}" && -x "${site_installer}" ]] || fail "Site installer is unavailable"

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/coquic-cloudflare-bootstrap.XXXXXX")" || fail "unable to create private temporary directory"
chmod 700 "${temporary_dir}"
apply_plan_dir=""
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "${apply_plan_dir}" && -d "${apply_plan_dir}" && ! -L "${apply_plan_dir}" ]]; then
    rm -rf -- "${apply_plan_dir}"
  fi
  rm -rf -- "${temporary_dir}"
  exit "${status}"
}
trap cleanup EXIT

operator_uid="$(id -u)" || fail "unable to determine invoking user"
reviewed_plan="${plan_dir}/${stack}.plan"
review_record="${plan_dir}/${stack}.review.json"
review_record_digest=""

ensure_plan_directory() {
  if [[ -L "${plan_dir}" ]]; then
    fail "reviewed plan directory must not be a symlink"
  fi
  if [[ ! -e "${plan_dir}" ]]; then
    ((apply == 0)) || fail "reviewed plan directory is unavailable"
    mkdir -p -- "${plan_dir}" || fail "unable to create reviewed plan directory"
    chmod 700 -- "${plan_dir}" || fail "unable to secure reviewed plan directory"
  fi
  [[ -d "${plan_dir}" && ! -L "${plan_dir}" ]] || fail "reviewed plan directory must be a directory"
  [[ "$(stat -c '%u' -- "${plan_dir}")" == "${operator_uid}" ]] || fail "reviewed plan directory is not owned by the invoking user"
  [[ "$(stat -c '%a' -- "${plan_dir}")" == "700" ]] || fail "reviewed plan directory must have mode 0700"
}

validate_review_file() {
  local path="$1"
  local label="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} is missing or not a regular file"
  [[ "$(stat -c '%u' -- "${path}")" == "${operator_uid}" ]] || fail "${label} is not owned by the invoking user"
  [[ "$(stat -c '%a' -- "${path}")" == "400" ]] || fail "${label} must have mode 0400"
}

invalidate_review() {
  ensure_plan_directory
  local path
  for path in "${reviewed_plan}" "${review_record}"; do
    if [[ -L "${path}" ]]; then
      fail "reviewed plan artifacts must not be symlinks"
    fi
    if [[ -e "${path}" ]]; then
      [[ -f "${path}" ]] || fail "reviewed plan artifact must be a regular file"
      [[ "$(stat -c '%u' -- "${path}")" == "${operator_uid}" ]] || fail "reviewed plan artifact is not owned by the invoking user"
      [[ "$(stat -c '%a' -- "${path}")" == "400" ]] || fail "reviewed plan artifact must have mode 0400"
      rm -f -- "${path}" || fail "unable to invalidate prior reviewed plan"
    fi
  done
}

persist_review() {
  ensure_plan_directory
  local stage_plan stage_record operations
  stage_plan="$(mktemp "${plan_dir}/.${stack}.plan.XXXXXX")" || fail "unable to stage reviewed Pulumi plan"
  stage_record="$(mktemp "${plan_dir}/.${stack}.review.XXXXXX")" || {
    rm -f -- "${stage_plan}"
    fail "unable to stage reviewed Pulumi metadata"
  }
  if ! cp -- "${saved_plan}" "${stage_plan}"; then
    rm -f -- "${stage_plan}" "${stage_record}"
    fail "unable to retain reviewed Pulumi plan"
  fi
  chmod 400 -- "${stage_plan}" || {
    rm -f -- "${stage_plan}" "${stage_record}"
    fail "unable to secure reviewed Pulumi plan"
  }
  operations="$(<"${temporary_dir}/preview-parse.out")"
  if ! python3 - "${stage_record}" "${stack}" "${plan_digest}" "${operations}" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import sys


destination = Path(sys.argv[1])
destination.write_text(
    json.dumps(
        {
            "operations": sys.argv[4],
            "plan_digest": sys.argv[3],
            "stack": sys.argv[2],
        },
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
  then
    rm -f -- "${stage_plan}" "${stage_record}"
    fail "unable to retain reviewed Pulumi metadata"
  fi
  chmod 400 -- "${stage_record}" || {
    rm -f -- "${stage_plan}" "${stage_record}"
    fail "unable to secure reviewed Pulumi metadata"
  }
  [[ "$(sha256sum -- "${stage_plan}" | cut -d' ' -f1)" == "${plan_digest}" ]] || {
    rm -f -- "${stage_plan}" "${stage_record}"
    fail "retained Pulumi plan failed digest validation"
  }
  for path in "${reviewed_plan}" "${review_record}"; do
    [[ ! -L "${path}" ]] || {
      rm -f -- "${stage_plan}" "${stage_record}"
      fail "reviewed plan artifacts must not be symlinks"
    }
  done
  if ! mv -f -- "${stage_plan}" "${reviewed_plan}"; then
    rm -f -- "${stage_plan}" "${stage_record}"
    fail "unable to publish reviewed Pulumi plan"
  fi
  if ! mv -f -- "${stage_record}" "${review_record}"; then
    rm -f -- "${stage_record}"
    fail "unable to publish reviewed Pulumi metadata"
  fi
  validate_review_file "${reviewed_plan}" "reviewed Pulumi plan"
  validate_review_file "${review_record}" "reviewed Pulumi metadata"
}

load_review() {
  ensure_plan_directory
  validate_review_file "${reviewed_plan}" "reviewed Pulumi plan"
  validate_review_file "${review_record}" "reviewed Pulumi metadata"
  if ! plan_digest="$(python3 - "${review_record}" "${stack}" 2>"${temporary_dir}/review-parse.err" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import re
import sys


payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(payload, dict) or set(payload) != {"operations", "plan_digest", "stack"}:
    raise SystemExit(2)
if payload["stack"] != sys.argv[2]:
    raise SystemExit(2)
if not isinstance(payload["plan_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", payload["plan_digest"]):
    raise SystemExit(2)
operations = payload["operations"]
if not isinstance(operations, str):
    raise SystemExit(2)
parts = operations.split()
labels = ("create", "update", "delete", "same", "read", "refresh")
if len(parts) != 7 or tuple(part.split("=", 1)[0] for part in parts[:6]) != labels:
    raise SystemExit(2)
if any(not re.fullmatch(r"[a-z]+=[0-9]+", part) for part in parts[:6]):
    raise SystemExit(2)
if not re.fullmatch(r"resources=[0-9]+", parts[6]):
    raise SystemExit(2)
print(payload["plan_digest"])
PY
  )"; then
    fail "reviewed Pulumi metadata is invalid"
  fi
  [[ "$(sha256sum -- "${reviewed_plan}" | cut -d' ' -f1)" == "${plan_digest}" ]] || fail "reviewed Pulumi plan failed digest validation"
  review_record_digest="$(sha256sum -- "${review_record}" | cut -d' ' -f1)" || fail "reviewed Pulumi metadata could not be hashed"
  saved_plan="${reviewed_plan}"
}

pin_apply_plan() {
  local directory
  directory="$(mktemp -d "${plan_dir}/.${stack}.apply.XXXXXX")" || fail "unable to create private apply plan directory"
  if ! chmod 700 -- "${directory}"; then
    rm -rf -- "${directory}"
    fail "unable to secure private apply plan directory"
  fi
  apply_plan_dir="${directory}"
  saved_plan="${apply_plan_dir}/reviewed.plan"
  if ! ln -P -- "${reviewed_plan}" "${saved_plan}"; then
    fail "unable to pin reviewed Pulumi plan"
  fi
  [[ -f "${saved_plan}" && ! -L "${saved_plan}" ]] || fail "pinned Pulumi plan is not a regular file"
  chmod 400 -- "${saved_plan}" || fail "unable to secure pinned Pulumi plan"
  validate_review_file "${saved_plan}" "pinned Pulumi plan"
  [[ "$(sha256sum -- "${saved_plan}" | cut -d' ' -f1)" == "${plan_digest}" ]] || fail "pinned Pulumi plan failed digest validation"
}

consume_review() {
  ensure_plan_directory
  if [[ -L "${reviewed_plan}" || -L "${review_record}" ]]; then
    fail "reviewed plan artifacts must not be symlinks"
  fi
  [[ -e "${reviewed_plan}" && -e "${review_record}" ]] || return 0
  validate_review_file "${reviewed_plan}" "reviewed Pulumi plan"
  validate_review_file "${review_record}" "reviewed Pulumi metadata"
  local current_plan_digest current_record_digest
  current_plan_digest="$(sha256sum -- "${reviewed_plan}" | cut -d' ' -f1)" || fail "reviewed Pulumi plan could not be hashed after apply"
  current_record_digest="$(sha256sum -- "${review_record}" | cut -d' ' -f1)" || fail "reviewed Pulumi metadata could not be hashed after apply"
  [[ "${current_plan_digest}" == "${plan_digest}" && "${current_record_digest}" == "${review_record_digest}" ]] || return 0
  rm -f -- "${reviewed_plan}" "${review_record}" || fail "unable to consume reviewed Pulumi plan"
}

cd -- "${cloudflare_dir}" || fail "unable to enter the Cloudflare project directory"

if ((apply == 1)); then
  load_review
  pin_apply_plan
else
  invalidate_review
fi

if ! "${pulumi_bin}" whoami >"${temporary_dir}/pulumi-whoami.out" 2>"${temporary_dir}/pulumi-whoami.err"; then
  fail "Pulumi Cloud login is required"
fi

if ((apply == 0)); then
  preview_output="${temporary_dir}/pulumi-preview.json"
  preview_error="${temporary_dir}/pulumi-preview.err"
  saved_plan="${temporary_dir}/${stack}.plan"
  if ! "${pulumi_bin}" preview \
    --stack "${stack}" \
    --json \
    --show-sames \
    --non-interactive \
    --save-plan "${saved_plan}" \
    >"${preview_output}" 2>"${preview_error}"; then
    fail "Pulumi preview failed"
  fi
  [[ -f "${saved_plan}" && ! -L "${saved_plan}" && -s "${saved_plan}" ]] || fail "Pulumi did not create a saved preview plan"
  chmod 400 "${saved_plan}"
fi

if ((apply == 0)); then
  # Pulumi --json emits a summary object by default, or an event stream when
  # streaming is enabled. Parse both forms, scan all values for secret-shaped
  # material, and admit only this exact graph, including Pulumi's root stack.
if python3 - "${preview_output}" >"${temporary_dir}/preview-parse.out" 2>"${temporary_dir}/preview-parse.err" <<'PY'
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import re
import sys


raw = Path(sys.argv[1]).read_text(encoding="utf-8")
if not raw.strip():
    raise SystemExit(2)

objects: list[object] = []
try:
    parsed = json.loads(raw)
    objects = parsed if isinstance(parsed, list) else [parsed]
except json.JSONDecodeError:
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            raise SystemExit(2) from None

if not objects or not all(isinstance(item, (dict, list)) for item in objects):
    raise SystemExit(2)

operation_keys = {"op", "operation", "action", "change"}
resource_wrapper_keys = {
    "metadata",
    "resource",
    "resourcepreevent",
    "resourcepostevent",
    "resourceoutputsevent",
    "event",
}
sensitive_key = re.compile(
    r"(?i)(?:access[_ -]?token|api[_ -]?key|password|private[_ -]?key|secret|credential)"
)
sensitive_value = re.compile(
    r"(?i)begin private key|authorization\s*:\s*bearer|"
    r"(?:api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]|\bsecret\b"
)

expected_resources = {
    ("pulumi:pulumi:stack", "coquic-cloudflare-coquic-production"),
    ("cloudflare:index/d1database:d1database", "publicationdatabase"),
    ("cloudflare:index/r2bucket:r2bucket", "publicartifacts"),
    ("cloudflare:index/r2bucket:r2bucket", "privateoriginals"),
    ("cloudflare:index/r2customdomain:r2customdomain", "publicartifactsdomain"),
    ("cloudflare:index/r2bucketlifecycle:r2bucketlifecycle", "privateoriginalslifecycle"),
    ("cloudflare:index/accounttoken:accounttoken", "stewardpublicationtoken"),
    ("cloudflare:index/accounttoken:accounttoken", "sitereadertoken"),
    ("cloudflare:index/workersscript:workersscript", "stewardlivegateway"),
    ("cloudflare:index/workerscustomdomain:workerscustomdomain", "stewardlivedomain"),
}


def normalize(value: object) -> str:
    return str(value).strip().lower().replace("_", "")


def urn_identity(value: object) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    parts = value.split("::")
    if len(parts) < 2:
        return None
    resource_type, name = parts[-2:]
    if not resource_type or not name:
        return None
    return normalize(resource_type), normalize(name)


def resource_identity(value: object) -> tuple[str, str] | None:
    if not isinstance(value, dict):
        return None
    identity = urn_identity(value.get("urn"))
    resource_type = value.get("type")
    name = value.get("name")
    if isinstance(resource_type, str) and isinstance(name, str) and resource_type and name:
        identity = (normalize(resource_type), normalize(name))
    return identity


def operation(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    normalized_keys = {normalize(item) for item in operation_keys}
    for key, child in value.items():
        if normalize(key) in normalized_keys and isinstance(child, str):
            return child.strip().lower().replace("_", "-")
    return None


def scan_sensitive(value: object) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            # Pulumi redacts existing secret outputs in retry previews.
            if child == "[secret]":
                continue
            child_name = str(child_key)
            if child_name.strip().lower() == "secret" and child is True:
                raise SystemExit(20)
            if sensitive_key.search(child_name) and isinstance(child, str) and child.strip():
                raise SystemExit(21)
            scan_sensitive(child)
    elif isinstance(value, list):
        for child in value:
            scan_sensitive(child)
    elif isinstance(value, str) and value != "[secret]" and sensitive_value.search(value):
        raise SystemExit(22)


records: set[tuple[tuple[str, str], str]] = set()


def walk(value: object) -> int:
    if isinstance(value, list):
        return sum(walk(child) for child in value)
    if not isinstance(value, dict):
        return 0
    scan_sensitive(value)
    found = 0
    current_operation = operation(value)
    identity = resource_identity(value)
    if current_operation is not None and identity is not None:
        records.add((identity, current_operation))
        found += 1
    elif current_operation is not None:
        for child_key, child in value.items():
            if normalize(child_key) in resource_wrapper_keys:
                child_identity = resource_identity(child)
                if child_identity is not None:
                    records.add((child_identity, current_operation))
                    found += 1
    for child in value.values():
        found += walk(child)
    if current_operation is not None and identity is None and found == 0:
        raise SystemExit(23)
    return found


for item in objects:
    walk(item)

if not records:
    raise SystemExit(24)

resource_operations: dict[tuple[str, str], set[str]] = {}
for identity, op in records:
    resource_operations.setdefault(identity, set()).add(op)

if set(resource_operations) != expected_resources:
    raise SystemExit(25)
if any(len(operations) != 1 for operations in resource_operations.values()):
    raise SystemExit(26)

allowed_operations = {"create", "same", "read", "refresh"}
worker_identity = (
    "cloudflare:index/workersscript:workersscript",
    "stewardlivegateway",
)
for identity, operations in resource_operations.items():
    operation = next(iter(operations))
    if operation not in allowed_operations and not (
        identity == worker_identity and operation == "update"
    ):
        raise SystemExit(27)

counts: Counter[str] = Counter(op for _, op in records)
labels = ("create", "update", "delete", "same", "read", "refresh")
print(" ".join(f"{label}={counts.get(label, 0)}" for label in labels) + f" resources={len(resource_operations)}")
PY
then
  : # Only a successfully checked preview can be retained below.
else
  # Report fixed labels only; never print provider text or parser tracebacks.
  case "$?" in
    2) reason="invalid preview JSON" ;;
    20) reason="unredacted secret wrapper" ;;
    21) reason="unredacted sensitive field" ;;
    22) reason="secret-shaped string" ;;
    23) reason="operation without resource identity" ;;
    24) reason="missing resource operations" ;;
    25) reason="resource allowlist mismatch" ;;
    26) reason="conflicting resource operations" ;;
    27) reason="update, delete, replacement, or unsupported operation" ;;
    *) reason="unexpected parser failure" ;;
  esac
  fail "Pulumi preview was not a safe structured plan for the protected stack: ${reason}"
fi
fi

if ((apply == 0)); then
  plan_digest="$(sha256sum -- "${saved_plan}" | cut -d' ' -f1)"
  [[ "${plan_digest}" =~ ^[0-9a-f]{64}$ ]] || fail "saved Pulumi plan could not be verified"
  persist_review
  printf 'preview accepted for stack %s\n' "${stack}"
  printf 'preview operations: %s\n' "$(<"${temporary_dir}/preview-parse.out")"
  printf 'reviewed plan retained with digest: %s\n' "${plan_digest}"
  printf 'no changes applied (review the plan, then rerun with --apply)\n'
  exit 0
fi

printf 'reviewed plan accepted for stack %s\n' "${stack}"
printf 'reviewed plan digest: %s\n' "${plan_digest}"
[[ "$(sha256sum -- "${saved_plan}" | cut -d' ' -f1)" == "${plan_digest}" ]] || fail "reviewed Pulumi plan changed before apply"
if ! "${pulumi_bin}" up \
  --stack "${stack}" \
  --plan "${saved_plan}" \
  --yes \
  --non-interactive \
  >"${temporary_dir}/pulumi-up.out" 2>"${temporary_dir}/pulumi-up.err"; then
  fail "Pulumi apply failed; cloud state may be partial, and D1 or host changes were not attempted"
fi
consume_review

stack_outputs="${temporary_dir}/stack-outputs.json"
if ! "${pulumi_bin}" stack output \
  --stack "${stack}" \
  --json \
  --show-secrets \
  >"${stack_outputs}" 2>"${temporary_dir}/stack-outputs.err"; then
  fail "Pulumi outputs could not be read; cloud apply completed, but D1 and host changes were not attempted"
fi

output_fields="${temporary_dir}/output-fields"
mkdir -m 700 -- "${output_fields}"
if ! python3 - "${stack_outputs}" "${output_fields}" >"${temporary_dir}/output-parse.out" 2>"${temporary_dir}/output-parse.err" <<'PY'
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys


source = Path(sys.argv[1])
destination = Path(sys.argv[2])
hex_id = re.compile(r"^[0-9a-fA-F]{32}$")
database_id = re.compile(
    r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"
)


def unwrap(value: object) -> object:
    if isinstance(value, dict) and set(value) >= {"value", "secret"} and isinstance(value["secret"], bool):
        return unwrap(value["value"])
    return value


def text(mapping: dict[str, object], key: str) -> str:
    value = unwrap(mapping.get(key))
    if not isinstance(value, str) or not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("invalid output value")
    return value


payload = unwrap(json.loads(source.read_text(encoding="utf-8")))
if not isinstance(payload, dict):
    raise ValueError("outputs are not an object")
allowed_top = {
    "d1_database_id",
    "public_bucket_name",
    "public_base_url",
    "live_url",
    "steward_config",
    "site_config",
    "steward_d1_token",
    "steward_s3_access_key_id",
    "steward_s3_secret_access_key",
    "steward_live_write_token",
    "site_d1_read_token",
}
if set(payload) != allowed_top:
    raise ValueError("output allowlist contains an unexpected or missing field")

steward = unwrap(payload["steward_config"])
site = unwrap(payload["site_config"])
if not isinstance(steward, dict) or not isinstance(site, dict):
    raise ValueError("composite output is missing")
if set(steward) != {
    "account_id",
    "d1_database_id",
    "d1_token",
    "public_bucket_name",
    "private_bucket_name",
    "s3_access_key_id",
    "s3_secret_access_key",
    "live_url",
    "live_write_token",
}:
    raise ValueError("Steward output fields drifted")
if set(site) != {
    "account_id",
    "d1_database_id",
    "d1_read_token",
    "public_base_url",
    "live_url",
}:
    raise ValueError("Site output fields drifted")

steward_values = {key: text(steward, key) for key in steward}
site_values = {key: text(site, key) for key in site}
if not hex_id.fullmatch(steward_values["account_id"]):
    raise ValueError("invalid account ID")
if not database_id.fullmatch(steward_values["d1_database_id"]):
    raise ValueError("invalid database ID")
if steward_values["account_id"].lower() != site_values["account_id"].lower():
    raise ValueError("account IDs differ")
if steward_values["d1_database_id"].lower() != site_values["d1_database_id"].lower():
    raise ValueError("database IDs differ")
if not site_values["public_base_url"].startswith("https://") or any(
    char in site_values["public_base_url"] for char in "?#\r\n"
):
    raise ValueError("invalid public URL")
if steward_values["live_url"] != "https://live.coquic.minhuw.dev/api/steward/live":
    raise ValueError("invalid live URL")
if site_values["live_url"] != steward_values["live_url"]:
    raise ValueError("live URLs differ")
if text(payload, "d1_database_id").lower() != steward_values["d1_database_id"].lower():
    raise ValueError("top-level database ID differs")
if text(payload, "public_bucket_name") != steward_values["public_bucket_name"]:
    raise ValueError("top-level bucket name differs")
if text(payload, "public_base_url") != site_values["public_base_url"]:
    raise ValueError("top-level public URL differs")
if text(payload, "live_url") != site_values["live_url"]:
    raise ValueError("top-level live URL differs")

standalone = {
    "steward_d1_token": steward_values["d1_token"],
    "steward_s3_access_key_id": steward_values["s3_access_key_id"],
    "steward_s3_secret_access_key": steward_values["s3_secret_access_key"],
    "steward_live_write_token": steward_values["live_write_token"],
    "site_d1_read_token": site_values["d1_read_token"],
}
for top_key, expected in standalone.items():
    if text(payload, top_key) != expected:
        raise ValueError("standalone output does not match composite")
if steward_values["live_write_token"] in {
    steward_values["d1_token"],
    steward_values["s3_access_key_id"],
    steward_values["s3_secret_access_key"],
    site_values["d1_read_token"],
}:
    raise ValueError("live credential is not distinct")

values = {
    "account_id": steward_values["account_id"].lower(),
    "d1_database_id": steward_values["d1_database_id"].lower(),
    "d1_token": steward_values["d1_token"],
    "s3_access_key_id": steward_values["s3_access_key_id"],
    "s3_secret_access_key": steward_values["s3_secret_access_key"],
    "live_write_token": steward_values["live_write_token"],
    "site_account_id": site_values["account_id"].lower(),
    "site_d1_database_id": site_values["d1_database_id"].lower(),
    "site_d1_read_token": site_values["d1_read_token"],
    "site_public_base_url": site_values["public_base_url"],
    "site_live_url": site_values["live_url"],
}
for key, value in values.items():
    path = destination / key
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)
        handle.write("\n")
PY
then
  fail "Pulumi outputs failed the exact secret allowlist; cloud apply completed, but D1 and host changes were not attempted"
fi

read_field() {
  local field="$1"
  [[ -f "${output_fields}/${field}" && ! -L "${output_fields}/${field}" ]] || fail "validated output field is missing"
  local value
  value="$(<"${output_fields}/${field}")"
  [[ -n "${value}" ]] || fail "validated output field is empty"
  printf '%s' "${value}"
}

d1_account_id="$(read_field account_id)"
d1_database_id="$(read_field d1_database_id)"
# Wrangler execute accepts a name/binding, not a raw UUID. Pin the binding to
# the validated Pulumi ID instead of discovering a database by name.
wrangler_config="${temporary_dir}/wrangler.json"
printf '{"d1_databases":[{"binding":"PUBLICATION","database_id":"%s"}]}\n' \
  "${d1_database_id}" >"${wrangler_config}"

wrangler_d1() {
  CLOUDFLARE_ACCOUNT_ID="${d1_account_id}" \
    WRANGLER_LOG_PATH="${temporary_dir}/wrangler-logs" \
    WRANGLER_SEND_METRICS=false \
    "${wrangler_bin}" d1 execute PUBLICATION \
    --config "${wrangler_config}" --remote "$@"
}

canonical_schema="${temporary_dir}/canonical-schema.json"
if ! python3 - "${schema_path}" "${canonical_schema}" >"${temporary_dir}/canonical-schema.out" 2>"${temporary_dir}/canonical-schema.err" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys


schema = Path(sys.argv[1]).read_text(encoding="utf-8")
connection = sqlite3.connect(":memory:")
try:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(schema)
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
finally:
    connection.close()

result = [
    {"type": row[0], "name": row[1], "tbl_name": row[2], "sql": row[3]}
    for row in rows
]
Path(sys.argv[2]).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
PY
then
  fail "canonical D1 schema could not be introspected"
fi

schema_query="SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
reconcile_schema() {
  local response_path="$1"
  local state
  if ! python3 - "${response_path}" "${canonical_schema}" >"${temporary_dir}/schema-state.out" 2>"${temporary_dir}/schema-state.err" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import sys


response = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))


def normalize_structure(value: str) -> str:
    return " ".join(value.split()).rstrip(";").lower()


def normalize_sql(value: str) -> str:
    result: list[str] = []
    pending_space = False
    quote: str | None = None
    index = 0
    while index < len(value):
        char = value[index]
        if quote is not None:
            result.append(char)
            if quote == "[":
                if char == "]":
                    quote = None
            elif char == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    index += 1
                    result.append(value[index])
                else:
                    quote = None
        elif char.isspace():
            pending_space = True
        else:
            if pending_space and result:
                result.append(" ")
            pending_space = False
            if char in ("'", '"', "`", "["):
                quote = char
                result.append(char)
            else:
                result.append(char.lower())
        index += 1
    if quote is not None:
        raise ValueError("remote schema SQL has an unterminated quote")
    normalized = "".join(result).strip()
    while normalized.endswith(";"):
        normalized = normalized[:-1].rstrip()
    return normalized


def normalize_row(row: object) -> dict[str, str | None]:
    if not isinstance(row, dict) or not {"type", "name", "tbl_name", "sql"} <= set(row):
        raise ValueError("schema row is malformed")
    if any(
        not isinstance(row[key], (str, type(None)))
        for key in ("type", "name", "tbl_name", "sql")
    ):
        raise ValueError("schema row has invalid values")
    return {
        "type": None if row["type"] is None else normalize_structure(row["type"]),
        "name": None if row["name"] is None else normalize_structure(row["name"]),
        "tbl_name": None if row["tbl_name"] is None else normalize_structure(row["tbl_name"]),
        "sql": None if row["sql"] is None else normalize_sql(row["sql"]),
    }


def result_rows(value: object) -> object:
    if isinstance(value, dict):
        if value.get("success") is False:
            raise ValueError("remote query failed")
        errors = value.get("errors")
        if errors not in (None, [], {}):
            raise ValueError("remote query returned errors")
        if isinstance(value.get("results"), list):
            rows = value["results"]
            if not rows or all(isinstance(item, dict) and "type" in item for item in rows):
                return rows
            for item in rows:
                try:
                    return result_rows(item)
                except ValueError:
                    continue
        if "result" in value:
            return result_rows(value["result"])
    if isinstance(value, list):
        if all(isinstance(item, dict) and "type" in item for item in value):
            return value
        for item in value:
            try:
                return result_rows(item)
            except ValueError:
                continue
    raise ValueError("remote schema output is malformed")


rows = result_rows(response)
if not isinstance(expected, list):
    raise ValueError("canonical schema is malformed")
normalized = []
for row in rows:
    item = normalize_row(row)
    # Match D1's exact system-table identity, not a prefix or normalized name.
    if (row["type"], row["name"], row["tbl_name"]) != ("table", "_cf_KV", "_cf_KV"):
        normalized.append(item)
expected_rows = [normalize_row(row) for row in expected]
normalized.sort(key=lambda item: (item["type"] or "", item["name"] or ""))
expected_rows.sort(key=lambda item: (item["type"] or "", item["name"] or ""))
if not normalized:
    print("blank")
elif normalized == expected_rows:
    print("exact")
else:
    print("drift")
PY
  then
    return 1
  fi
  state="$(<"${temporary_dir}/schema-state.out")"
  case "${state}" in
    blank|exact|drift)
      printf '%s' "${state}"
      ;;
    *)
      return 1
      ;;
  esac
}

query_schema() {
  local response_path="$1"
  wrangler_d1 --command "${schema_query}" \
    --json \
    >"${response_path}" 2>"${temporary_dir}/wrangler-query.err"
}

schema_response="${temporary_dir}/schema.json"
if ! query_schema "${schema_response}"; then
  fail "D1 schema inspection failed"
fi
schema_state="$(reconcile_schema "${schema_response}")" || fail "D1 schema output was malformed"
case "${schema_state}" in
  blank)
    if ! wrangler_d1 --file "${schema_path}" \
      --yes \
      >"${temporary_dir}/wrangler-bootstrap.out" 2>"${temporary_dir}/wrangler-bootstrap.err"; then
      fail "D1 bootstrap failed; no host credentials were installed"
    fi
    if ! query_schema "${temporary_dir}/schema-after-bootstrap.json"; then
      fail "D1 verification after bootstrap failed"
    fi
    after_bootstrap="$(reconcile_schema "${temporary_dir}/schema-after-bootstrap.json")" || fail "D1 verification output was malformed"
    [[ "${after_bootstrap}" == "exact" ]] || fail "D1 bootstrap did not produce the canonical schema"
    ;;
  exact)
    ;;
  drift)
    fail "D1 schema drift requires a separately reviewed forward change"
    ;;
esac

ensure_credentials_directory() {
  if [[ -L "${credentials_dir}" ]]; then
    fail "credential directory must not be a symlink"
  fi
  if [[ ! -e "${credentials_dir}" ]]; then
    mkdir -p -- "${credentials_dir}" || fail "unable to create credential directory"
    chmod 700 -- "${credentials_dir}"
  fi
  [[ -d "${credentials_dir}" && ! -L "${credentials_dir}" ]] || fail "credential directory must be a directory"
  [[ "$(stat -c '%u' -- "${credentials_dir}")" == "$(id -u)" ]] || fail "credential directory is not owned by the invoking user"
  [[ "$(stat -c '%a' -- "${credentials_dir}")" == "700" ]] || fail "credential directory must have mode 0700"
}

install_steward_credentials() {
  ensure_credentials_directory
  local stage="${credentials_dir}/.coquic-steward-bootstrap.$$"
  local -a names=(d1-read-token r2-access-key-id r2-secret-access-key live-write-token)
  local -a old_names=()
  local -a installed_names=()
  local name destination value
  mkdir -m 700 -- "${stage}" || fail "unable to create credential staging directory"

  restore_credentials() {
    local restore_name restore_destination
    set +e
    for restore_name in "${installed_names[@]}"; do
      restore_destination="${credentials_dir}/${restore_name}"
      rm -f -- "${restore_destination}"
    done
    for restore_name in "${old_names[@]}"; do
      if [[ -f "${stage}/old-${restore_name}" ]]; then
        mv -f -- "${stage}/old-${restore_name}" "${credentials_dir}/${restore_name}"
      fi
    done
    rm -rf -- "${stage}"
    set -e
  }

  for name in "${names[@]}"; do
    destination="${credentials_dir}/${name}"
    if [[ -L "${destination}" ]]; then
      restore_credentials
      fail "credential target must not be a symlink"
    fi
    if [[ -e "${destination}" ]]; then
      [[ -f "${destination}" ]] || { restore_credentials; fail "credential target must be a regular file"; }
      [[ "$(stat -c '%u' -- "${destination}")" == "$(id -u)" ]] || { restore_credentials; fail "credential target is not owned by the invoking user"; }
      mv -- "${destination}" "${stage}/old-${name}" || { restore_credentials; fail "unable to stage existing credential"; }
      old_names+=("${name}")
    fi
    case "${name}" in
      d1-read-token)
        value="$(read_field d1_token)" || { restore_credentials; fail "validated D1 credential is missing"; }
        ;;
      r2-access-key-id)
        value="$(read_field s3_access_key_id)" || { restore_credentials; fail "validated R2 access credential is missing"; }
        ;;
      r2-secret-access-key)
        value="$(read_field s3_secret_access_key)" || { restore_credentials; fail "validated R2 secret credential is missing"; }
        ;;
      live-write-token)
        value="$(read_field live_write_token)" || { restore_credentials; fail "validated live credential is missing"; }
        ;;
    esac
    if ! printf '%s\n' "${value}" >"${stage}/new-${name}"; then
      restore_credentials
      fail "unable to stage credential files"
    fi
    if ! chmod 600 -- "${stage}/new-${name}"; then
      restore_credentials
      fail "unable to secure staged credential files"
    fi
  done

  for name in "${names[@]}"; do
    mv -f -- "${stage}/new-${name}" "${credentials_dir}/${name}" || { restore_credentials; fail "unable to install credential files"; }
    installed_names+=("${name}")
  done
  for name in "${names[@]}"; do
    destination="${credentials_dir}/${name}"
    [[ -f "${destination}" && ! -L "${destination}" ]] || { restore_credentials; fail "installed credential is not a regular file"; }
    [[ "$(stat -c '%u' -- "${destination}")" == "$(id -u)" && "$(stat -c '%a' -- "${destination}")" == "600" ]] || { restore_credentials; fail "installed credential has unsafe ownership or mode"; }
  done
  rm -rf -- "${stage}"
}

install_steward_credentials

site_input="${temporary_dir}/site-cloud-config.env"
{
  printf 'CLOUDFLARE_ACCOUNT_ID=%s\n' "$(read_field site_account_id)"
  printf 'COQUIC_STEWARD_D1_DATABASE_ID=%s\n' "$(read_field site_d1_database_id)"
  printf 'COQUIC_STEWARD_D1_READ_TOKEN=%s\n' "$(read_field site_d1_read_token)"
  printf 'COQUIC_STEWARD_PUBLIC_R2_BASE_URL=%s\n' "$(read_field site_public_base_url)"
  printf 'COQUIC_STEWARD_LIVE_SNAPSHOT_URL=%s\n' "$(read_field site_live_url)"
} >"${site_input}"
chmod 600 -- "${site_input}"

if ! env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_API_KEY -u PULUMI_ACCESS_TOKEN \
  "${site_installer}" "${site_input}" \
  >"${temporary_dir}/site-installer.out" 2>"${temporary_dir}/site-installer.err"; then
  fail "Site cloud configuration handoff failed; D1 and Steward credentials remain"
fi

printf 'cloud bootstrap complete: current D1 verified, Steward credentials installed, and Site handoff completed\n'
