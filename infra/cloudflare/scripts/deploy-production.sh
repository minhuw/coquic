#!/usr/bin/env bash
set -euo pipefail

# This command is an operator-local boundary. It never prints provider output:
# Pulumi, Wrangler, and the Site handoff are captured below a private
# temporary directory and reduced to value-free status messages.
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly cloudflare_dir="$(cd -- "${script_dir}/.." && pwd -P)"
readonly repository_root="$(cd -- "${cloudflare_dir}/../.." && pwd -P)"
readonly schema_path="${repository_root}/contracts/steward-cloud/d1.sql"

usage() {
  cat >&2 <<'EOF'
usage: deploy-production.sh --stack production --credentials-dir DIR [--apply]

Preview is read-only. Add --apply only after reviewing the structured preview
when the current D1, protected credentials, and Site handoff should be bootstrapped.
A blank D1 is initialized, an exact schema is reused, and schema drift fails closed.
EOF
}

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

stack="${PULUMI_STACK:-}"
credentials_dir="${COQUIC_STEWARD_CREDENTIAL_DIR:-}"
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
[[ "${stack}" == "production" ]] || fail "only the production stack is allowed"
[[ -n "${credentials_dir}" ]] || fail "--credentials-dir is required"
[[ "${credentials_dir}" == /* ]] || fail "--credentials-dir must be absolute"
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
cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "${temporary_dir}"
  exit "${status}"
}
trap cleanup EXIT

cd -- "${cloudflare_dir}" || fail "unable to enter the Cloudflare project directory"

if ! "${pulumi_bin}" whoami >"${temporary_dir}/pulumi-whoami.out" 2>"${temporary_dir}/pulumi-whoami.err"; then
  fail "Pulumi Cloud login is required"
fi

preview_output="${temporary_dir}/pulumi-preview.json"
preview_error="${temporary_dir}/pulumi-preview.err"
saved_plan="${temporary_dir}/production.plan"
if ! "${pulumi_bin}" preview \
  --stack "${stack}" \
  --json \
  --non-interactive \
  --save-plan "${saved_plan}" \
  >"${preview_output}" 2>"${preview_error}"; then
  fail "Pulumi preview failed"
fi
[[ -f "${saved_plan}" && ! -L "${saved_plan}" && -s "${saved_plan}" ]] || fail "Pulumi did not create a saved preview plan"
chmod 400 "${saved_plan}"

# Pulumi JSON is a stream of event objects in current releases, while test
# doubles and older releases may emit one JSON array/object. Parse both forms,
# scan all values for secret-shaped material, and admit only this exact graph.
if ! python3 - "${preview_output}" >"${temporary_dir}/preview-parse.out" 2>"${temporary_dir}/preview-parse.err" <<'PY'
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
    ("cloudflare:index/d1database:d1database", "publicationdatabase"),
    ("cloudflare:index/r2bucket:r2bucket", "publicartifacts"),
    ("cloudflare:index/r2bucket:r2bucket", "privateoriginals"),
    ("cloudflare:index/r2customdomain:r2customdomain", "publicartifactsdomain"),
    ("cloudflare:index/r2bucketlifecycle:r2bucketlifecycle", "privateoriginalslifecycle"),
    ("cloudflare:index/accounttoken:accounttoken", "stewardpublicationtoken"),
    ("cloudflare:index/accounttoken:accounttoken", "sitereadertoken"),
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
            child_name = str(child_key)
            if child_name.strip().lower() == "secret" and child is True:
                raise ValueError("preview contains a secret value")
            if sensitive_key.search(child_name) and isinstance(child, str) and child.strip():
                raise ValueError("preview contains a secret value")
            scan_sensitive(child)
    elif isinstance(value, list):
        for child in value:
            scan_sensitive(child)
    elif isinstance(value, str) and sensitive_value.search(value):
        raise ValueError("preview contains a secret value")


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
        raise ValueError("operation has no structured resource identity")
    return found


for item in objects:
    walk(item)

if not records:
    raise ValueError("preview contains no structured resource events")

resource_operations: dict[tuple[str, str], set[str]] = {}
for identity, op in records:
    resource_operations.setdefault(identity, set()).add(op)

if set(resource_operations) != expected_resources:
    raise ValueError("preview resource allowlist does not match the protected stack")
if any(len(operations) != 1 for operations in resource_operations.values()):
    raise ValueError("preview contains conflicting operations for a resource")

allowed_operations = {"create", "same", "read", "refresh"}
for operations in resource_operations.values():
    if next(iter(operations)) not in allowed_operations:
        raise ValueError("preview contains a destructive or updating operation")

counts: Counter[str] = Counter(op for _, op in records)
labels = ("create", "update", "delete", "same", "read", "refresh")
print(" ".join(f"{label}={counts.get(label, 0)}" for label in labels) + f" resources={len(resource_operations)}")
PY
then
  fail "Pulumi preview was not a safe structured plan for the protected stack"
fi

plan_digest="$(sha256sum "${saved_plan}" | cut -d' ' -f1)"
[[ "${plan_digest}" =~ ^[0-9a-f]{64}$ ]] || fail "saved Pulumi plan could not be verified"
printf 'preview accepted for stack %s\n' "${stack}"
printf 'preview operations: %s\n' "$(<"${temporary_dir}/preview-parse.out")"

if ((apply == 0)); then
  printf 'no changes applied (use --apply with this command to continue)\n'
  exit 0
fi

[[ "$(sha256sum "${saved_plan}" | cut -d' ' -f1)" == "${plan_digest}" ]] || fail "saved Pulumi plan changed before apply"
if ! "${pulumi_bin}" up \
  --stack "${stack}" \
  --plan "${saved_plan}" \
  --yes \
  --non-interactive \
  >"${temporary_dir}/pulumi-up.out" 2>"${temporary_dir}/pulumi-up.err"; then
  fail "Pulumi apply failed; cloud state may be partial, and D1 or host changes were not attempted"
fi

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
    "steward_config",
    "site_config",
    "steward_d1_token",
    "steward_s3_access_key_id",
    "steward_s3_secret_access_key",
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
}:
    raise ValueError("Steward output fields drifted")
if set(site) != {
    "account_id",
    "d1_database_id",
    "d1_read_token",
    "public_base_url",
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
if text(payload, "d1_database_id").lower() != steward_values["d1_database_id"].lower():
    raise ValueError("top-level database ID differs")
if text(payload, "public_bucket_name") != steward_values["public_bucket_name"]:
    raise ValueError("top-level bucket name differs")
if text(payload, "public_base_url") != site_values["public_base_url"]:
    raise ValueError("top-level public URL differs")

standalone = {
    "steward_d1_token": steward_values["d1_token"],
    "steward_s3_access_key_id": steward_values["s3_access_key_id"],
    "steward_s3_secret_access_key": steward_values["s3_secret_access_key"],
    "site_d1_read_token": site_values["d1_read_token"],
}
for top_key, expected in standalone.items():
    if text(payload, top_key) != expected:
        raise ValueError("standalone output does not match composite")

values = {
    "account_id": steward_values["account_id"].lower(),
    "d1_database_id": steward_values["d1_database_id"].lower(),
    "d1_token": steward_values["d1_token"],
    "s3_access_key_id": steward_values["s3_access_key_id"],
    "s3_secret_access_key": steward_values["s3_secret_access_key"],
    "site_account_id": site_values["account_id"].lower(),
    "site_d1_database_id": site_values["d1_database_id"].lower(),
    "site_d1_read_token": site_values["d1_read_token"],
    "site_public_base_url": site_values["public_base_url"],
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

d1_database_id="$(read_field d1_database_id)"

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
normalized = [normalize_row(row) for row in rows]
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
  "${wrangler_bin}" d1 execute "${d1_database_id}" \
    --remote \
    --command "${schema_query}" \
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
    if ! "${wrangler_bin}" d1 execute "${d1_database_id}" \
      --remote \
      --file "${schema_path}" \
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
  local -a names=(d1-read-token r2-access-key-id r2-secret-access-key)
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
} >"${site_input}"
chmod 600 -- "${site_input}"

if ! env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_API_KEY -u PULUMI_ACCESS_TOKEN \
  "${site_installer}" "${site_input}" \
  >"${temporary_dir}/site-installer.out" 2>"${temporary_dir}/site-installer.err"; then
  fail "Site cloud configuration handoff failed; D1 and Steward credentials remain"
fi

printf 'cloud bootstrap complete: current D1 verified, Steward credentials installed, and Site handoff completed\n'
