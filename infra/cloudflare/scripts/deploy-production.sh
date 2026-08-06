#!/usr/bin/env bash
set -euo pipefail

# This command is intentionally an operator-local boundary.  It never prints
# provider output: Pulumi, Wrangler, and the Site handoff are captured below a
# private temporary directory and reduced to value-free status messages.
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly cloudflare_dir="$(cd -- "${script_dir}/.." && pwd -P)"
readonly repository_root="$(cd -- "${cloudflare_dir}/../.." && pwd -P)"
readonly schema_path="${repository_root}/contracts/steward-cloud/d1.sql"

usage() {
  cat >&2 <<'EOF'
usage: deploy-production.sh --stack production --credentials-dir DIR \
  --mode prepare|activate [--apply]

Preview is the default.  Prepare applies only the accepted create-only
preview, bootstraps and verifies the candidate D1, and installs three private
Steward files.  Activate re-verifies the prepared candidate and one real task,
then hands Site its protected four-field input file.  Activate never applies
Pulumi and either mode leaves the old D1 untouched.
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
mode="${COQUIC_ROLLOUT_MODE:-}"
apply=0

while (($#)); do
  case "$1" in
    --apply)
      apply=1
      shift
      ;;
    --mode|--gate)
      (($# >= 2)) || fail "$1 requires a value"
      mode="$2"
      shift 2
      ;;
    --mode=*|--gate=*)
      mode="${1#*=}"
      shift
      ;;
    --prepare)
      mode="prepare"
      shift
      ;;
    --activate)
      mode="activate"
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
    --credentials-dir|--credential-dir)
      (($# >= 2)) || fail "$1 requires a value"
      credentials_dir="$2"
      shift 2
      ;;
    --credentials-dir=*|--credential-dir=*)
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
[[ "${mode}" == "prepare" || "${mode}" == "activate" ]] || fail "--mode must be prepare or activate"
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

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/coquic-cloudflare-rollout.XXXXXX")" || fail "unable to create private temporary directory"
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

# Pulumi's JSON mode is a stream of event objects in current releases, while
# test doubles and older releases may emit one JSON array/object.  Parse both
# forms and admit only the managed resources and transitions below.  Resource
# identity is checked separately from operation text so an arbitrary create
# event cannot satisfy the create-only gate.
if ! python3 - "${preview_output}" "${mode}" >"${temporary_dir}/preview-parse.out" 2>"${temporary_dir}/preview-parse.err" <<'PY'
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import re
import sys


raw = Path(sys.argv[1]).read_text(encoding="utf-8")
mode = sys.argv[2]
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
resource_wrapper_keys = {"metadata", "resource", "resourcepreevent", "resourcepostevent", "resourceoutputsevent", "event"}
sensitive_key = re.compile(r"(?i)(?:access[_ -]?token|api[_ -]?key|password|private[_ -]?key|secret|credential)")
sensitive_value = re.compile(r"(?i)begin private key|authorization\s*:\s*bearer|(?:api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]|\bsecret\b")

# These are the Pulumi type/name identities owned by this stack.  The
# publication database and all non-usage resources must remain retained.
expected_resources = {
    ("cloudflare:index/d1database:d1database", "publicationdatabase"),
    ("cloudflare:index/d1database:d1database", "usagedatabase"),
    ("cloudflare:index/r2bucket:r2bucket", "publicartifacts"),
    ("cloudflare:index/r2bucket:r2bucket", "privateoriginals"),
    ("cloudflare:index/r2customdomain:r2customdomain", "publicartifactsdomain"),
    ("cloudflare:index/r2bucketlifecycle:r2bucketlifecycle", "privateoriginalslifecycle"),
    ("cloudflare:index/accounttoken:accounttoken", "stewardpublicationtoken"),
    ("cloudflare:index/accounttoken:accounttoken", "sitereadertoken"),
}
candidate_resource = ("cloudflare:index/d1database:d1database", "usagedatabase")


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
    for key, child in value.items():
        if normalize(key) in {normalize(item) for item in operation_keys} and isinstance(child, str):
            return child.strip().lower().replace("_", "-")
    return None


def scan_sensitive(value: object, key: str | None = None) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            child_name = str(child_key)
            if child_name.strip().lower() == "secret" and child is True:
                raise ValueError("preview contains a secret value")
            if sensitive_key.search(child_name) and isinstance(child, str) and child.strip():
                raise ValueError("preview contains a secret value")
            scan_sensitive(child, child_name)
    elif isinstance(value, list):
        for child in value:
            scan_sensitive(child, key)
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
    for child_key, child in value.items():
        # Provider event wrappers put the operation and resource identity in a
        # nested metadata object.  Walk all children, but use the count to
        # distinguish a wrapper from an unstructured operation record.
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

for identity, operations in resource_operations.items():
    op = next(iter(operations))
    if identity == candidate_resource:
        if op not in {"create", "same", "read", "refresh"}:
            raise ValueError("candidate database transition is not create-only")
        if mode == "activate" and op == "create":
            raise ValueError("activation requires an already-prepared candidate")
    elif op not in {"same", "read", "refresh"}:
        raise ValueError("retained resource transition is not read-only")

counts: Counter[str] = Counter(op for _, op in records)
labels = ("create", "update", "same", "read", "refresh")
print(" ".join(f"{label}={counts.get(label, 0)}" for label in labels) + f" resources={len(resource_operations)}")
PY
then
  fail "Pulumi preview was not a safe structured plan or create-only resource allowlist"
fi

plan_digest="$(sha256sum "${saved_plan}" | cut -d' ' -f1)"
[[ "${plan_digest}" =~ ^[0-9a-f]{64}$ ]] || fail "saved Pulumi plan could not be verified"
printf 'preview accepted for stack %s\n' "${stack}"
printf 'preview operations: %s\n' "$(<"${temporary_dir}/preview-parse.out")"

preview_operations="$(<"${temporary_dir}/preview-parse.out")"
if [[ "${preview_operations}" =~ update=([1-9][0-9]*) ]]; then
  fail "${mode} gate requires a create-only Pulumi preview"
fi
if [[ "${mode}" == "activate" && "${preview_operations}" =~ create=([1-9][0-9]*) ]]; then
  fail "activation requires an already-prepared candidate"
fi

if ((apply == 0)); then
  printf 'no changes applied (use --apply with this command to continue)\n'
  exit 0
fi

[[ "$(sha256sum "${saved_plan}" | cut -d' ' -f1)" == "${plan_digest}" ]] || fail "saved Pulumi plan changed before apply"
if [[ "${mode}" == "prepare" ]]; then
  if ! "${pulumi_bin}" up \
    --stack "${stack}" \
    --plan "${saved_plan}" \
    --yes \
    --non-interactive \
    >"${temporary_dir}/pulumi-up.out" 2>"${temporary_dir}/pulumi-up.err"; then
    fail "Pulumi apply failed; cloud state may be partial, and no D1 or host changes were attempted"
  fi
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
database_id = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


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
    "usage_d1_database_id",
    "rollback_d1_database_id",
    "public_bucket_name",
    "public_base_url",
    "steward_config",
    "site_config",
    "steward_d1_token",
    "steward_s3_access_key_id",
    "steward_s3_secret_access_key",
    "site_d1_read_token",
}
if set(payload) - allowed_top:
    raise ValueError("unexpected output field")

steward = unwrap(payload.get("steward_config"))
site = unwrap(payload.get("site_config"))
if not isinstance(steward, dict) or not isinstance(site, dict):
    raise ValueError("composite output is missing")
if set(steward) != {
    "account_id",
    "d1_database_id",
    "rollback_d1_database_id",
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
    "rollback_d1_database_id",
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
if not database_id.fullmatch(steward_values["rollback_d1_database_id"]):
    raise ValueError("invalid rollback database ID")
if steward_values["d1_database_id"].lower() == steward_values["rollback_d1_database_id"].lower():
    raise ValueError("candidate and rollback database IDs must differ")
if steward_values["account_id"].lower() != site_values["account_id"].lower():
    raise ValueError("account IDs differ")
if steward_values["d1_database_id"].lower() != site_values["d1_database_id"].lower():
    raise ValueError("database IDs differ")
if steward_values["rollback_d1_database_id"].lower() != site_values["rollback_d1_database_id"].lower():
    raise ValueError("rollback database IDs differ")
if not site_values["public_base_url"].startswith("https://") or any(char in site_values["public_base_url"] for char in "?#\r\n"):
    raise ValueError("invalid public URL")
if "d1_database_id" in payload and text(payload, "d1_database_id").lower() != steward_values["d1_database_id"].lower():
    raise ValueError("top-level database ID differs")
if "usage_d1_database_id" in payload and text(payload, "usage_d1_database_id").lower() != steward_values["d1_database_id"].lower():
    raise ValueError("usage database ID differs")
if "rollback_d1_database_id" in payload and text(payload, "rollback_d1_database_id").lower() != steward_values["rollback_d1_database_id"].lower():
    raise ValueError("top-level rollback database ID differs")
if "public_bucket_name" in payload and text(payload, "public_bucket_name") != steward_values["public_bucket_name"]:
    raise ValueError("top-level bucket name differs")
if "public_base_url" in payload and text(payload, "public_base_url") != site_values["public_base_url"]:
    raise ValueError("top-level public URL differs")

standalone = {
    "steward_d1_token": (steward_values["d1_token"], "d1_token"),
    "steward_s3_access_key_id": (steward_values["s3_access_key_id"], "s3_access_key_id"),
    "steward_s3_secret_access_key": (steward_values["s3_secret_access_key"], "s3_secret_access_key"),
    "site_d1_read_token": (site_values["d1_read_token"], "d1_read_token"),
}
for top_key, (expected, _nested_key) in standalone.items():
    if top_key in payload and text(payload, top_key) != expected:
        raise ValueError("standalone output does not match composite")

values = {
    "account_id": steward_values["account_id"].lower(),
    "d1_database_id": steward_values["d1_database_id"].lower(),
    "rollback_d1_database_id": steward_values["rollback_d1_database_id"].lower(),
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
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
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

steward_d1_database_id="$(read_field d1_database_id)"
rollback_d1_database_id="$(read_field rollback_d1_database_id)"
[[ "${steward_d1_database_id}" != "${rollback_d1_database_id}" ]] || fail "candidate and rollback database IDs must differ"

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
    {
        "type": row[0],
        "name": row[1],
        "tbl_name": row[2],
        "sql": row[3],
    }
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
    if any(not isinstance(row[key], (str, type(None))) for key in ("type", "name", "tbl_name", "sql")):
        raise ValueError("schema row has invalid values")
    return {
        "type": None if row["type"] is None else normalize_structure(row["type"]),
        "name": None if row["name"] is None else normalize_structure(row["name"]),
        "tbl_name": None if row["tbl_name"] is None else normalize_structure(row["tbl_name"]),
        "sql": None if row["sql"] is None else normalize_sql(row["sql"]),
    }


def result_rows(value: object) -> object:
    if isinstance(value, dict):
        if "success" in value and value["success"] is False:
            raise ValueError("remote query failed")
        errors = value.get("errors")
        if errors not in (None, [], {}):
            raise ValueError("remote query returned errors")
        if isinstance(value.get("results"), list):
            candidate = value["results"]
            if not candidate or all(isinstance(item, dict) and "type" in item for item in candidate):
                return candidate
            for item in candidate:
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
expected = [normalize_row(row) for row in expected]
normalized.sort(key=lambda item: (item["type"] or "", item["name"] or ""))
expected.sort(key=lambda item: (item["type"] or "", item["name"] or ""))
if not normalized:
    print("blank")
elif normalized == expected:
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
  "${wrangler_bin}" d1 execute "${steward_d1_database_id}" \
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
    [[ "${mode}" == "prepare" ]] || fail "activation requires a bootstrapped candidate D1"
    if ! "${wrangler_bin}" d1 execute "${steward_d1_database_id}" \
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
    :
    ;;
  drift)
    fail "D1 schema drift requires a separately reviewed forward migration"
    ;;
esac

validate_sample() {
  local response_path="$1"
  if ! python3 - "${response_path}" >"${temporary_dir}/sample-state.out" 2>"${temporary_dir}/sample-state.err" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

response = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(response, dict) or response.get("success") is False:
    raise ValueError("sample query failed")
if response.get("errors") not in (None, [], {}):
    raise ValueError("sample query returned errors")

envelope_private_key = re.compile(r"(?i)(?:api[_ -]?token|access[_ -]?key|password|secret|credential|private|prompt_text|raw|transcript|path|url)")
envelope_private_value = re.compile(r"(?i)(?:file://|https?://|s3://|gs://|ssh://|wss?://|/home/|/media/|/tmp/|begin private key|authorization\s*:\s*bearer)")


def scan_public_payload(value: object) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            if envelope_private_key.search(str(child_key)) and child not in (None, [], {}):
                raise ValueError("sample response contains a private field")
            scan_public_payload(child)
    elif isinstance(value, list):
        for child in value:
            scan_public_payload(child)
    elif isinstance(value, str) and envelope_private_value.search(value):
        raise ValueError("sample response contains a private value")


scan_public_payload(response)


def rows(value: object) -> list[object] | None:
    if isinstance(value, dict):
        candidate = value.get("results")
        if isinstance(candidate, list):
            if all(isinstance(item, dict) for item in candidate):
                return candidate
            for item in candidate:
                nested = rows(item)
                if nested is not None:
                    return nested
        if "result" in value:
            return rows(value["result"])
    if isinstance(value, list):
        if all(isinstance(item, dict) for item in value):
            return value
        for item in value:
            nested = rows(item)
            if nested is not None:
                return nested
    return None


items = rows(response)
MAX_SAMPLE_ROWS = 16_384
if not items or len(items) > MAX_SAMPLE_ROWS or not all(isinstance(item, dict) for item in items):
    raise ValueError("sample task evidence is missing, unbounded, or malformed")
samples = [item for item in items if isinstance(item, dict)]

token_fields = ("prompt_tokens", "cached_tokens", "uncached_tokens", "completion_tokens", "reasoning_tokens", "total_tokens")
cost_fields = ("uncached_input_cost_micro_usd", "cached_input_cost_micro_usd", "output_cost_micro_usd", "total_cost_micro_usd")
metric_groups = (
    "task_summary",
    "run_summary",
    "invocation",
    "global",
)
allowed = {
    "publication_id", "task_id", "usage_generation_id",
    "task_head_state", "usage_head_task_id", "usage_head_generation_id", "usage_head_state", "usage_generation_state",
    "generation_publication_id", "generation_task_id", "generation_ownership_class",
    "publication_generation_state", "task_lifecycle_state", "run_state",
    "run_id", "pipeline_id", "task_summary_id", "task_summary_usage_generation_id", "task_summary_publication_id", "task_summary_task_id", "task_summary_scope",
    "task_summary_run_id", "run_summary_id", "run_summary_usage_generation_id", "run_summary_publication_id", "run_summary_task_id", "run_summary_scope", "run_summary_run_id",
    "invocation_id", "invocation_publication_id", "invocation_task_id",
    "invocation_pipeline_id", "invocation_run_id", "invocation_ownership_class", "invocation_model",
    "retry_ordinal", "turn_id", "turn_usage_generation_id", "turn_invocation_id",
    "turn_publication_id", "turn_task_id", "turn_run_id", "turn_ordinal",
    "global_id", "global_usage_generation_id", "global_head_usage_generation_id", "global_head_id", "global_head_state", "global_period_kind",
    "global_period_key", "global_model", "global_ownership_class",
    "generation_expected_summary_count", "generation_expected_invocation_count",
    "generation_expected_turn_count", "generation_expected_price_count",
    "generation_expected_global_count", "run_invocation_count", "run_turn_count",
    "run_count", "summary_count", "invocation_count", "turn_count", "price_count", "global_count",
}
for group in metric_groups:
    allowed.update(f"{group}_{field}" for field in ("coverage", "known_token_subtotal", "known_cost_subtotal_micro_usd", *token_fields, *cost_fields))
    count_fields = ("covered_turns", "expected_turns") if group == "invocation" else ("covered_invocations", "expected_invocations")
    allowed.update(f"{group}_{field}" for field in count_fields)
allowed.update(f"turn_{field}" for field in (*token_fields, *cost_fields))
private_key = re.compile(r"(?i)(?:api[_ -]?token|access[_ -]?key|password|secret|credential|private|prompt_text|raw|transcript|path|url)")
private_value = re.compile(r"(?i)(?:file://|https?://|s3://|gs://|ssh://|wss?://|/home/|/media/|/tmp/|begin private key|authorization\s*:\s*bearer)")
for sample in samples:
    if set(sample) - allowed or any(private_key.search(str(key)) for key in sample if key not in allowed):
        raise ValueError("sample row contains a private or unexpected field")
    if set(sample) != allowed:
        raise ValueError("sample evidence shape is incomplete")
    if any(isinstance(value, str) and private_value.search(value) for value in sample.values()):
        raise ValueError("sample row contains a private value")


first = samples[0]


def row_text(sample: dict[str, object], name: str, *, optional: bool = False) -> str | None:
    item = sample[name]
    if item is None and optional:
        return None
    if not isinstance(item, str) or not item or any(ord(char) < 32 or ord(char) == 127 for char in item):
        raise ValueError("sample identity is invalid")
    return item


def row_integer(
    sample: dict[str, object],
    name: str,
    *,
    optional: bool = False,
    maximum: int = 9_007_199_254_740_991,
) -> int | None:
    item = sample[name]
    if item is None and optional:
        return None
    if isinstance(item, bool) or not isinstance(item, int) or item < 0 or item > maximum:
        raise ValueError("sample counter is invalid")
    return item


def same_field(name: str) -> object:
    values = {sample[name] for sample in samples}
    if len(values) != 1:
        raise ValueError("sample repeated evidence is inconsistent")
    return first[name]


def state(sample: dict[str, object], name: str, expected: str) -> None:
    if row_text(sample, name) != expected:
        raise ValueError("sample state is incoherent")


shared_fields = (
    "publication_id", "task_id", "usage_generation_id", "task_head_state",
    "usage_head_task_id", "usage_head_generation_id", "usage_head_state", "usage_generation_state",
    "generation_publication_id", "generation_task_id", "generation_ownership_class",
    "publication_generation_state", "task_lifecycle_state", "run_state", "run_id", "pipeline_id",
    "task_summary_id", "task_summary_usage_generation_id", "task_summary_publication_id",
    "task_summary_task_id", "task_summary_scope", "task_summary_run_id", "run_summary_id",
    "run_summary_usage_generation_id", "run_summary_publication_id", "run_summary_task_id",
    "run_summary_scope", "run_summary_run_id", "generation_expected_summary_count",
    "generation_expected_invocation_count", "generation_expected_turn_count",
    "generation_expected_price_count", "generation_expected_global_count", "run_invocation_count",
    "run_turn_count", "run_count", "summary_count", "invocation_count", "turn_count",
    "price_count",
)
for group in ("task_summary", "run_summary"):
    shared_fields += tuple(
        f"{group}_{field}"
        for field in ("coverage", "covered_invocations", "expected_invocations", "known_token_subtotal", "known_cost_subtotal_micro_usd", *token_fields, *cost_fields)
    )
for name in shared_fields:
    same_field(name)

publication_id = row_text(first, "publication_id")
task_id = row_text(first, "task_id")
generation_id = row_text(first, "usage_generation_id")
run_id = row_text(first, "run_id")
pipeline_id = row_text(first, "pipeline_id")
state(first, "task_head_state", "visible")
state(first, "usage_head_state", "visible")
state(first, "usage_generation_state", "visible")
state(first, "publication_generation_state", "visible")
if row_text(first, "usage_head_task_id") != task_id or row_text(first, "usage_head_generation_id") != generation_id:
    raise ValueError("sample usage head ownership is inconsistent")
if row_text(first, "generation_publication_id") != publication_id or row_text(first, "generation_task_id") != task_id:
    raise ValueError("sample generation ownership is inconsistent")
if row_text(first, "generation_ownership_class") != "task-owned":
    raise ValueError("sample generation ownership class is invalid")
if row_text(first, "task_lifecycle_state") not in {"active", "completed", "failed", "cancelled"}:
    raise ValueError("sample task state is invalid")
if row_text(first, "run_state") not in {"completed", "failed", "cancelled"}:
    raise ValueError("sample run state is invalid")
if row_text(first, "task_summary_usage_generation_id") != generation_id or row_text(first, "task_summary_publication_id") != publication_id or row_text(first, "task_summary_task_id") != task_id:
    raise ValueError("sample task summary ownership is inconsistent")
if row_text(first, "run_summary_usage_generation_id") != generation_id or row_text(first, "run_summary_publication_id") != publication_id or row_text(first, "run_summary_task_id") != task_id:
    raise ValueError("sample run summary ownership is inconsistent")
if row_text(first, "task_summary_scope") != "task" or row_text(first, "run_summary_scope") != "run":
    raise ValueError("sample summaries have invalid scopes")
if row_text(first, "task_summary_run_id", optional=True) is not None or row_text(first, "run_summary_run_id") != run_id:
    raise ValueError("sample summaries have invalid run ownership")

def validate_metrics(sample: dict[str, object], prefix: str, *, turn: bool = False) -> tuple[int | None, ...]:
    values = tuple(sample[f"{prefix}_{field}"] for field in token_fields)
    for item in values:
        if item is not None and (isinstance(item, bool) or not isinstance(item, int) or item < 0 or item > 9_007_199_254_740_991):
            raise ValueError("sample token metric is invalid")
    if all(item is not None for item in values):
        prompt, cached, uncached, completion, reasoning, total = values
        if cached > prompt or uncached != prompt - cached or reasoning > completion or total != prompt + completion:
            raise ValueError("sample token arithmetic is inconsistent")
    if turn and any(item is None for item in values):
        raise ValueError("sample turn token evidence is incomplete")
    costs = tuple(sample[f"{prefix}_{field}"] for field in cost_fields)
    for item in costs:
        if item is not None and (isinstance(item, bool) or not isinstance(item, int) or item < 0 or item > 9_007_199_254_740_991):
            raise ValueError("sample cost metric is invalid")
    if any(item is None for item in costs) and not all(item is None for item in costs):
        raise ValueError("sample cost state is mixed")
    return values


def validate_coverage(sample: dict[str, object], prefix: str, count_name: str) -> None:
    coverage = row_text(sample, f"{prefix}_coverage")
    if coverage not in {"complete", "partial", "unavailable"}:
        raise ValueError("sample coverage is invalid")
    covered_name = f"{prefix}_covered_{count_name}"
    expected_name = f"{prefix}_expected_{count_name}"
    covered = row_integer(sample, covered_name)
    expected = row_integer(sample, expected_name)
    if covered is None or expected is None or covered > expected:
        raise ValueError("sample coverage counts are invalid")
    if coverage == "complete" and covered != expected:
        raise ValueError("sample complete coverage is inconsistent")
    if coverage == "unavailable":
        if sample[f"{prefix}_known_token_subtotal"] is not None or sample[f"{prefix}_known_cost_subtotal_micro_usd"] is not None:
            raise ValueError("sample unavailable coverage has fabricated subtotals")
        if any(sample[f"{prefix}_{field}"] is not None for field in (*token_fields, *cost_fields)):
            raise ValueError("sample unavailable coverage has fabricated metrics")
    total = sample[f"{prefix}_total_tokens"]
    known_total = sample[f"{prefix}_known_token_subtotal"]
    if total is not None and known_total is not None and total != known_total:
        raise ValueError("sample token subtotal is inconsistent")
    cost = sample[f"{prefix}_total_cost_micro_usd"]
    known_cost = sample[f"{prefix}_known_cost_subtotal_micro_usd"]
    if cost is not None and known_cost is not None and cost != known_cost:
        raise ValueError("sample cost subtotal is inconsistent")


for sample in samples:
    for name in ("task_summary_id", "run_summary_id", "invocation_id", "turn_id", "global_id"):
        row_text(sample, name)
    if row_text(sample, "invocation_publication_id") != publication_id or row_text(sample, "invocation_task_id") != task_id:
        raise ValueError("sample invocation ownership is inconsistent")
    if row_text(sample, "invocation_pipeline_id") != pipeline_id or row_text(sample, "invocation_run_id") != run_id:
        raise ValueError("sample invocation run ownership is inconsistent")
    if row_text(sample, "invocation_ownership_class") != "task-owned":
        raise ValueError("sample invocation ownership class is invalid")
    if row_text(sample, "turn_usage_generation_id") != generation_id or row_text(sample, "turn_invocation_id") != row_text(sample, "invocation_id"):
        raise ValueError("sample turn ownership is inconsistent")
    if row_text(sample, "turn_publication_id") != publication_id or row_text(sample, "turn_task_id") != task_id or row_text(sample, "turn_run_id") != run_id:
        raise ValueError("sample turn run ownership is inconsistent")
    if row_text(sample, "global_usage_generation_id") != generation_id or row_text(sample, "global_ownership_class") != "task-owned":
        raise ValueError("sample global ownership is inconsistent")
    period_kind = row_text(sample, "global_period_kind")
    if period_kind not in {"lifetime", "daily"}:
        raise ValueError("sample global period is invalid")
    period_key = row_text(sample, "global_period_key")
    if period_kind == "lifetime" and period_key != "lifetime":
        raise ValueError("sample lifetime period key is invalid")
    if period_kind == "daily" and re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", period_key or "") is None:
        raise ValueError("sample daily period key is invalid")
    state(sample, "global_head_state", "visible")
    if row_text(sample, "global_head_usage_generation_id") != generation_id or row_text(sample, "global_head_id") != row_text(sample, "global_id"):
        raise ValueError("sample global head ownership is inconsistent")
    row_integer(sample, "retry_ordinal", maximum=4_096)
    turn_ordinal = row_integer(sample, "turn_ordinal", maximum=4_096)
    if turn_ordinal is None or turn_ordinal < 1:
        raise ValueError("sample turn ordinal is invalid")
    for prefix in ("task_summary", "run_summary", "invocation", "global"):
        validate_coverage(sample, prefix, "turns" if prefix == "invocation" else "invocations")
    validate_metrics(sample, prefix)
    validate_metrics(sample, "turn", turn=True)


def identity_records(prefix: str, fields: tuple[str, ...]) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for sample in samples:
        identity = row_text(sample, f"{prefix}_id")
        assert identity is not None
        if identity in records and any(records[identity][field] != sample[field] for field in fields):
            raise ValueError(f"sample {prefix} identity is contradictory")
        records.setdefault(identity, sample)
    return records


invocation_fields = (
    "invocation_publication_id", "invocation_task_id", "invocation_pipeline_id", "invocation_run_id",
    "invocation_ownership_class", "retry_ordinal", "invocation_model", "invocation_coverage",
    "invocation_covered_turns", "invocation_expected_turns", "invocation_known_token_subtotal",
    "invocation_known_cost_subtotal_micro_usd", *(f"invocation_{field}" for field in (*token_fields, *cost_fields)),
)
turn_fields = (
    "turn_usage_generation_id", "turn_invocation_id", "turn_publication_id", "turn_task_id", "turn_run_id",
    "turn_ordinal", *(f"turn_{field}" for field in (*token_fields, *cost_fields)),
)
global_fields = (
    "global_usage_generation_id", "global_head_usage_generation_id", "global_head_id", "global_head_state",
    "global_period_kind", "global_period_key", "global_model", "global_ownership_class",
    *(f"global_{field}" for field in ("coverage", "covered_invocations", "expected_invocations", "known_token_subtotal", "known_cost_subtotal_micro_usd", *token_fields, *cost_fields)),
)
invocations = identity_records("invocation", invocation_fields)
turns = identity_records("turn", turn_fields)
globals = identity_records("global", global_fields)
if len({(row["invocation_id"], row["turn_id"], row["global_id"]) for row in samples}) != len(samples):
    raise ValueError("sample evidence contains duplicate invocation, turn, and global rows")

for name, expected_name, minimum in (
    ("summary_count", "generation_expected_summary_count", 1),
    ("invocation_count", "generation_expected_invocation_count", 1),
    ("turn_count", "generation_expected_turn_count", 1),
    ("price_count", "generation_expected_price_count", 0),
    ("global_count", "generation_expected_global_count", 1),
):
    expected = row_integer(first, expected_name)
    actual = row_integer(first, name)
    if expected is None or actual is None or expected < minimum or actual != expected:
        raise ValueError("sample generation counts are inconsistent")
if row_integer(first, "invocation_count") != len(invocations) or row_integer(first, "turn_count") != len(turns) or row_integer(first, "global_count") != len(globals):
    raise ValueError("sample evidence does not cover every counted row")
if row_integer(first, "run_count") != 1 or row_integer(first, "run_invocation_count") != len(invocations) or row_integer(first, "run_turn_count") != len(turns):
    raise ValueError("sample run counts are inconsistent")
for prefix in ("task_summary", "run_summary"):
    if row_text(first, f"{prefix}_coverage") == "complete":
        if row_integer(first, f"{prefix}_covered_invocations") != len(invocations) or row_integer(first, f"{prefix}_expected_invocations") != len(invocations):
            raise ValueError("sample summary coverage is inconsistent")

turns_by_invocation: dict[str, list[dict[str, object]]] = {}
for turn in turns.values():
    turns_by_invocation.setdefault(row_text(turn, "turn_invocation_id") or "", []).append(turn)
for invocation_id, invocation in invocations.items():
    children = turns_by_invocation.get(invocation_id, [])
    covered = row_integer(invocation, "invocation_covered_turns")
    expected = row_integer(invocation, "invocation_expected_turns")
    if covered is None or expected is None or covered != len(children) or covered > expected:
        raise ValueError("sample invocation turn coverage is inconsistent")


def rollup_metrics(parent: dict[str, object], parent_prefix: str, children: list[dict[str, object]], child_prefix: str) -> None:
    if row_text(parent, f"{parent_prefix}_coverage") != "complete":
        return
    for field in (*token_fields, *cost_fields):
        values = [child[f"{child_prefix}_{field}"] for child in children]
        if not values:
            total = None
        elif all(value is None for value in values):
            total = None
        elif any(value is None for value in values):
            raise ValueError("sample complete rollup has unknown child metrics")
        else:
            total = sum(value for value in values if isinstance(value, int))
        if parent[f"{parent_prefix}_{field}"] != total:
            raise ValueError("sample usage levels disagree")


rollup_metrics(first, "task_summary", list(invocations.values()), "invocation")
rollup_metrics(first, "run_summary", list(invocations.values()), "invocation")
for invocation_id, invocation in invocations.items():
    rollup_metrics(invocation, "invocation", turns_by_invocation.get(invocation_id, []), "turn")

models = {row_text(invocation, "invocation_model") for invocation in invocations.values()}
for global_row in globals.values():
    model = row_text(global_row, "global_model")
    if model not in models:
        raise ValueError("sample global model is unrelated to selected task")
    matching = [invocation for invocation in invocations.values() if row_text(invocation, "invocation_model") == model]
    if row_text(global_row, "global_coverage") == "complete":
        expected = row_integer(global_row, "global_expected_invocations")
        if expected == len(matching):
            rollup_metrics(global_row, "global", matching, "invocation")
print("valid")
PY
  then
    return 1
  fi
  [[ "$(<"${temporary_dir}/sample-state.out")" == "valid" ]]
}

if [[ "${mode}" == "activate" ]]; then
  sample_query="SELECT
    th.publication_id AS publication_id,
    th.task_id AS task_id,
    th.usage_generation_id AS usage_generation_id,
    th.state AS task_head_state,
    uh.task_id AS usage_head_task_id,
    uh.usage_generation_id AS usage_head_generation_id,
    uh.state AS usage_head_state,
    ug.state AS usage_generation_state,
    ug.publication_id AS generation_publication_id,
    ug.task_id AS generation_task_id,
    ug.ownership_class AS generation_ownership_class,
    pg.state AS publication_generation_state,
    t.lifecycle_state AS task_lifecycle_state,
    r.run_state AS run_state,
    r.run_id AS run_id,
    r.pipeline_id AS pipeline_id,
    ts.summary_id AS task_summary_id,
    ts.usage_generation_id AS task_summary_usage_generation_id,
    ts.publication_id AS task_summary_publication_id,
    ts.task_id AS task_summary_task_id,
    ts.scope AS task_summary_scope,
    ts.run_id AS task_summary_run_id,
    ts.coverage AS task_summary_coverage,
    ts.covered_invocations AS task_summary_covered_invocations,
    ts.expected_invocations AS task_summary_expected_invocations,
    ts.known_token_subtotal AS task_summary_known_token_subtotal,
    ts.known_cost_subtotal_micro_usd AS task_summary_known_cost_subtotal_micro_usd,
    ts.prompt_tokens AS task_summary_prompt_tokens,
    ts.cached_tokens AS task_summary_cached_tokens,
    ts.uncached_tokens AS task_summary_uncached_tokens,
    ts.completion_tokens AS task_summary_completion_tokens,
    ts.reasoning_tokens AS task_summary_reasoning_tokens,
    ts.total_tokens AS task_summary_total_tokens,
    ts.uncached_input_cost_micro_usd AS task_summary_uncached_input_cost_micro_usd,
    ts.cached_input_cost_micro_usd AS task_summary_cached_input_cost_micro_usd,
    ts.output_cost_micro_usd AS task_summary_output_cost_micro_usd,
    ts.total_cost_micro_usd AS task_summary_total_cost_micro_usd,
    rs.summary_id AS run_summary_id,
    rs.usage_generation_id AS run_summary_usage_generation_id,
    rs.publication_id AS run_summary_publication_id,
    rs.task_id AS run_summary_task_id,
    rs.scope AS run_summary_scope,
    rs.run_id AS run_summary_run_id,
    rs.coverage AS run_summary_coverage,
    rs.covered_invocations AS run_summary_covered_invocations,
    rs.expected_invocations AS run_summary_expected_invocations,
    rs.known_token_subtotal AS run_summary_known_token_subtotal,
    rs.known_cost_subtotal_micro_usd AS run_summary_known_cost_subtotal_micro_usd,
    rs.prompt_tokens AS run_summary_prompt_tokens,
    rs.cached_tokens AS run_summary_cached_tokens,
    rs.uncached_tokens AS run_summary_uncached_tokens,
    rs.completion_tokens AS run_summary_completion_tokens,
    rs.reasoning_tokens AS run_summary_reasoning_tokens,
    rs.total_tokens AS run_summary_total_tokens,
    rs.uncached_input_cost_micro_usd AS run_summary_uncached_input_cost_micro_usd,
    rs.cached_input_cost_micro_usd AS run_summary_cached_input_cost_micro_usd,
    rs.output_cost_micro_usd AS run_summary_output_cost_micro_usd,
    rs.total_cost_micro_usd AS run_summary_total_cost_micro_usd,
    i.invocation_id AS invocation_id,
    i.publication_id AS invocation_publication_id,
    i.task_id AS invocation_task_id,
    i.pipeline_id AS invocation_pipeline_id,
    i.run_id AS invocation_run_id,
    i.ownership_class AS invocation_ownership_class,
    i.retry_ordinal AS retry_ordinal,
    i.model AS invocation_model,
    i.coverage AS invocation_coverage,
    i.covered_turns AS invocation_covered_turns,
    i.expected_turns AS invocation_expected_turns,
    NULL AS invocation_known_token_subtotal,
    NULL AS invocation_known_cost_subtotal_micro_usd,
    i.prompt_tokens AS invocation_prompt_tokens,
    i.cached_tokens AS invocation_cached_tokens,
    i.uncached_tokens AS invocation_uncached_tokens,
    i.completion_tokens AS invocation_completion_tokens,
    i.reasoning_tokens AS invocation_reasoning_tokens,
    i.total_tokens AS invocation_total_tokens,
    i.uncached_input_cost_micro_usd AS invocation_uncached_input_cost_micro_usd,
    i.cached_input_cost_micro_usd AS invocation_cached_input_cost_micro_usd,
    i.output_cost_micro_usd AS invocation_output_cost_micro_usd,
    i.total_cost_micro_usd AS invocation_total_cost_micro_usd,
    u.turn_id AS turn_id,
    u.usage_generation_id AS turn_usage_generation_id,
    u.invocation_id AS turn_invocation_id,
    u.publication_id AS turn_publication_id,
    u.task_id AS turn_task_id,
    u.run_id AS turn_run_id,
    u.ordinal AS turn_ordinal,
    u.prompt_tokens AS turn_prompt_tokens,
    u.cached_tokens AS turn_cached_tokens,
    u.uncached_tokens AS turn_uncached_tokens,
    u.completion_tokens AS turn_completion_tokens,
    u.reasoning_tokens AS turn_reasoning_tokens,
    u.total_tokens AS turn_total_tokens,
    u.uncached_input_cost_micro_usd AS turn_uncached_input_cost_micro_usd,
    u.cached_input_cost_micro_usd AS turn_cached_input_cost_micro_usd,
    u.output_cost_micro_usd AS turn_output_cost_micro_usd,
    u.total_cost_micro_usd AS turn_total_cost_micro_usd,
    g.global_id AS global_id,
    g.usage_generation_id AS global_usage_generation_id,
    gh.usage_generation_id AS global_head_usage_generation_id,
    gh.global_id AS global_head_id,
    gh.state AS global_head_state,
    g.period_kind AS global_period_kind,
    g.period_key AS global_period_key,
    g.model AS global_model,
    g.ownership_class AS global_ownership_class,
    g.coverage AS global_coverage,
    g.covered_invocations AS global_covered_invocations,
    g.expected_invocations AS global_expected_invocations,
    g.known_token_subtotal AS global_known_token_subtotal,
    g.known_cost_subtotal_micro_usd AS global_known_cost_subtotal_micro_usd,
    g.prompt_tokens AS global_prompt_tokens,
    g.cached_tokens AS global_cached_tokens,
    g.uncached_tokens AS global_uncached_tokens,
    g.completion_tokens AS global_completion_tokens,
    g.reasoning_tokens AS global_reasoning_tokens,
    g.total_tokens AS global_total_tokens,
    g.uncached_input_cost_micro_usd AS global_uncached_input_cost_micro_usd,
    g.cached_input_cost_micro_usd AS global_cached_input_cost_micro_usd,
    g.output_cost_micro_usd AS global_output_cost_micro_usd,
    g.total_cost_micro_usd AS global_total_cost_micro_usd,
    ug.expected_summary_count AS generation_expected_summary_count,
    ug.expected_invocation_count AS generation_expected_invocation_count,
    ug.expected_turn_count AS generation_expected_turn_count,
    ug.expected_price_count AS generation_expected_price_count,
    ug.expected_global_count AS generation_expected_global_count,
    (SELECT count(*) FROM runs AS rc WHERE rc.publication_id = th.publication_id AND rc.task_id = th.task_id) AS run_count,
    (SELECT count(*) FROM usage_summaries AS sc WHERE sc.usage_generation_id = ug.usage_generation_id AND sc.publication_id = th.publication_id AND sc.task_id = th.task_id) AS summary_count,
    (SELECT count(*) FROM usage_invocations AS ic WHERE ic.usage_generation_id = ug.usage_generation_id AND ic.task_id = th.task_id AND ic.ownership_class = 'task-owned') AS invocation_count,
    (SELECT count(*) FROM usage_turns AS uc WHERE uc.usage_generation_id = ug.usage_generation_id AND uc.task_id = th.task_id) AS turn_count,
    (SELECT count(*) FROM usage_prices AS pc WHERE pc.usage_generation_id = ug.usage_generation_id) AS price_count,
    (SELECT count(*) FROM usage_globals AS gc WHERE gc.usage_generation_id = ug.usage_generation_id AND gc.ownership_class = 'task-owned') AS global_count,
    (SELECT count(*) FROM usage_invocations AS ric WHERE ric.usage_generation_id = ug.usage_generation_id AND ric.task_id = th.task_id AND ric.run_id = r.run_id AND ric.ownership_class = 'task-owned') AS run_invocation_count,
    (SELECT count(*) FROM usage_turns AS rtc WHERE rtc.usage_generation_id = ug.usage_generation_id AND rtc.task_id = th.task_id AND rtc.run_id = r.run_id) AS run_turn_count
  FROM task_heads AS th
  JOIN publication_generations AS pg
    ON pg.publication_id = th.publication_id
   AND pg.task_id = th.task_id
   AND pg.state = 'visible'
  JOIN tasks AS t
    ON t.publication_id = pg.publication_id
   AND t.task_id = pg.task_id
  JOIN usage_heads AS uh
    ON uh.task_id = th.task_id
   AND uh.usage_generation_id = th.usage_generation_id
   AND uh.state = 'visible'
  JOIN usage_generations AS ug
    ON ug.usage_generation_id = uh.usage_generation_id
   AND ug.publication_id = pg.publication_id
   AND ug.task_id = pg.task_id
   AND ug.ownership_class = 'task-owned'
   AND ug.state = 'visible'
  JOIN runs AS r
    ON r.publication_id = pg.publication_id
   AND r.task_id = pg.task_id
  JOIN usage_summaries AS ts
    ON ts.usage_generation_id = ug.usage_generation_id
   AND ts.publication_id = pg.publication_id
   AND ts.task_id = pg.task_id
   AND ts.scope = 'task'
   AND ts.run_id IS NULL
  JOIN usage_summaries AS rs
    ON rs.usage_generation_id = ug.usage_generation_id
   AND rs.publication_id = pg.publication_id
   AND rs.task_id = pg.task_id
   AND rs.scope = 'run'
   AND rs.run_id = r.run_id
  JOIN usage_invocations AS i
    ON i.usage_generation_id = ug.usage_generation_id
   AND i.publication_id = pg.publication_id
   AND i.task_id = pg.task_id
   AND i.pipeline_id = r.pipeline_id
   AND i.run_id = r.run_id
   AND i.ownership_class = 'task-owned'
  JOIN usage_turns AS u
    ON u.usage_generation_id = i.usage_generation_id
   AND u.invocation_id = i.invocation_id
   AND u.publication_id = i.publication_id
   AND u.task_id = i.task_id
   AND u.run_id = i.run_id
  JOIN usage_globals AS g
    ON g.usage_generation_id = ug.usage_generation_id
    AND g.ownership_class = 'task-owned'
  JOIN usage_global_heads AS gh
    ON gh.global_id = g.global_id
   AND gh.usage_generation_id = g.usage_generation_id
   AND gh.period_kind = g.period_kind
   AND gh.period_key = g.period_key
   AND gh.model = g.model
   AND gh.ownership_class = g.ownership_class
   AND gh.state = 'visible'
  WHERE th.state = 'visible'
  ORDER BY r.run_id, i.retry_ordinal, i.invocation_id, u.ordinal, g.period_kind, g.period_key, g.model
  LIMIT 16385"
  if ! "${wrangler_bin}" d1 execute "${steward_d1_database_id}" \
    --remote \
    --command "${sample_query}" \
    --json \
    >"${temporary_dir}/sample.json" 2>"${temporary_dir}/wrangler-sample.err"; then
    fail "candidate usage sample query failed"
  fi
  validate_sample "${temporary_dir}/sample.json" || fail "candidate usage sample is missing or invalid"
fi

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
  local stage="${credentials_dir}/.coquic-steward-rollout.$$"
  local -a names=(d1-read-token r2-access-key-id r2-secret-access-key)
  local -a old_names=()
  local -a installed_names=()
  local name destination value
  mkdir -m 700 -- "${stage}" || fail "unable to create credential staging directory"

  rollback_credentials() {
    local rollback_name rollback_destination
    set +e
    for rollback_name in "${installed_names[@]}"; do
      rollback_destination="${credentials_dir}/${rollback_name}"
      rm -f -- "${rollback_destination}"
    done
    for rollback_name in "${old_names[@]}"; do
      if [[ -f "${stage}/old-${rollback_name}" ]]; then
        mv -f -- "${stage}/old-${rollback_name}" "${credentials_dir}/${rollback_name}"
      fi
    done
    rm -rf -- "${stage}"
    set -e
  }

  for name in "${names[@]}"; do
    destination="${credentials_dir}/${name}"
    if [[ -L "${destination}" ]]; then
      rollback_credentials
      fail "credential target must not be a symlink"
    fi
    if [[ -e "${destination}" ]]; then
      [[ -f "${destination}" ]] || { rollback_credentials; fail "credential target must be a regular file"; }
      [[ "$(stat -c '%u' -- "${destination}")" == "$(id -u)" ]] || { rollback_credentials; fail "credential target is not owned by the invoking user"; }
      mv -- "${destination}" "${stage}/old-${name}" || { rollback_credentials; fail "unable to stage existing credential"; }
      old_names+=("${name}")
    fi
    case "${name}" in
      d1-read-token)
        if ! value="$(read_field d1_token)"; then
          rollback_credentials
          fail "validated D1 credential is missing"
        fi
        ;;
      r2-access-key-id)
        if ! value="$(read_field s3_access_key_id)"; then
          rollback_credentials
          fail "validated R2 access credential is missing"
        fi
        ;;
      r2-secret-access-key)
        if ! value="$(read_field s3_secret_access_key)"; then
          rollback_credentials
          fail "validated R2 secret credential is missing"
        fi
        ;;
    esac
    if ! printf '%s\n' "${value}" >"${stage}/new-${name}"; then
      rollback_credentials
      fail "unable to stage credential files"
    fi
    if ! chmod 600 -- "${stage}/new-${name}"; then
      rollback_credentials
      fail "unable to secure staged credential files"
    fi
  done

  for name in "${names[@]}"; do
    mv -f -- "${stage}/new-${name}" "${credentials_dir}/${name}" || { rollback_credentials; fail "unable to install credential files"; }
    installed_names+=("${name}")
  done
  for name in "${names[@]}"; do
    destination="${credentials_dir}/${name}"
    [[ -f "${destination}" && ! -L "${destination}" ]] || { rollback_credentials; fail "installed credential is not a regular file"; }
    [[ "$(stat -c '%u' -- "${destination}")" == "$(id -u)" && "$(stat -c '%a' -- "${destination}")" == "600" ]] || { rollback_credentials; fail "installed credential has unsafe ownership or mode"; }
  done
  rm -rf -- "${stage}"
}

if [[ "${mode}" == "prepare" ]]; then
  install_steward_credentials
  printf 'producer gate prepared: candidate D1 verified and Steward credentials installed; Site remains unchanged\n'
  exit 0
fi

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
  fail "Site cloud configuration handoff failed; cloud, D1, and Steward credentials remain"
fi

printf 'cloud rollout activated: candidate D1 verified, usage sample accepted, Site handoff completed\n'
