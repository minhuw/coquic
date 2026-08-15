from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import textwrap
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "infra/cloudflare/scripts/deploy-production.sh"
SCHEMA = ROOT / "contracts/steward-cloud/d1.sql"


PULUMI_FAKE = r'''#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import sys


args = sys.argv[1:]
log = Path(os.environ["COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"command": "pulumi", "argv": args}) + "\n")

case = os.environ.get("PULUMI_CASE", "ok")
if args[:1] == ["whoami"]:
    if case == "auth-failure":
        raise SystemExit(1)
    print("operator@pulumi.example")
    raise SystemExit(0)
if args[:1] == ["preview"]:
    if case == "preview-failure":
        print("provider output is hidden", file=sys.stderr)
        raise SystemExit(1)
    plan = Path(args[args.index("--save-plan") + 1])
    plan.write_text("saved-plan", encoding="utf-8")
    resources = [
        ("cloudflare:index/d1Database:D1Database", "publicationDatabase"),
        ("cloudflare:index/r2Bucket:R2Bucket", "publicArtifacts"),
        ("cloudflare:index/r2Bucket:R2Bucket", "privateOriginals"),
        ("cloudflare:index/r2CustomDomain:R2CustomDomain", "publicArtifactsDomain"),
        ("cloudflare:index/r2BucketLifecycle:R2BucketLifecycle", "privateOriginalsLifecycle"),
        ("cloudflare:index/accountToken:AccountToken", "stewardPublicationToken"),
        ("cloudflare:index/accountToken:AccountToken", "siteReaderToken"),
    ]
    if case == "malformed-preview":
        print("not structured JSON")
    elif case == "update":
        print(json.dumps({"op": "update", "type": resources[0][0], "name": resources[0][1]}))
    elif case == "destructive":
        print(json.dumps({"op": "delete", "type": resources[0][0], "name": resources[0][1]}))
    elif case == "unexpected":
        resources.append(("cloudflare:index/r2Bucket:R2Bucket", "unexpectedBucket"))
        for resource_type, name in resources:
            print(json.dumps({"op": "same", "type": resource_type, "name": name}))
    elif case == "secret-preview":
        print(json.dumps({"op": "same", "type": resources[0][0], "name": resources[0][1], "output": "fixture-secret"}))
    else:
        operation = "create" if case == "ok" else "same"
        for resource_type, name in resources:
            resource_operation = operation if name == "publicationDatabase" else "same"
            print(json.dumps({
                "resourcePreEvent": {
                    "metadata": {
                        "op": resource_operation,
                        "type": resource_type,
                        "name": name,
                        "urn": f"urn:pulumi:production::coquic-cloudflare::{resource_type}::{name}",
                    }
                }
            }))
    raise SystemExit(0)
if args[:1] == ["up"]:
    plan = Path(args[args.index("--plan") + 1])
    Path(os.environ["PULUMI_UP_PLAN"]).write_text(
        plan.read_text(encoding="utf-8"), encoding="utf-8"
    )
    Path(os.environ["PULUMI_APPLIED"]).write_text("yes", encoding="utf-8")
    if case == "apply-failure":
        print("apply output is hidden", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(0)
if args[:2] == ["stack", "output"]:
    if case == "output-failure":
        raise SystemExit(1)
    print(Path(os.environ["OUTPUTS"]).read_text(encoding="utf-8"), end="")
    raise SystemExit(0)
raise SystemExit(2)
'''


WRANGLER_FAKE = r'''#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import sys


args = sys.argv[1:]
log = Path(os.environ["COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"command": "wrangler", "argv": args}) + "\n")

if args[:2] != ["d1", "execute"]:
    raise SystemExit(2)
case = os.environ.get("WRANGLER_CASE", "exact")
if "--file" in args:
    if case == "bootstrap-failure":
        raise SystemExit(1)
    Path(os.environ["WRANGLER_BOOTSTRAPPED"]).write_text("yes", encoding="utf-8")
    raise SystemExit(0)
if "--command" not in args:
    raise SystemExit(2)
if case == "query-failure":
    raise SystemExit(1)
if case == "malformed":
    print("not-json")
    raise SystemExit(0)
if case == "drift":
    print(json.dumps({"success": True, "results": [{
        "type": "table",
        "name": "wrong",
        "tbl_name": "wrong",
        "sql": "CREATE TABLE wrong (id INTEGER)",
    }]}))
    raise SystemExit(0)
if case in {"blank", "bootstrap-failure"} and not Path(os.environ["WRANGLER_BOOTSTRAPPED"]).exists():
    print(json.dumps({"success": True, "results": []}))
    raise SystemExit(0)
rows_key = "SCHEMA_ROWS_POPULATED" if case == "exact-populated" else "SCHEMA_ROWS"
print(Path(os.environ[rows_key]).read_text(encoding="utf-8"), end="")
raise SystemExit(0)
'''


SITE_FAKE = r'''#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys


args = sys.argv[1:]
log = Path(os.environ["COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write("site " + " ".join(args) + "\n")
if len(args) != 1:
    raise SystemExit(2)
if "CLOUDFLARE_API_TOKEN" in os.environ or "PULUMI_ACCESS_TOKEN" in os.environ:
    raise SystemExit(3)
shutil.copyfile(args[0], os.environ["SITE_INPUT"])
if os.environ.get("SITE_CASE") == "failure":
    print("handoff output is hidden", file=sys.stderr)
    raise SystemExit(1)
raise SystemExit(0)
'''


ID_FAKE = r'''#!/usr/bin/env python3
import os
import sys


if sys.argv[1:] == ["-u"]:
    uid = os.getuid()
    print(uid + 1 if os.environ.get("OWNER_CASE") == "foreign" else uid)
    raise SystemExit(0)
raise SystemExit(2)
'''


MV_FAKE = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys


args = sys.argv[1:]
if os.environ.get("MV_CASE") == "fail-second-install" and any(
    Path(arg).name == "new-r2-access-key-id" for arg in args
):
    raise SystemExit(1)
real_mv = os.environ["REAL_MV"]
os.execv(real_mv, [real_mv, *args])
'''


def _write_executable(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    path.chmod(0o700)


def _schema_rows(path: Path, *, populated: bool = False) -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA.read_text(encoding="utf-8"))
        if populated:
            connection.execute(
                """
                INSERT INTO publication_generations (
                    publication_id, task_id, run_id, metadata_digest,
                    idempotency_key, state, expected_task_count,
                    expected_pipeline_count, expected_run_count,
                    expected_event_count, expected_artifact_count, created_at
                ) VALUES (?, ?, ?, ?, ?, 'staged', 0, 0, 0, 0, 0, ?)
                """,
                (
                    "publication-1",
                    "task-1",
                    "run-1",
                    "a" * 64,
                    "key-1",
                    "2026-08-01T00:00:00Z",
                ),
            )
        rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
    finally:
        connection.close()

    schema_rows = [
        {"type": row[0], "name": row[1], "tbl_name": row[2], "sql": row[3]}
        for row in rows
    ]
    path.write_text(
        json.dumps({"success": True, "results": schema_rows}), encoding="utf-8"
    )


def _outputs() -> tuple[dict[str, Any], dict[str, str]]:
    account = "a" * 32
    database = "12345678-1234-4abc-8def-1234567890ab"
    values = {
        "d1_token": "steward-" + "x" * 20,
        "s3_access_key_id": "access-" + "y" * 20,
        "s3_secret_access_key": "e" * 64,
        "d1_read_token": "site-" + "q" * 20,
    }
    steward = {
        "account_id": account,
        "d1_database_id": database,
        "d1_token": values["d1_token"],
        "public_bucket_name": "coquic-public-artifacts",
        "private_bucket_name": "coquic-private-originals",
        "s3_access_key_id": values["s3_access_key_id"],
        "s3_secret_access_key": values["s3_secret_access_key"],
    }
    site = {
        "account_id": account,
        "d1_database_id": database,
        "d1_read_token": values["d1_read_token"],
        "public_base_url": "https://artifacts.coquic.minhuw.dev",
    }
    payload = {
        "d1_database_id": database,
        "public_bucket_name": steward["public_bucket_name"],
        "public_base_url": site["public_base_url"],
        "steward_config": steward,
        "site_config": site,
        "steward_d1_token": values["d1_token"],
        "steward_s3_access_key_id": values["s3_access_key_id"],
        "steward_s3_secret_access_key": values["s3_secret_access_key"],
        "site_d1_read_token": values["d1_read_token"],
    }
    return payload, values


@pytest.fixture
def harness(tmp_path: Path) -> dict[str, Any]:
    fake_dir = tmp_path / "fake-bin"
    fake_dir.mkdir(mode=0o700)
    pulumi = fake_dir / "pulumi"
    wrangler = fake_dir / "wrangler"
    site = fake_dir / "site-installer"
    fake_id = fake_dir / "id"
    fake_mv = fake_dir / "mv"
    _write_executable(pulumi, PULUMI_FAKE)
    _write_executable(wrangler, WRANGLER_FAKE)
    _write_executable(site, SITE_FAKE)
    _write_executable(fake_id, ID_FAKE)
    _write_executable(fake_mv, MV_FAKE)

    outputs, values = _outputs()
    outputs_path = tmp_path / "outputs.json"
    outputs_path.write_text(json.dumps(outputs), encoding="utf-8")
    rows_path = tmp_path / "schema.json"
    _schema_rows(rows_path)
    populated_rows_path = tmp_path / "schema-populated.json"
    _schema_rows(populated_rows_path, populated=True)
    command_log = tmp_path / "commands.jsonl"
    applied = tmp_path / "pulumi-applied"
    bootstrapped = tmp_path / "wrangler-bootstrapped"
    site_input = tmp_path / "site-input"
    credentials = tmp_path / "credentials"
    credentials.mkdir(mode=0o700)
    plan_dir = tmp_path / "reviewed-plans"
    plan_dir.mkdir(mode=0o700)
    up_plan = tmp_path / "pulumi-up-plan"
    real_mv = shutil.which("mv")
    assert real_mv is not None
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_dir}:{env['PATH']}",
            "PULUMI_BIN": str(pulumi),
            "WRANGLER_BIN": str(wrangler),
            "COQUIC_SITE_INSTALLER": str(site),
            "CLOUDFLARE_API_TOKEN": "bootstrap-" + "b" * 24,
            "COMMAND_LOG": str(command_log),
            "OUTPUTS": str(outputs_path),
            "SCHEMA_ROWS": str(rows_path),
            "SCHEMA_ROWS_POPULATED": str(populated_rows_path),
            "PULUMI_APPLIED": str(applied),
            "PULUMI_UP_PLAN": str(up_plan),
            "WRANGLER_BOOTSTRAPPED": str(bootstrapped),
            "COQUIC_CLOUDFLARE_PLAN_DIR": str(plan_dir),
            "SITE_INPUT": str(site_input),
            "PULUMI_CASE": "ok",
            "WRANGLER_CASE": "exact",
            "SITE_CASE": "ok",
            "OWNER_CASE": "owned",
            "MV_CASE": "ok",
            "REAL_MV": real_mv,
        }
    )
    return {
        "tmp": tmp_path,
        "env": env,
        "credentials": credentials,
        "outputs_path": outputs_path,
        "command_log": command_log,
        "applied": applied,
        "bootstrapped": bootstrapped,
        "site_input": site_input,
        "plan_dir": plan_dir,
        "up_plan": up_plan,
        "values": values,
    }


def _run(harness: dict[str, Any], *extra: str, apply: bool = False) -> subprocess.CompletedProcess[str]:
    args = [
        "--stack",
        "production",
        "--credentials-dir",
        str(harness["credentials"]),
        "--plan-dir",
        str(harness["plan_dir"]),
    ]
    if apply:
        args.append("--apply")
    args.extend(extra)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=ROOT,
        env=harness["env"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _reviewed_apply(harness: dict[str, Any], *extra: str) -> subprocess.CompletedProcess[str]:
    preview = _run(harness)
    assert preview.returncode == 0, preview.stderr
    return _run(harness, *extra, apply=True)


def _logs(harness: dict[str, Any]) -> list[dict[str, Any] | str]:
    if not harness["command_log"].exists():
        return []
    result: list[dict[str, Any] | str] = []
    for line in harness["command_log"].read_text(encoding="utf-8").splitlines():
        if line.startswith("site "):
            result.append(line)
        else:
            result.append(json.loads(line))
    return result


def _argv(logs: list[dict[str, Any] | str], command: str) -> list[list[str]]:
    return [
        entry["argv"]
        for entry in logs
        if isinstance(entry, dict) and entry["command"] == command
    ]


def test_help_describes_preview_and_apply() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    text = result.stdout + result.stderr
    assert "Preview is read-only" in text
    assert "--apply" in text


def test_default_preview_is_read_only(harness: dict[str, Any]) -> None:
    result = _run(harness)
    assert result.returncode == 0, result.stderr
    assert "preview accepted" in result.stdout
    assert "no changes applied" in result.stdout
    assert not harness["applied"].exists()
    assert not any(harness["credentials"].iterdir())
    reviewed_plan = harness["plan_dir"] / "production.plan"
    review_record = harness["plan_dir"] / "production.review.json"
    assert reviewed_plan.is_file()
    assert review_record.is_file()
    assert stat.S_IMODE(reviewed_plan.stat().st_mode) == 0o400
    assert stat.S_IMODE(review_record.stat().st_mode) == 0o400
    assert stat.S_IMODE(harness["plan_dir"].stat().st_mode) == 0o700
    logs = _logs(harness)
    pulumi = _argv(logs, "pulumi")
    assert [argv[0] for argv in pulumi] == ["whoami", "preview"]
    preview = pulumi[1]
    assert preview[preview.index("--stack") + 1] == "production"
    assert "--save-plan" in preview
    assert _argv(logs, "wrangler") == []
    assert all(isinstance(entry, dict) for entry in logs)
    assert "bootstrap-" not in result.stdout + result.stderr


def test_apply_requires_a_prior_reviewed_plan(harness: dict[str, Any]) -> None:
    result = _run(harness, apply=True)
    assert result.returncode != 0
    assert "reviewed Pulumi plan" in result.stderr
    assert not harness["applied"].exists()
    assert _argv(_logs(harness), "pulumi") == []


def test_apply_consumes_reviewed_plan_without_a_new_preview(
    harness: dict[str, Any],
) -> None:
    preview = _run(harness)
    assert preview.returncode == 0, preview.stderr
    harness["env"]["PULUMI_CASE"] = "update"
    result = _run(harness, apply=True)
    assert result.returncode == 0, result.stderr
    pulumi = _argv(_logs(harness), "pulumi")
    assert [argv[0] for argv in pulumi] == [
        "whoami",
        "preview",
        "whoami",
        "up",
        "stack",
    ]
    assert harness["up_plan"].read_text(encoding="utf-8") == "saved-plan"
    assert not (harness["plan_dir"] / "production.plan").exists()
    assert not (harness["plan_dir"] / "production.review.json").exists()


def test_apply_rejects_a_changed_reviewed_plan(harness: dict[str, Any]) -> None:
    preview = _run(harness)
    assert preview.returncode == 0, preview.stderr
    reviewed_plan = harness["plan_dir"] / "production.plan"
    reviewed_plan.chmod(0o600)
    reviewed_plan.write_text("tampered-plan", encoding="utf-8")
    reviewed_plan.chmod(0o400)
    result = _run(harness, apply=True)
    assert result.returncode != 0
    assert "digest" in result.stderr
    assert not harness["applied"].exists()
    assert all(argv[0] != "up" for argv in _argv(_logs(harness), "pulumi"))


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("update", "safe structured plan"),
        ("destructive", "safe structured plan"),
        ("malformed-preview", "safe structured plan"),
        ("unexpected", "safe structured plan"),
    ],
)
def test_preview_rejects_unsafe_or_unreliable_plans(
    harness: dict[str, Any], case: str, message: str
) -> None:
    harness["env"]["PULUMI_CASE"] = case
    result = _run(harness)
    assert result.returncode != 0
    assert message in result.stderr
    assert not harness["applied"].exists()
    assert _argv(_logs(harness), "wrangler") == []


def test_preview_rejects_secret_shaped_data_without_leaking_it(
    harness: dict[str, Any],
) -> None:
    harness["env"]["PULUMI_CASE"] = "secret-preview"
    result = _run(harness)
    assert result.returncode != 0
    assert "fixture-secret" not in result.stdout + result.stderr
    assert not harness["applied"].exists()
    assert _argv(_logs(harness), "wrangler") == []


def test_wrong_stack_and_missing_auth_are_rejected(harness: dict[str, Any]) -> None:
    wrong = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--stack",
            "staging",
            "--credentials-dir",
            str(harness["credentials"]),
        ],
        cwd=ROOT,
        env=harness["env"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert wrong.returncode != 0
    assert "production" in wrong.stderr
    no_auth_env = harness["env"].copy()
    no_auth_env.pop("CLOUDFLARE_API_TOKEN")
    no_auth = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--stack",
            "production",
            "--credentials-dir",
            str(harness["credentials"]),
        ],
        cwd=ROOT,
        env=no_auth_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert no_auth.returncode != 0
    assert "API_TOKEN" in no_auth.stderr


def test_apply_bootstraps_schema_installs_credentials_and_hands_site(
    harness: dict[str, Any],
) -> None:
    harness["env"]["WRANGLER_CASE"] = "blank"
    result = _reviewed_apply(harness)
    assert result.returncode == 0, result.stderr
    assert "cloud bootstrap complete" in result.stdout
    assert harness["applied"].exists()
    assert harness["bootstrapped"].exists()
    values = harness["values"]
    expected_files = {
        "d1-read-token": values["d1_token"],
        "r2-access-key-id": values["s3_access_key_id"],
        "r2-secret-access-key": values["s3_secret_access_key"],
    }
    assert stat.S_IMODE(harness["credentials"].stat().st_mode) == 0o700
    for name, value in expected_files.items():
        path = harness["credentials"] / name
        assert path.read_text(encoding="utf-8") == value + "\n"
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    site_lines = harness["site_input"].read_text(encoding="utf-8").splitlines()
    assert [line.split("=", 1)[0] for line in site_lines] == [
        "CLOUDFLARE_ACCOUNT_ID",
        "COQUIC_STEWARD_D1_DATABASE_ID",
        "COQUIC_STEWARD_D1_READ_TOKEN",
        "COQUIC_STEWARD_PUBLIC_R2_BASE_URL",
    ]
    assert harness["values"]["d1_read_token"] in site_lines[2]
    wrangler = _argv(_logs(harness), "wrangler")
    assert any("--file" in argv for argv in wrangler)
    assert len([argv for argv in wrangler if "--command" in argv]) == 2
    joined = " ".join(json.dumps(entry) for entry in _logs(harness))
    assert "bootstrap-" not in joined


@pytest.mark.parametrize("case", ["exact", "exact-populated"])
def test_exact_schema_and_empty_data_are_accepted(
    harness: dict[str, Any], case: str
) -> None:
    harness["env"]["WRANGLER_CASE"] = case
    result = _reviewed_apply(harness)
    assert result.returncode == 0, result.stderr
    wrangler = _argv(_logs(harness), "wrangler")
    assert len(wrangler) == 1
    assert "--command" in wrangler[0]
    assert "--file" not in wrangler[0]
    assert harness["site_input"].exists()


@pytest.mark.parametrize("case", ["drift", "malformed", "query-failure"])
def test_schema_failure_stops_before_host_mutation(
    harness: dict[str, Any], case: str
) -> None:
    harness["env"]["WRANGLER_CASE"] = case
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert harness["applied"].exists()
    assert not any(harness["credentials"].iterdir())
    assert not harness["site_input"].exists()


def test_pulumi_apply_failure_stops_before_d1_or_files(harness: dict[str, Any]) -> None:
    harness["env"]["PULUMI_CASE"] = "apply-failure"
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "D1" in result.stderr
    assert _argv(_logs(harness), "wrangler") == []
    assert not any(harness["credentials"].iterdir())


def test_bootstrap_failure_preserves_host_state(harness: dict[str, Any]) -> None:
    harness["env"]["WRANGLER_CASE"] = "bootstrap-failure"
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "bootstrap failed" in result.stderr
    assert not any(harness["credentials"].iterdir())
    assert not harness["site_input"].exists()


def test_output_allowlist_rejects_extra_value_without_leaking_it(
    harness: dict[str, Any],
) -> None:
    payload = json.loads(harness["outputs_path"].read_text(encoding="utf-8"))
    canary = "canary-" + "c" * 24
    payload["unexpected"] = canary
    harness["outputs_path"].write_text(json.dumps(payload), encoding="utf-8")
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "allowlist" in result.stderr
    assert canary not in result.stdout + result.stderr
    assert _argv(_logs(harness), "wrangler") == []


def test_site_failure_leaves_installed_credentials_for_retry(
    harness: dict[str, Any],
) -> None:
    harness["env"]["SITE_CASE"] = "failure"
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "handoff failed" in result.stderr
    assert (harness["credentials"] / "d1-read-token").exists()
    assert (harness["credentials"] / "r2-access-key-id").exists()
    assert (harness["credentials"] / "r2-secret-access-key").exists()
    assert "handoff output" not in result.stdout + result.stderr


def test_rerun_replaces_existing_private_files(harness: dict[str, Any]) -> None:
    first = _reviewed_apply(harness)
    assert first.returncode == 0, first.stderr
    old = (harness["credentials"] / "d1-read-token").read_text(encoding="utf-8")
    outputs = json.loads(harness["outputs_path"].read_text(encoding="utf-8"))
    outputs["steward_config"]["d1_token"] = "replacement-" + "r" * 20
    outputs["steward_d1_token"] = outputs["steward_config"]["d1_token"]
    harness["outputs_path"].write_text(json.dumps(outputs), encoding="utf-8")
    second = _reviewed_apply(harness)
    assert second.returncode == 0, second.stderr
    assert (harness["credentials"] / "d1-read-token").read_text(encoding="utf-8") != old
    assert stat.S_IMODE((harness["credentials"] / "d1-read-token").stat().st_mode) == 0o600


@pytest.mark.parametrize("mode", [0o755, 0o750])
def test_existing_credential_directory_must_be_private(
    harness: dict[str, Any], mode: int
) -> None:
    harness["credentials"].chmod(mode)
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "0700" in result.stderr
    assert not any(harness["credentials"].iterdir())


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_credential_path_must_be_a_real_directory(
    harness: dict[str, Any], kind: str
) -> None:
    harness["credentials"].rmdir()
    if kind == "file":
        harness["credentials"].write_text("not a directory", encoding="utf-8")
    else:
        target = harness["tmp"] / "credential-target"
        target.mkdir(mode=0o700)
        harness["credentials"].symlink_to(target, target_is_directory=True)

    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "credential directory" in result.stderr
    assert not harness["site_input"].exists()


def test_credential_directory_must_be_owned_by_invoking_user(
    harness: dict[str, Any],
) -> None:
    preview = _run(harness)
    assert preview.returncode == 0, preview.stderr
    harness["env"]["OWNER_CASE"] = "foreign"
    result = _run(harness, apply=True)
    assert result.returncode != 0
    assert "not owned" in result.stderr
    assert not any(harness["credentials"].iterdir())
    assert not harness["site_input"].exists()


def test_partial_credential_install_restores_prior_files(
    harness: dict[str, Any],
) -> None:
    old_values = {
        "d1-read-token": "old-d1-token\n",
        "r2-access-key-id": "old-r2-access\n",
        "r2-secret-access-key": "old-r2-secret\n",
    }
    for name, value in old_values.items():
        path = harness["credentials"] / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
    harness["env"]["MV_CASE"] = "fail-second-install"

    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "unable to install credential files" in result.stderr
    assert not harness["site_input"].exists()
    assert not list(harness["credentials"].glob(".coquic-steward-bootstrap.*"))
    for name, value in old_values.items():
        path = harness["credentials"] / name
        assert path.read_text(encoding="utf-8") == value
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
