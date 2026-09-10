from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import textwrap
import time
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
import time


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
assert args[args.index("--stack") + 1] == "coquic-production"
if args[:1] == ["preview"]:
    if case == "preview-failure":
        print("provider output is hidden", file=sys.stderr)
        raise SystemExit(1)
    plan = Path(args[args.index("--save-plan") + 1])
    plan.write_text(os.environ.get("PULUMI_PLAN_CONTENT", "saved-plan"), encoding="utf-8")
    resources = [
        ("pulumi:pulumi:Stack", "coquic-cloudflare-coquic-production"),
        ("cloudflare:index/d1Database:D1Database", "publicationDatabase"),
        ("cloudflare:index/r2Bucket:R2Bucket", "publicArtifacts"),
        ("cloudflare:index/r2Bucket:R2Bucket", "privateOriginals"),
        ("cloudflare:index/r2CustomDomain:R2CustomDomain", "publicArtifactsDomain"),
        ("cloudflare:index/r2BucketLifecycle:R2BucketLifecycle", "privateOriginalsLifecycle"),
        ("cloudflare:index/accountToken:AccountToken", "stewardPublicationToken"),
        ("cloudflare:index/accountToken:AccountToken", "siteReaderToken"),
    ]
    if case == "malformed-preview":
        print("not structured JSON fixture-secret")
    elif case == "missing-operations":
        print(json.dumps({"diagnostics": []}))
    elif case == "update":
        print(json.dumps({"op": "update", "type": resources[1][0], "name": resources[1][1]}))
    elif case == "destructive":
        print(json.dumps({"op": "delete", "type": resources[1][0], "name": resources[1][1]}))
    elif case == "unexpected":
        resources.append(("cloudflare:index/r2Bucket:R2Bucket", "unexpectedBucket"))
        for resource_type, name in resources:
            print(json.dumps({"op": "same", "type": resource_type, "name": name}))
    elif case == "secret-preview":
        print(json.dumps({"op": "same", "type": resources[1][0], "name": resources[1][1], "output": "fixture-secret"}))
    elif case.startswith("summary"):
        assert "--show-sames" in args
        steps = [
            {
                "op": "create",
                "urn": f"urn:pulumi:coquic-production::coquic-cloudflare::{resource_type}::{name}",
                "newState": {"type": resource_type, "protect": True},
                "detailedDiff": None,
            }
            for resource_type, name in resources
        ]
        if case == "summary-wrong-stack":
            steps[0]["urn"] = steps[0]["urn"].replace("coquic-production", "other-stack")
        elif case == "summary-stack-update":
            steps[0]["op"] = "update"
        elif case == "summary-stack-delete":
            steps[0]["op"] = "delete"
        elif case == "summary-stack-replace":
            steps[0]["op"] = "replace"
        elif case == "summary-extra-resource":
            steps.append({"op": "create", "type": "pulumi:providers:other", "name": "default"})
        elif case == "summary-conflict":
            steps.append({**steps[0], "op": "same"})
        elif case == "summary-no-identity":
            steps.append({"op": "create"})
        elif case == "summary-secret":
            steps[0]["newState"]["outputs"] = {"api_key": "fixture-secret"}
        elif case == "summary-secret-wrapper":
            steps[0]["newState"]["outputs"] = {"secret": True, "value": "fixture-secret"}
        elif case.startswith("summary-retry"):
            for step in steps:
                step["op"] = "same"
            value = json.loads(os.environ.get("PREVIEW_SECRET_VALUE", '"[secret]"'))
            steps[0]["oldState"] = {"outputs": {"steward_s3_secret_access_key": value}}
        print(json.dumps({"steps": steps, "diagnostics": [], "changeSummary": {steps[0]["op"]: len(steps)}}))
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
                        "urn": f"urn:pulumi:coquic-production::coquic-cloudflare::{resource_type}::{name}",
                    }
                }
            }))
    raise SystemExit(0)
if args[:1] == ["up"]:
    plan = Path(args[args.index("--plan") + 1])
    if case == "pause-before-plan-open":
        Path(os.environ["PULUMI_UP_READY"]).write_text("ready", encoding="utf-8")
        while not Path(os.environ["PULUMI_UP_RELEASE"]).exists():
            time.sleep(0.01)
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
assert args[2] == "PUBLICATION", "d1 execute takes a name or binding, not a UUID"
assert os.environ.get("CLOUDFLARE_ACCOUNT_ID") == "a" * 32
config_path = Path(args[args.index("--config") + 1])
assert config_path.is_file() and not config_path.is_symlink()
assert config_path.stat().st_mode & 0o777 == 0o600
assert json.loads(config_path.read_text(encoding="utf-8")) == {
    "d1_databases": [{
        "binding": "PUBLICATION",
        "database_id": "12345678-1234-4abc-8def-1234567890ab",
    }],
}
assert Path(os.environ["WRANGLER_LOG_PATH"]).parent == config_path.parent
assert os.environ.get("WRANGLER_SEND_METRICS") == "false"
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
    rows = json.loads(Path(os.environ["SCHEMA_ROWS"]).read_text(encoding="utf-8"))["results"]
    print(json.dumps({"success": True, "results": [row for row in rows if row["name"] == "_cf_KV"]}))
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
        # D1 includes this system table even before application initialization.
        connection.execute("CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID")
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
    up_ready = tmp_path / "pulumi-up-ready"
    up_release = tmp_path / "pulumi-up-release"
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
            "PULUMI_UP_READY": str(up_ready),
            "PULUMI_UP_RELEASE": str(up_release),
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
        "up_ready": up_ready,
        "up_release": up_release,
        "values": values,
    }


def _run(
    harness: dict[str, Any],
    *extra: str,
    apply: bool = False,
    stack: str | None = "coquic-production",
) -> subprocess.CompletedProcess[str]:
    args = [
        "--credentials-dir",
        str(harness["credentials"]),
        "--plan-dir",
        str(harness["plan_dir"]),
    ]
    if stack is not None:
        args.extend(["--stack", stack])
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
    assert text.splitlines()[0] == (
        "usage: deploy-production.sh --stack coquic-production "
        "--credentials-dir DIR [--plan-dir DIR] [--apply]"
    )
    assert "Preview is read-only" in text
    assert "--apply" in text


def test_default_preview_is_read_only(harness: dict[str, Any]) -> None:
    result = _run(harness)
    assert result.returncode == 0, result.stderr
    assert "preview accepted" in result.stdout
    assert "no changes applied" in result.stdout
    assert not harness["applied"].exists()
    assert not any(harness["credentials"].iterdir())
    reviewed_plan = harness["plan_dir"] / "coquic-production.plan"
    review_record = harness["plan_dir"] / "coquic-production.review.json"
    assert reviewed_plan.is_file()
    assert review_record.is_file()
    assert json.loads(review_record.read_text(encoding="utf-8"))["stack"] == "coquic-production"
    assert stat.S_IMODE(reviewed_plan.stat().st_mode) == 0o400
    assert stat.S_IMODE(review_record.stat().st_mode) == 0o400
    assert stat.S_IMODE(harness["plan_dir"].stat().st_mode) == 0o700
    logs = _logs(harness)
    pulumi = _argv(logs, "pulumi")
    assert [argv[0] for argv in pulumi] == ["whoami", "preview"]
    preview = pulumi[1]
    assert preview[preview.index("--stack") + 1] == "coquic-production"
    assert "--save-plan" in preview
    assert "--show-sames" in preview
    assert Path(preview[preview.index("--save-plan") + 1]).name == "coquic-production.plan"
    assert _argv(logs, "wrangler") == []
    assert all(isinstance(entry, dict) for entry in logs)
    assert "bootstrap-" not in result.stdout + result.stderr


def test_preview_accepts_pulumi_summary_with_root_stack(harness: dict[str, Any]) -> None:
    harness["env"]["PULUMI_CASE"] = "summary"
    result = _run(harness)
    assert result.returncode == 0, result.stderr
    assert "create=8" in result.stdout
    assert "resources=8" in result.stdout
    assert not harness["applied"].exists()
    assert _argv(_logs(harness), "wrangler") == []
    assert not any(harness["credentials"].iterdir())


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("summary-wrong-stack", "resource allowlist mismatch"),
        ("summary-stack-update", "update, delete, replacement, or unsupported operation"),
        ("summary-stack-delete", "update, delete, replacement, or unsupported operation"),
        ("summary-stack-replace", "update, delete, replacement, or unsupported operation"),
        ("summary-extra-resource", "resource allowlist mismatch"),
        ("summary-conflict", "conflicting resource operations"),
        ("summary-no-identity", "operation without resource identity"),
        ("summary-secret", "unredacted sensitive field"),
        ("summary-secret-wrapper", "unredacted secret wrapper"),
        ("secret-preview", "secret-shaped string"),
        ("malformed-preview", "invalid preview JSON"),
        ("missing-operations", "missing resource operations"),
    ],
)
def test_preview_checks_root_stack_without_bypassing_safety(
    harness: dict[str, Any], case: str, reason: str,
) -> None:
    harness["env"]["PULUMI_CASE"] = case
    result = _run(harness)
    assert result.returncode != 0
    assert result.stderr == (
        "error: Pulumi preview was not a safe structured plan for the protected stack: "
        f"{reason}\n"
    )
    assert "fixture-secret" not in result.stdout + result.stderr
    assert not any(harness["plan_dir"].iterdir())
    assert not harness["applied"].exists()
    assert _argv(_logs(harness), "wrangler") == []


def test_retry_reviews_unchanged_resources_and_redacted_outputs(
    harness: dict[str, Any],
) -> None:
    harness["env"]["WRANGLER_CASE"] = "query-failure"
    failed = _reviewed_apply(harness)
    assert failed.returncode != 0
    assert harness["applied"].exists()
    assert not any(harness["plan_dir"].iterdir())
    harness["env"].update(PULUMI_CASE="summary-retry", WRANGLER_CASE="exact")
    preview = _run(harness)
    assert preview.returncode == 0, preview.stderr
    assert "create=0 update=0 delete=0 same=8" in preview.stdout
    result = _run(harness, apply=True)
    assert result.returncode == 0, result.stderr
    assert harness["site_input"].exists()


@pytest.mark.parametrize(
    "value",
    ["[secret]-fixture-secret", "fixture-secret", " [secret]", {"secret": True, "value": "[secret]"}],
)
def test_retry_rejects_nonredacted_secret_outputs(harness: dict[str, Any], value: Any) -> None:
    harness["env"]["PULUMI_CASE"] = "summary-retry"
    harness["env"]["PREVIEW_SECRET_VALUE"] = json.dumps(value)
    result = _run(harness)
    assert result.returncode != 0
    assert "safe structured plan" in result.stderr
    assert "fixture-secret" not in result.stdout + result.stderr
    assert not any(harness["plan_dir"].iterdir())


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
    assert not (harness["plan_dir"] / "coquic-production.plan").exists()
    assert not (harness["plan_dir"] / "coquic-production.review.json").exists()


def test_apply_pins_the_reviewed_plan_against_concurrent_replacement(
    harness: dict[str, Any],
) -> None:
    harness["env"]["PULUMI_PLAN_CONTENT"] = "replacement-plan-P"
    preview = _run(harness)
    assert preview.returncode == 0, preview.stderr

    apply_env = harness["env"].copy()
    apply_env["PULUMI_CASE"] = "pause-before-plan-open"
    apply_process = subprocess.Popen(
        [
            "bash",
            str(SCRIPT),
            "--stack",
            "coquic-production",
            "--credentials-dir",
            str(harness["credentials"]),
            "--plan-dir",
            str(harness["plan_dir"]),
            "--apply",
        ],
        cwd=ROOT,
        env=apply_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while not harness["up_ready"].exists() and time.monotonic() < deadline:
            assert apply_process.poll() is None, apply_process.stderr.read()
            time.sleep(0.01)
        assert harness["up_ready"].exists()

        harness["env"]["PULUMI_PLAN_CONTENT"] = "replacement-plan-Q"
        replacement = _run(harness)
        assert replacement.returncode == 0, replacement.stderr
    finally:
        harness["up_release"].touch()
        stdout, stderr = apply_process.communicate(timeout=30)

    assert apply_process.returncode == 0, stdout + stderr
    assert harness["up_plan"].read_text(encoding="utf-8") == "replacement-plan-P"
    assert (harness["plan_dir"] / "coquic-production.plan").read_text(encoding="utf-8") == "replacement-plan-Q"


def test_apply_rejects_a_changed_reviewed_plan(harness: dict[str, Any]) -> None:
    preview = _run(harness)
    assert preview.returncode == 0, preview.stderr
    reviewed_plan = harness["plan_dir"] / "coquic-production.plan"
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


@pytest.mark.parametrize("stack", ["production", "staging"])
@pytest.mark.parametrize("source", ["cli", "env"])
@pytest.mark.parametrize("apply", [False, True])
def test_wrong_stack_is_rejected_before_calls_or_plan_invalidation(
    harness: dict[str, Any], stack: str, source: str, apply: bool
) -> None:
    artifacts = {
        harness["plan_dir"] / f"{name}.{suffix}": f"retained-{name}-{suffix}"
        for name in (stack, "coquic-production")
        for suffix in ("plan", "review.json")
    }
    for path, content in artifacts.items():
        path.write_text(content, encoding="utf-8")
        path.chmod(0o400)
    harness["env"]["PULUMI_STACK"] = stack if source == "env" else "coquic-production"

    result = _run(harness, stack=stack if source == "cli" else None, apply=apply)

    assert result.returncode != 0
    assert result.stderr == "error: only the coquic-production stack is allowed\n"
    assert _logs(harness) == []
    assert set(harness["plan_dir"].iterdir()) == set(artifacts)
    for path, content in artifacts.items():
        assert path.read_text(encoding="utf-8") == content
        assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert not any(harness["credentials"].iterdir())


def test_missing_auth_is_rejected(harness: dict[str, Any]) -> None:
    no_auth_env = harness["env"].copy()
    no_auth_env.pop("CLOUDFLARE_API_TOKEN")
    no_auth = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--stack",
            "coquic-production",
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


@pytest.mark.parametrize("ambient_account", [None, "f" * 32])
def test_apply_bootstraps_schema_installs_credentials_and_hands_site(
    harness: dict[str, Any], ambient_account: str | None,
) -> None:
    if ambient_account is None:
        harness["env"].pop("CLOUDFLARE_ACCOUNT_ID", None)
    else:
        harness["env"]["CLOUDFLARE_ACCOUNT_ID"] = ambient_account
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
    config_paths = {Path(argv[argv.index("--config") + 1]) for argv in wrangler}
    assert len(config_paths) == 1
    assert all(not path.parent.exists() for path in config_paths)
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


@pytest.mark.parametrize("initialized", [False, True])
@pytest.mark.parametrize(
    ("kind", "name", "table", "sql"),
    [
        ("table", "_cf_application", "_cf_application", "CREATE TABLE _cf_application (id INTEGER)"),
        ("table", " _cf_KV ", " _cf_KV ", 'CREATE TABLE " _cf_KV " (id INTEGER)'),
        ("view", "_cf_KV", "_cf_KV", "CREATE VIEW _cf_KV AS SELECT 1"),
        ("index", "_cf_KV", "tasks", "CREATE INDEX _cf_KV ON tasks (task_id)"),
    ],
)
def test_system_table_exception_does_not_hide_schema_drift(
    harness: dict[str, Any], initialized: bool, kind: str, name: str, table: str, sql: str,
) -> None:
    path = Path(harness["env"]["SCHEMA_ROWS"])
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not initialized:
        payload["results"] = [row for row in payload["results"] if row["name"] == "_cf_KV"]
    payload["results"].append({"type": kind, "name": name, "tbl_name": table, "sql": sql})
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "schema drift" in result.stderr
    assert not harness["bootstrapped"].exists()
    assert not any(harness["credentials"].iterdir())
    assert not harness["site_input"].exists()


def test_pulumi_apply_failure_stops_before_d1_or_files(harness: dict[str, Any]) -> None:
    harness["env"]["PULUMI_CASE"] = "apply-failure"
    result = _reviewed_apply(harness)
    assert result.returncode != 0
    assert "D1" in result.stderr
    assert _argv(_logs(harness), "wrangler") == []
    assert not any(harness["credentials"].iterdir())
    for path in (
        harness["plan_dir"] / "coquic-production.plan",
        harness["plan_dir"] / "coquic-production.review.json",
    ):
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o400


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
