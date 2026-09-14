"""Real Wrangler, fake cloud: requires Linux user/network namespaces and nix develop."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import threading
from typing import Any

import pytest
import test_deploy_production as deploy


pytest_plugins = ["test_deploy_production"]

ACCOUNT = "a" * 32
DATABASE = "12345678-1234-4abc-8def-1234567890ab"
DATABASE_PATH = f"/client/v4/accounts/{ACCOUNT}/d1/database/{DATABASE}"
SCHEMA_QUERY = (
    "SELECT type, name, tbl_name, sql FROM sqlite_master "
    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
)


def _offline_apply(harness: dict[str, Any], blank: bool) -> None:
    # The server and every deploy subprocess share a fresh, loopback-only network.
    assert [name for _, name in socket.if_nameindex()] == ["lo"]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=10)
    env = harness["env"]
    deploy.ROOT = Path(harness["project"])
    deploy.SCRIPT = deploy.ROOT / "infra/cloudflare/scripts/deploy-production.sh"
    version = subprocess.run(
        [env["WRANGLER_BIN"], "--version"],
        cwd=deploy.ROOT,
        env={**env, "WRANGLER_WRITE_LOGS": "false"},
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    assert version.stdout.strip() == "4.93.0", version.stdout + version.stderr
    rows = json.loads(Path(env["SCHEMA_ROWS"]).read_text(encoding="utf-8"))
    schema = (deploy.ROOT / "contracts/steward-cloud/d1.sql").read_bytes()
    # Wrangler's remote --file API uses MD5 as a content identifier, not security.
    etag = hashlib.md5(schema, usedforsecurity=False).hexdigest()
    requests: list[tuple[str, str, Any]] = []
    imported = False

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            nonlocal imported
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.command, self.path, body))
            if self.headers.get("Authorization") != f"Bearer {env['CLOUDFLARE_API_TOKEN']}":
                self.send_error(403, "expected fake bootstrap token")
                return
            if self.path == DATABASE_PATH + "/query" and body == {"sql": SCHEMA_QUERY}:
                result = [rows if not blank or imported else {
                    "success": True,
                    "results": [row for row in rows["results"] if row["name"] == "_cf_KV"],
                }]
            elif (
                blank
                and not imported
                and self.path == DATABASE_PATH + "/import"
                and body == {"action": "init", "etag": etag}
            ):
                # Cached-upload branch: still exercises real --file hashing/import.
                imported = True
                result = {
                    "success": True,
                    "status": "complete",
                    "messages": [],
                    "result": {
                        "num_queries": 1,
                        "final_bookmark": "offline-bookmark",
                        "meta": {"duration": 1, "rows_read": 0, "rows_written": 0, "size_after": 4096},
                    },
                }
            else:
                self.send_error(400, "unexpected query or import")
                return
            payload = json.dumps(
                {"success": True, "errors": [], "messages": [], "result": result}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            requests.append((self.command, self.path, None))
            self.send_error(400, "account enumeration and database name lookup forbidden")

        do_PUT = do_PATCH = do_DELETE = do_HEAD = do_GET

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Supported by Wrangler 4.93.0's getCloudflareApiBaseUrlFromEnv().
    env["CLOUDFLARE_API_BASE_URL"] = f"http://127.0.0.1:{server.server_port}/client/v4"
    try:
        result = deploy._reviewed_apply(harness)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    expected = [("POST", DATABASE_PATH + "/query", {"sql": SCHEMA_QUERY})]
    if blank:
        expected += [
            ("POST", DATABASE_PATH + "/import", {"action": "init", "etag": etag}),
            expected[0],
        ]
    assert requests == expected, (requests, result.stdout, result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "cloud bootstrap complete" in result.stdout
    assert env["CLOUDFLARE_API_TOKEN"] not in result.stdout + result.stderr


@pytest.mark.parametrize("blank", [False, True], ids=["exact", "blank-import"])
def test_deploy_with_real_wrangler(harness: dict[str, Any], blank: bool) -> None:
    wrangler = shutil.which("wrangler")
    assert wrangler is not None, "run with nix develop (Wrangler 4.93.0 required)"
    unshare = shutil.which("unshare")
    ip = shutil.which("ip")
    if unshare is None or ip is None:
        pytest.skip("offline Wrangler test requires unshare and ip; no live-network fallback")

    root = harness["tmp"]
    project = root / "project"
    # Copy only public inputs, never Pulumi stack YAML, logins, .env, or caches.
    # Execute the actual script unchanged, without permitting writes in the checkout.
    for source in (deploy.SCRIPT, deploy.SCHEMA):
        destination = project / source.relative_to(deploy.ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    home = root / "home"
    home.mkdir(mode=0o700)
    env = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "VIRTUAL_ENV")
        if key in os.environ
    }
    # The shared fixture inherits ambient env; take ONLY its explicit fake settings.
    for key in (
        "PATH", "PULUMI_BIN", "COQUIC_SITE_INSTALLER", "CLOUDFLARE_API_TOKEN",
        "COMMAND_LOG", "OUTPUTS", "SCHEMA_ROWS", "PULUMI_APPLIED",
        "PULUMI_UP_PLAN", "SITE_INPUT", "REAL_MV", "COQUIC_CLOUDFLARE_PLAN_DIR",
    ):
        env[key] = harness["env"][key]
    env.update(
        HOME=str(home),
        PULUMI_HOME=str(home / ".pulumi"),
        XDG_CONFIG_HOME=str(home / "config"),
        XDG_CACHE_HOME=str(home / "cache"),
        XDG_DATA_HOME=str(home / "data"),
        XDG_STATE_HOME=str(home / "state"),
        TMPDIR=str(root),
        WRANGLER_BIN=str(Path(wrangler).resolve()),
        WRANGLER_SEND_METRICS="false",
        WRANGLER_SEND_ERROR_REPORTS="false",
        PYTHONNOUSERSITE="1",
        PYTHONDONTWRITEBYTECODE="1",
        UV_OFFLINE="true",
        CI="true",
    )
    harness["env"] = env
    harness["project"] = project
    state = root / "harness.json"
    state.write_text(json.dumps(harness, default=str), encoding="utf-8")
    state.chmod(0o600)
    namespace = [unshare, "--user", "--map-root-user", "--net"]
    probe = subprocess.run(
        [*namespace, ip, "link", "set", "lo", "up"],
        cwd=project, env=env, capture_output=True, text=True, timeout=10,
    )
    if probe.returncode:
        pytest.skip(f"network namespace unavailable; refusing live-network fallback: {probe.stderr}")
    child = subprocess.run(
        [*namespace, sys.executable, str(Path(__file__).resolve()), str(state), str(int(blank))],
        cwd=project, env=env, capture_output=True, text=True, timeout=90,
    )
    assert child.returncode == 0, child.stdout + child.stderr
    assert harness["applied"].exists()
    values = harness["values"]
    expected_files = {
        "d1-read-token": values["d1_token"],
        "r2-access-key-id": values["s3_access_key_id"],
        "r2-secret-access-key": values["s3_secret_access_key"],
        "live-write-token": values["live_write_token"],
    }
    assert {path.name for path in harness["credentials"].iterdir()} == set(expected_files)
    for name, value in expected_files.items():
        path = harness["credentials"] / name
        assert path.read_text(encoding="utf-8") == value + "\n"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert harness["site_input"].read_text(encoding="utf-8").splitlines() == [
        f"CLOUDFLARE_ACCOUNT_ID={ACCOUNT}",
        f"COQUIC_STEWARD_D1_DATABASE_ID={DATABASE}",
        f"COQUIC_STEWARD_D1_READ_TOKEN={values['d1_read_token']}",
        "COQUIC_STEWARD_PUBLIC_R2_BASE_URL=https://artifacts.coquic.minhuw.dev",
        "COQUIC_STEWARD_LIVE_SNAPSHOT_URL=https://live.coquic.minhuw.dev/api/steward/live",
    ]
    assert not list(project.rglob(".wrangler"))
    assert not list(home.rglob("*.log"))
    assert not list(root.glob("coquic-cloudflare-bootstrap.*"))


if __name__ == "__main__":
    _offline_apply(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")), bool(int(sys.argv[2])))
