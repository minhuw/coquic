"""Real pinned Pulumi/provider regression; fake REST inside a loopback-only namespace."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
from typing import Any

import pytest


ACCOUNT = "a" * 32
BOOTSTRAP = "FAKE_OFFLINE_BOOTSTRAP_TOKEN"
TOKEN_VALUE = "FAKE_OFFLINE_CREATED_TOKEN_VALUE"
SECRET_SIGNATURE = "4dabf18193072939515e22adb298388d"


def _offline_regression(root: Path) -> None:
    assert [name for _, name in socket.if_nameindex()] == ["lo"]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=10)
    assert importlib.metadata.version("pulumi-cloudflare") == "6.18.0"
    project = root / "project"
    requests: list[str] = []
    violations: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            if (
                self.path != f"/client/v4/accounts/{ACCOUNT}/tokens"
                or self.headers.get("Authorization") != f"Bearer {BOOTSTRAP}"
            ):
                self.do_GET()
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body["name"])
            policies = body["policies"]
            for index, policy in enumerate(policies):
                # Real REST resources are objects; the SDK serializes these compactly.
                assert policy["resources"] == {f"com.cloudflare.api.account.{ACCOUNT}": "*"}
                policy["id"] = f"{index + 1:032x}"
                policy["permission_groups"].reverse()
            payload = json.dumps({
                "success": True, "errors": [], "messages": [],
                "result": {
                    "id": f"{len(requests):032x}", "name": body["name"],
                    "status": "active", "policies": policies, "value": TOKEN_VALUE,
                    "issued_on": "2026-01-01T00:00:00Z",
                    "modified_on": "2026-01-01T00:00:00Z",
                },
            }, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            violations.append(self.command + " " + self.path)
            self.send_error(400, "unexpected offline request")

        do_PUT = do_PATCH = do_DELETE = do_HEAD = do_GET

    def pulumi(*args: str) -> str:
        result = subprocess.run(
            ["pulumi", *args], cwd=project, env=os.environ,
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout + result.stderr
        assert TOKEN_VALUE not in output, "created token leaked to CLI output"
        assert BOOTSTRAP not in output, "bootstrap token leaked to CLI output"
        assert result.returncode == 0, output
        return result.stdout

    assert pulumi("version").strip() == "v3.192.0"
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for mode in ("legacy", "canonical"):
            (project / "mode").write_text(mode, encoding="utf-8")
            pulumi("stack", "init", mode, "--non-interactive")
            pulumi("config", "set", "cloudflare:baseUrl",
                   f"http://127.0.0.1:{server.server_port}/client/v4/", "--non-interactive")
            pulumi("up", "--yes", "--skip-preview", "--non-interactive")
            state = json.loads(pulumi("stack", "export"))
            tokens = [resource for resource in state["deployment"]["resources"]
                      if resource["type"] == "cloudflare:index/accountToken:AccountToken"]
            assert len(tokens) == 2
            for token in tokens:
                value = token["outputs"]["value"]
                assert value[SECRET_SIGNATURE] == "1b47061264138c4ac30d75fd1eb44270"
                assert "ciphertext" in value and "plaintext" not in value
                inputs = token["inputs"]["policies"][0]
                outputs = token["outputs"]["policies"][0]
                assert json.loads(inputs["resources"]) == json.loads(outputs["resources"])
                assert outputs["resources"] == json.dumps(
                    json.loads(outputs["resources"]), separators=(",", ":")
                )
                input_ids = [group["id"] for group in inputs["permissionGroups"]]
                output_ids = [group["id"] for group in outputs["permissionGroups"]]
                assert set(input_ids) == set(output_ids)
                assert output_ids == sorted(output_ids)
                if mode == "legacy":
                    assert inputs["resources"] != outputs["resources"]
                    if token["inputs"]["name"] == "steward":
                        assert input_ids != output_ids
                else:
                    assert inputs["resources"] == outputs["resources"]
                    assert input_ids == output_ids

            def preview_ops() -> dict[str, str]:
                preview = json.loads(pulumi(
                    "preview", "--json", "--show-sames", "--refresh=false", "--non-interactive",
                ))
                return {step["urn"].rsplit("::", 1)[-1]: step["op"]
                        for step in preview["steps"]
                        if step["newState"]["type"] == "cloudflare:index/accountToken:AccountToken"}

            ops = preview_ops()
            expected = "update" if mode == "legacy" else "same"
            assert ops == {"steward": expected, "site": expected}, (mode, ops)
            print(f"{mode} repeat preview: {ops}", flush=True)
            if mode == "legacy":
                # Keep the actual create checkpoint, including its legacy inputs.
                # Only change the program: migration must not rotate either token.
                (project / "mode").write_text("canonical", encoding="utf-8")
                ops = preview_ops()
                assert ops == {"steward": "same", "site": "same"}, ops
                print(f"legacy-state migration: {ops}", flush=True)
            if mode == "canonical":
                (project / "mode").write_text("changed", encoding="utf-8")
                ops = preview_ops()
                assert ops == {"steward": "update", "site": "same"}, ops
                print(f"genuine permission change: {ops}", flush=True)
        assert sorted(requests) == ["site", "site", "steward", "steward"]
        assert not violations, violations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_account_token_create_repeat_preview(tmp_path: Path) -> None:
    plugin = Path.home() / ".pulumi/plugins/resource-cloudflare-v6.18.0/pulumi-resource-cloudflare"
    if not plugin.is_file() or any(shutil.which(tool) is None for tool in ("pulumi", "unshare", "ip")):
        pytest.skip("run with nix develop and preinstall public Cloudflare 6.18.0 provider; "
                    "Pulumi 3.192.0, unshare and ip required; no downloads/live fallback")
    project = tmp_path / "project"
    home = tmp_path / "home"
    backend = tmp_path / "backend"
    for path in (project, home, backend):
        path.mkdir(mode=0o700)
    plugin_dir = home / ".pulumi/plugins/resource-cloudflare-v6.18.0"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / plugin.name).symlink_to(plugin)
    # Copy only public program/config source, never operator stack YAML or logins.
    source = Path(__file__).resolve().parents[1]
    shutil.copyfile(source / "__main__.py", project / "program.py")
    shutil.copyfile(source / "config.py", project / "config.py")
    (project / "Pulumi.yaml").write_text("name: offline-account-tokens\nruntime:\n  name: python\n", encoding="utf-8")
    (project / "__main__.py").write_text(
        'import json, runpy\n'
        'from pathlib import Path\n'
        'import pulumi_cloudflare as cloudflare\n'
        'program = runpy.run_path("program.py", run_name="offline_program")\n'
        'mode = Path("mode").read_text()\n'
        'names = program["_STEWARD_PERMISSION_GROUPS"]\n'
        'groups = {name: f"{4-index:032x}" for index, name in enumerate(names)}\n'
        'for label, selected in (("steward", names), ("site", program["_SITE_PERMISSION_GROUPS"])):\n'
        '    if mode == "changed" and label == "steward":\n'
        '        selected = selected[:-1]\n'
        f'    policy = program["_allow_policy"]({ACCOUNT!r}, groups, selected)\n'
        '    if mode == "legacy":\n'
        '        policy["resources"] = json.dumps(json.loads(policy["resources"]), sort_keys=True)\n'
        '        policy["permission_groups"] = [{"id": groups[name]} for name in selected]\n'
        f'    cloudflare.AccountToken(label, account_id={ACCOUNT!r}, name=label, policies=[policy])\n',
        encoding="utf-8",
    )
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "VIRTUAL_ENV") if key in os.environ}
    env.update(
        HOME=str(home), PULUMI_HOME=str(home / ".pulumi"),
        XDG_CONFIG_HOME=str(home / "config"), XDG_CACHE_HOME=str(home / "cache"),
        XDG_DATA_HOME=str(home / "data"), XDG_STATE_HOME=str(home / "state"),
        TMPDIR=str(tmp_path), PULUMI_BACKEND_URL=backend.as_uri(),
        PULUMI_CONFIG_PASSPHRASE="fake-offline-passphrase",
        PULUMI_SKIP_UPDATE_CHECK="true", PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION="true",
        CLOUDFLARE_API_TOKEN=BOOTSTRAP, UV_OFFLINE="true", CI="true",
        PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1",
    )
    namespace = ["unshare", "--user", "--map-root-user", "--net"]
    probe = subprocess.run([*namespace, "ip", "link", "set", "lo", "up"],
                           cwd=project, env=env, capture_output=True, timeout=10)
    if probe.returncode:
        pytest.skip("user/network namespaces unavailable; enable them with nix develop toolchain; "
                    "no live-network fallback")
    child = subprocess.run(
        [*namespace, sys.executable, str(Path(__file__).resolve()), str(tmp_path)],
        cwd=project, env=env, capture_output=True, text=True, timeout=600,
    )
    output = child.stdout + child.stderr
    assert child.returncode == 0, output.replace(TOKEN_VALUE, "[redacted]").replace(BOOTSTRAP, "[redacted]")


if __name__ == "__main__":
    _offline_regression(Path(sys.argv[1]))
