import os
from pathlib import Path
import subprocess


def test_python_language_plugin_runs_offline_preview_and_retry(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "Pulumi.yaml").write_text(
        "name: coquic-cloudflare\nruntime:\n  name: python\n",
        encoding="utf-8",
    )
    # Local components exercise the real JSON format without any cloud provider.
    resources = [
        ("cloudflare:index/d1Database:D1Database", "publicationDatabase"),
        ("cloudflare:index/r2Bucket:R2Bucket", "publicArtifacts"),
        ("cloudflare:index/r2Bucket:R2Bucket", "privateOriginals"),
        ("cloudflare:index/r2CustomDomain:R2CustomDomain", "publicArtifactsDomain"),
        ("cloudflare:index/r2BucketLifecycle:R2BucketLifecycle", "privateOriginalsLifecycle"),
        ("cloudflare:index/accountToken:AccountToken", "stewardPublicationToken"),
        ("cloudflare:index/accountToken:AccountToken", "siteReaderToken"),
    ]
    (project / "__main__.py").write_text(
        'import pulumi\n'
        f'for typ, name in {resources!r}:\n'
        '    pulumi.ComponentResource(typ, name, {}, opts=pulumi.ResourceOptions(protect=True))\n'
        'pulumi.export("marker", "python-language-plugin-ran")\n'
        'pulumi.export("steward_s3_secret_access_key", pulumi.Output.secret("fake-token-value"))\n',
        encoding="utf-8",
    )
    backend = tmp_path / "backend"
    backend.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    # Preserve uv's Python environment, never operator credentials or Pulumi settings.
    env = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "VIRTUAL_ENV")
        if key in os.environ
    }
    env.update(
        {
            "HOME": str(home),
            "PULUMI_HOME": str(home / ".pulumi"),
            "PULUMI_BACKEND_URL": backend.as_uri(),
            "PULUMI_CONFIG_PASSPHRASE": "offline-test-passphrase",
            "PULUMI_SKIP_UPDATE_CHECK": "true",
            "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
            "UV_OFFLINE": "true",
        }
    )
    for args in (
        ["stack", "init", "coquic-production", "--non-interactive"],
        ["preview", "--stack", "coquic-production", "--non-interactive", "--color", "never"],
    ):
        result = subprocess.run(
            ["pulumi", *args],
            cwd=project,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    assert '"python-language-plugin-ran"' in result.stdout

    for args in (
        ["up", "--yes", "--non-interactive"],
        ["preview", "--json", "--show-sames", "--non-interactive", "--save-plan", str(tmp_path / "retry.plan")],
    ):
        result = subprocess.run(
            ["pulumi", *args], cwd=project, env=env,
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    assert "fake-token-value" not in result.stdout
    preview = tmp_path / "retry.json"
    preview.write_text(result.stdout, encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "scripts/deploy-production.sh"
    parser = script.read_text(encoding="utf-8").split(
        'python3 - "${preview_output}"', 1,
    )[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    checked = subprocess.run(
        ["python3", "-c", parser, str(preview)], env=env,
        capture_output=True, text=True, timeout=30,
    )
    assert checked.returncode == 0, checked.stderr
    assert checked.stdout.strip() == (
        "create=0 update=0 delete=0 same=8 read=0 refresh=0 resources=8"
    )
