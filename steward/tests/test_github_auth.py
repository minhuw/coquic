from __future__ import annotations

import json
import os
from dataclasses import replace
import sys
import shutil
import subprocess
from pathlib import Path

import pytest

from coquic_steward.core.config import StewardAuthenticationConfig, StewardConfig, StewardDeploymentConfig
from coquic_steward.core.github_auth import (
    MAX_GITHUB_TOKEN_BYTES,
    git_environment,
    git_remote_environment,
    github_cli_environment,
    validate_https_remote,
    read_config_github_token,
)
from coquic_steward.core.subprocesses import run_command


def _config(tmp_path: Path, *, token: str = "token-value") -> StewardConfig:
    deployment = StewardDeploymentConfig(
        enabled=True,
        home=tmp_path,
        repository=tmp_path / "repository",
        min_free_bytes=100,
        max_owned_docker_bytes=200,
        recovery_free_bytes=150,
        recovery_owned_docker_bytes=100,
    )
    return StewardConfig(repo_root=tmp_path, deployment=deployment,
                         authentication=StewardAuthenticationConfig(github_token=token))


def test_local_mode_keeps_ambient_authentication(tmp_path: Path) -> None:
    config = StewardConfig(repo_root=tmp_path)

    assert github_cli_environment(config) == {}
    assert git_environment(config) == {}
    assert git_remote_environment(config) == {}


def test_git_remote_environment_preserves_production_controls(tmp_path: Path) -> None:
    config = _config(tmp_path)

    environment = git_remote_environment(config)
    assert environment["GH_TOKEN"] == "token-value"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GCM_INTERACTIVE"] == "never"
    assert "GIT_SSH_COMMAND" not in environment
    assert all("token-value" not in value for key, value in environment.items() if key != "GH_TOKEN" and value is not None)



def test_github_cli_environment_reads_one_token_per_call(tmp_path: Path) -> None:
    config = _config(tmp_path, token="first-token")

    expected = {
        "GH_TOKEN": "first-token",
        "GITHUB_TOKEN": None,
        "GH_ENTERPRISE_TOKEN": None,
        "GITHUB_ENTERPRISE_TOKEN": None,
        "GH_HOST": "github.com",
        "GH_CONFIG_DIR": "/dev",
        "GH_PROMPT_DISABLED": "1",
        "GH_DEBUG": None,
    }
    assert github_cli_environment(config) == expected
    config = _config(tmp_path, token="second-token")
    expected["GH_TOKEN"] = "second-token"
    assert github_cli_environment(config) == expected


def test_github_cli_environment_removes_ambient_authentication(tmp_path: Path, monkeypatch) -> None:
    for name, value in {
        "GITHUB_TOKEN": "ambient-token",
        "GH_ENTERPRISE_TOKEN": "ambient-enterprise-token",
        "GITHUB_ENTERPRISE_TOKEN": "ambient-enterprise-token",
        "GH_HOST": "enterprise.example",
        "GH_CONFIG_DIR": "/tmp/ambient-gh",
        "GH_PROMPT_DISABLED": "0",
        "GH_DEBUG": "api",
    }.items():
        monkeypatch.setenv(name, value)
    result = run_command(
        [
            sys.executable,
            "-c",
            "import json,os; print(json.dumps({name: os.getenv(name) for name in "
            "('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN',"
            "'GH_HOST','GH_CONFIG_DIR','GH_PROMPT_DISABLED','GH_DEBUG')}))",
        ],
        cwd=tmp_path,
        env=github_cli_environment(_config(tmp_path, token="inline-token")),
        check=True,
    )
    assert json.loads(result.stdout) == {
        "GH_TOKEN": "inline-token",
        "GITHUB_TOKEN": None,
        "GH_ENTERPRISE_TOKEN": None,
        "GITHUB_ENTERPRISE_TOKEN": None,
        "GH_HOST": "github.com",
        "GH_CONFIG_DIR": "/dev",
        "GH_PROMPT_DISABLED": "1",
        "GH_DEBUG": None,
    }


@pytest.mark.parametrize(
    "contents",
    (
        "\n",
        "token\nsecond\n",
        "x" * (MAX_GITHUB_TOKEN_BYTES + 1),
        " token\n",
        "token \n",
        "token\x00",
        "token\x7f",
        "token\r\n",
        "nonascii-\u00e9",
    ),
)
def test_github_cli_environment_rejects_malformed_tokens(
    tmp_path: Path, contents: str
) -> None:
    with pytest.raises(ValueError, match="GitHub token"):
        _config(tmp_path, token=contents)


@pytest.mark.parametrize("remote", (
    "https://github.com/minhuw/coquic.git",
    "https://github.com/Org-1/repo.name_2",
))
def test_validate_https_remote_accepts_canonical_urls(remote: str) -> None:
    assert validate_https_remote(remote) == remote


@pytest.mark.parametrize("remote", (
    "git@github.com:minhuw/coquic.git", "ssh://git@github.com/org/repo",
    "https://example.invalid/org/repo", "https://github.com.evil/org/repo",
    "https://token@github.com/org/repo", "https://git:token@github.com/org/repo",
    "https://github.com:443/org/repo", "https://github.com/org/repo?token=secret",
    "https://github.com/org/repo#fragment", "https://github.com/org/repo/",
    "https://github.com/org/../repo", "https://github.com/../repo",
    "https://github.com/org/..", "https://github.com/org/.",
    "https://github.com/org/r%2fother", "https://github.com/org/r%5cother",
    "https://github.com/org/%2e%2e", "https://github.com/org/repo\\other",
    "https://github.com/org/repo\n", "https://github.com/org/repo\x00",
    "https://GitHub.com/org/repo", "HTTPS://github.com/org/repo",
    "file:///srv/coquic.git", "ext::/bin/sh", "/srv/coquic.git", "",
))
def test_validate_https_remote_rejects_noncanonical_urls(remote: str) -> None:
    with pytest.raises(ValueError, match="credential-free https://github.com") as error:
        validate_https_remote(remote)
    assert "token@" not in str(error.value)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("kind", ("symlink", "fifo", "directory", "public", "missing"))
def test_token_reader_rejects_unsafe_files(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "sensitive-path"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_text('[steward.authentication]\ngithub_token = "synthetic-secret"\n')
        target.chmod(0o600)
        path.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "directory":
        path.mkdir()
    elif kind == "public":
        path.write_text('[steward.authentication]\ngithub_token = "synthetic-secret"\n')
        path.chmod(0o644)
    with pytest.raises((ValueError, FileNotFoundError)) as error:
        read_config_github_token(path)
    assert "sensitive-path" not in str(error.value)
    assert "synthetic-secret" not in str(error.value)
    assert error.value.__cause__ is None


def test_config_reader_uses_open_descriptor_and_bounds_token(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "steward.toml"
    path.write_text('[steward.authentication]\ngithub_token = "' + "x" * MAX_GITHUB_TOKEN_BYTES + '"\n')
    path.chmod(0o600)
    original_open = os.open

    def swap_after_open(selected, flags):
        assert flags & os.O_NOFOLLOW
        assert flags & os.O_NONBLOCK
        descriptor = original_open(selected, flags)
        selected.unlink()
        selected.write_text("replacement-token")
        selected.chmod(0o600)
        return descriptor

    monkeypatch.setattr(os, "open", swap_after_open)
    assert read_config_github_token(path) == "x" * MAX_GITHUB_TOKEN_BYTES


def _native_git_env(tmp_path: Path, monkeypatch) -> tuple[dict[str, str], Path]:
    config = _config(tmp_path, token="synthetic-token-only")
    home = tmp_path / "clean-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    marker = tmp_path / "untrusted-helper-ran"
    injected = tmp_path / "injected.gitconfig"
    injected.write_text(
        f'[credential]\n helper = "!touch {marker}"\n'
        '[url "https://example.invalid/"]\n insteadOf = https://github.com/\n'
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(injected))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(injected))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "credential.helper")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", f"!touch {marker}")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'credential.helper=!touch {marker}'")
    monkeypatch.setenv("GIT_ASKPASS", f"touch {marker}")
    monkeypatch.setenv("SSH_ASKPASS", f"touch {marker}")
    monkeypatch.setenv("GH_TOKEN", "ambient-token-must-not-win")
    for key in ("GIT_TRACE", "GIT_TRACE_CURL", "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF"):
        monkeypatch.setenv(key, str(tmp_path / key))
    monkeypatch.setenv("GIT_TRACE2_ENV_VARS", "GH_TOKEN,GITHUB_TOKEN")
    monkeypatch.setenv("GIT_TRACE_REDACT", "0")
    monkeypatch.setenv("GIT_CURL_VERBOSE", "1")
    monkeypatch.setenv("GH_DEBUG", "api")
    before = dict(os.environ)
    environment = {key: value for key, value in {**os.environ, **git_environment(config)}.items() if value is not None}
    assert dict(os.environ) == before
    return environment, marker


@pytest.mark.skipif(not shutil.which("gh") or not shutil.which("git"), reason="native Git/gh required")
def test_native_credential_helper_is_host_scoped_ephemeral_and_trace_free(tmp_path, monkeypatch) -> None:
    environment, marker = _native_git_env(tmp_path, monkeypatch)
    github = "protocol=https\nhost=github.com\n\n"
    result = subprocess.run(
        ["git", "credential", "fill"], input=github, cwd=tmp_path,
        env=environment, text=True, capture_output=True, check=True,
    )
    assert "password=synthetic-token-only\n" in result.stdout
    assert "synthetic-token-only" not in result.stderr
    foreign = subprocess.run(
        ["git", "credential", "fill"], input="protocol=https\nhost=example.invalid\n\n",
        cwd=tmp_path, env=environment, text=True, capture_output=True,
    )
    assert foreign.returncode != 0
    assert "synthetic-token-only" not in foreign.stdout + foreign.stderr
    for operation in ("approve", "reject"):
        subprocess.run(
            ["git", "credential", operation], input=result.stdout + "\n",
            cwd=tmp_path, env=environment, text=True, capture_output=True, check=True,
        )
    assert not marker.exists()
    assert not any(tmp_path.glob("GIT_TRACE*"))
    assert not list((tmp_path / "clean-home").rglob("*"))
    settings = [
        (environment[f"GIT_CONFIG_KEY_{index}"], environment[f"GIT_CONFIG_VALUE_{index}"])
        for index in range(int(environment["GIT_CONFIG_COUNT"]))
    ]
    assert ("http.followRedirects", "false") in settings


def test_standalone_validation_does_not_import_application_dependencies(tmp_path) -> None:
    import coquic_steward.core.github_auth as auth

    script = str(Path(auth.__file__).resolve())
    for remote, status in (("https://github.com/org/repo.git", 0), ("https://secret@github.com/org/repo", 1)):
        result = subprocess.run(
            [sys.executable, "-S", script, "validate-remote", remote],
            cwd=tmp_path, capture_output=True, text=True,
        )
        assert result.returncode == status
        assert "secret" not in result.stdout + result.stderr
        assert len(result.stderr) < 200


@pytest.mark.parametrize(("contents", "status"), (
    ('[steward.authentication]\ngithub_token = "synthetic-secret"\n', 0),
    ('[steward.authentication]\nproxy_url = "https://proxy.test"\napi_key = "model-key"\n', 1),
    ('[steward.authentication]\ngithub_token = ""\n', 1),
    ('[steward.authentication]\ngithub_token = "unterminated\n', 1),
))
def test_standalone_config_validation_requires_inline_token(tmp_path, contents, status) -> None:
    import coquic_steward.core.github_auth as auth

    path = tmp_path / "private.toml"
    path.write_text(contents)
    path.chmod(0o600)
    result = subprocess.run(
        [sys.executable, "-S", str(Path(auth.__file__).resolve()),
         "validate-config", "--config", str(path)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == status
    assert "synthetic-secret" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert len(result.stderr) < 200


def test_standalone_clone_uses_same_helper_without_inheriting_git_selectors(tmp_path, monkeypatch) -> None:
    import coquic_steward.core.github_auth as auth

    environment, _marker = _native_git_env(tmp_path, monkeypatch)
    monkeypatch.setenv("GIT_DIR", "/untrusted/repository")
    monkeypatch.setenv("GIT_WORK_TREE", "/untrusted/worktree")
    monkeypatch.setenv("GIT_EXEC_PATH", "/untrusted/tools")
    monkeypatch.setenv("GIT_SSL_NO_VERIFY", "1")
    monkeypatch.setenv("SSL_CERT_FILE", "/untrusted/ca.pem")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert argv == [str(Path(shutil.which("git")).resolve()), "clone", "--branch", "main",
                        "--single-branch", "--", "https://github.com/org/repo.git", str(tmp_path / "clone")]
        assert "synthetic-token-only" not in repr(argv)
        child = kwargs["env"]
        assert child["GH_TOKEN"] == "synthetic-token-only"
        assert "GIT_SSL_NO_VERIFY" not in child
        assert "SSL_CERT_FILE" not in child
        assert all(value is not None for value in child.values())
        assert child["GIT_CONFIG_COUNT"] == environment["GIT_CONFIG_COUNT"]
        assert not {"GIT_DIR", "GIT_WORK_TREE", "GIT_EXEC_PATH"} & child.keys()
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        return subprocess.CompletedProcess(argv, 0)

    private_config = tmp_path / "steward.toml"
    private_config.write_text('[steward.authentication]\ngithub_token = "synthetic-token-only"\n')
    private_config.chmod(0o600)
    monkeypatch.setattr(auth.subprocess, "run", fake_run)
    assert auth.main(["clone", "--config", str(private_config),
                      "--branch", "main", "--remote", "https://github.com/org/repo.git",
                      "--destination", str(tmp_path / "clone")]) == 0
    assert len(calls) == 1


def test_clone_refuses_bad_inputs_before_invoking_git(tmp_path, monkeypatch, capsys) -> None:
    import coquic_steward.core.github_auth as auth

    monkeypatch.setattr(auth.subprocess, "run", lambda *a, **k: pytest.fail("must not invoke Git"))
    assert auth.main(["clone", "--config", str(tmp_path / "private-token"),
                      "--branch", "main", "--remote", "https://secret@github.com/org/repo",
                      "--destination", str(tmp_path / "clone")]) == 1
    output = capsys.readouterr()
    assert "secret@" not in output.err
    assert "private-token" not in output.err


def test_standalone_parser_does_not_echo_untrusted_arguments(tmp_path) -> None:
    import coquic_steward.core.github_auth as auth

    result = subprocess.run(
        [sys.executable, "-S", str(Path(auth.__file__).resolve()),
         "validate-remote", "--private-token-must-not-be-echoed"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert result.stderr == "invalid GitHub HTTPS command arguments\n"


def test_missing_helper_fails_without_exposing_token(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path, token="synthetic-private-token")
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(ValueError, match="required gh executable is unavailable"):
        git_remote_environment(config)


@pytest.mark.skipif(not shutil.which("gh") or not shutil.which("git"), reason="native Git/gh required")
def test_repository_helpers_and_trace_config_cannot_capture_token(tmp_path, monkeypatch) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    marker = tmp_path / "local-helper-ran"
    for key, value in (
        ("credential.helper", f"!touch {marker}"),
        ("credential.https://github.com/org.helper", f"!touch {marker}"),
        ("trace2.eventTarget", str(tmp_path / "GIT_TRACE-local")),
        ("trace2.envVars", "GH_TOKEN"),
    ):
        subprocess.run(["git", "config", "--local", key, value], cwd=tmp_path, check=True)
    # Config setup itself can produce traces; only credential operations matter.
    (tmp_path / "GIT_TRACE-local").unlink(missing_ok=True)
    environment, _ = _native_git_env(tmp_path, monkeypatch)
    result = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\npath=org/repo.git\n\n",
        cwd=tmp_path, env=environment, text=True, capture_output=True, check=True,
    )
    assert "password=synthetic-token-only\n" in result.stdout
    assert not marker.exists()
    assert not any(tmp_path.glob("GIT_TRACE*"))


@pytest.mark.skipif(any(not shutil.which(tool) for tool in ("git", "gh", "openssl")), reason="native Git/gh/OpenSSL required")
@pytest.mark.parametrize("production", (False, True))
def test_git_rejects_self_signed_tls_despite_inherited_verification_bypass(tmp_path, monkeypatch, production):
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from coquic_steward.core.subprocesses import run_command

    certificate = tmp_path / "certificate.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", str(key), "-out", str(certificate)],
        check=True, capture_output=True, timeout=15,
    )
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.headers.get("Authorization"))
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="synthetic"')
            self.end_headers()

        def log_message(self, *_args):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = _config(tmp_path, token="synthetic-token-only")
    config = replace(config, deployment=replace(config.deployment, enabled=production))
    monkeypatch.setenv("GIT_SSL_NO_VERIFY", "1")
    # Ambient CA overrides must not turn this untrusted certificate into a root.
    monkeypatch.setenv("GIT_SSL_CAINFO", str(certificate))
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    environment = git_remote_environment(config)
    assert environment["GIT_SSL_NO_VERIFY"] is None
    try:
        # Transport fixture only: production remote validation still rejects
        # loopback URLs, and no external host or real credential is involved.
        result = run_command(
            ["git", "ls-remote", f"https://127.0.0.1:{server.server_port}/repo.git"],
            cwd=tmp_path, env=environment, timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not result.ok
    assert "certificate" in result.stderr.lower()
    assert "synthetic-token-only" not in result.stdout + result.stderr
    assert requests == []  # Not even an unauthenticated HTTP request passed TLS.
    assert os.environ["GIT_SSL_NO_VERIFY"] == "1"


@pytest.mark.parametrize("contents", (
    "[steward]\n", "[steward.authentication]\n",
    '[steward.authentication]\ngithub_token = "synthetic-secret"\nproxy_url = "https://proxy.test"\n',
    '[steward.authentication]\ngithub_token = "synthetic-secret"\nunknown = true\n',
    '[steward.authentication]\ngithub_token = "synthetic-secret "\n',
    '[steward.authentication]\ngithub_token = "synthetic-secret\n',
))
def test_standalone_clone_rejects_private_config_without_application_imports(tmp_path, contents):
    import coquic_steward.core.github_auth as auth

    path = tmp_path / "private.toml"
    path.write_text(contents)
    path.chmod(0o600)
    result = subprocess.run(
        [sys.executable, "-S", str(Path(auth.__file__).resolve()), "clone",
         "--config", str(path), "--branch", "main", "--remote", "https://github.com/org/repo",
         "--destination", str(tmp_path / "clone")],
        cwd=tmp_path, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 1
    assert "synthetic-secret" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert len(result.stderr) < 200


def test_config_github_token_checks_current_owner(tmp_path, monkeypatch):
    path = tmp_path / "private.toml"
    path.write_text('[steward.authentication]\ngithub_token = "synthetic-secret"\n')
    path.chmod(0o600)
    monkeypatch.setattr(os, "geteuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(ValueError, match="owned by the current user"):
        read_config_github_token(path)
