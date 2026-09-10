from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
import sys
import traceback
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr, TypeAdapter

from coquic_steward import cli
from coquic_steward.core import config as config_module
from coquic_steward.core.config import (
    StewardAuthenticationConfig,
    StewardConfig,
    StewardContainerConfig,
    StewardDeploymentConfig,
    load_config,
)
from coquic_steward.orchestration import preflight

KEY = "inline-test-key-never-print"
PROXY = "http://host.docker.internal:8080/v1"


def _write_config(tmp_path: Path, contents: str, *, mode: int = 0o600) -> Path:
    path = tmp_path / "authentication.toml"
    path.write_text(contents, encoding="utf-8")
    path.chmod(mode)
    return path


def _authentication_toml(proxy_url: str = PROXY, api_key: str = KEY) -> str:
    return (
        "[steward.authentication]\n"
        f"proxy_url = {json.dumps(proxy_url)}\n"
        f"api_key = {json.dumps(api_key)}\n"
    )


@pytest.mark.parametrize(
    "proxy_url",
    (
        PROXY,
        "https://proxy.example.test/v1",
        "http://localhost:1",
        "http://127.0.0.1:65535/v1/",
        "http://[::1]:8080/v1",
        "http://[::1]:08080/v1",
        "https://proxy.example.test./v1",
        "https://proxy.test/" + "a" * (2048 - len("https://proxy.test/")),
    ),
)
def test_inline_authentication_loads_without_container(
    repo: Path, tmp_path: Path, proxy_url: str
) -> None:
    path = _write_config(tmp_path, _authentication_toml(proxy_url))
    config = load_config(repo_root=repo, config_path=path)

    assert config.authentication.proxy_url == proxy_url
    assert isinstance(config.authentication.api_key, SecretStr)
    assert config.read_codex_api_key_bytes() == KEY.encode()
    assert not config.container.enabled


@pytest.mark.parametrize("api_key", (KEY, SecretStr(KEY), "é" * 2048, "k" * 4096))
def test_authentication_wraps_validated_key_and_redacts_dumps(api_key) -> None:
    authentication = StewardAuthenticationConfig(PROXY, api_key)
    raw_key = api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
    config = StewardConfig(repo_root=Path("/unused"), authentication=authentication)

    assert config.read_codex_api_key_bytes() == raw_key.encode("utf-8")
    assert isinstance(authentication.api_key, SecretStr)
    assert raw_key not in repr(config)
    assert raw_key not in str(authentication.api_key)
    assert raw_key not in repr(asdict(config))
    assert raw_key not in json.dumps(asdict(config), default=str)
    assert raw_key.encode() not in TypeAdapter(StewardAuthenticationConfig).dump_json(authentication)
    with pytest.raises(FrozenInstanceError):
        authentication.api_key = SecretStr("replacement")


def test_omitted_authentication_has_no_environment_or_file_fallback(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("CODEX_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL"):
        monkeypatch.setenv(name, "ignored-ambient-value")
    path = _write_config(tmp_path, "[steward]\n", mode=0o644)
    config = load_config(repo_root=repo, config_path=path)

    def no_reads(*_args, **_kwargs):
        pytest.fail("Codex authentication must not read credential files")

    monkeypatch.setattr(os, "open", no_reads)
    monkeypatch.setattr(Path, "read_bytes", no_reads)
    assert config.authentication == StewardAuthenticationConfig()
    assert config.read_codex_api_key_bytes() is None
    configured = replace(config, authentication=StewardAuthenticationConfig(PROXY, KEY))
    assert configured.read_codex_api_key_bytes() == KEY.encode()
    assert not hasattr(config, "codex_api_key_path")
    assert not hasattr(config, "codex_credential_path")
    assert not hasattr(config.container, "codex_api_key_path")
    assert not hasattr(config.deployment, "codex_credential_path")


def test_loading_inline_authentication_opens_only_configuration_file(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(tmp_path, _authentication_toml())
    opened = []
    original_open = os.open

    def record_open(filename, flags, *args, **kwargs):
        opened.append(filename)
        assert flags & os.O_NOFOLLOW
        assert flags & os.O_NONBLOCK
        return original_open(filename, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", record_open)
    config = load_config(repo_root=repo, config_path=path)
    assert config.read_codex_api_key_bytes() == KEY.encode()
    assert opened == [path]


@pytest.mark.parametrize(
    "contents",
    (
        "[steward.authentication]\n",
        f"[steward.authentication]\napi_key = '{KEY}'\n",
        f"[steward.authentication]\nproxy_url = '{PROXY}'\n",
        "[steward]\nauthentication = false\n",
        "[steward]\nauthentication = []\n",
        f"[steward]\nauthentication = '{KEY}'\n",
        _authentication_toml() + f"'{KEY}' = true\n",
        _authentication_toml() + "token_path = '/not-supported'\n",
        f"[steward.authentication]\nproxy_url = '{PROXY}'\nAPI_KEY = '{KEY}'\n",
        f"[steward.authentication]\nproxy_url = '{PROXY}'\napi-key = '{KEY}'\n",
    ),
)
def test_authentication_requires_exact_nonempty_pair(
    repo: Path, tmp_path: Path, contents: str
) -> None:
    path = _write_config(tmp_path, contents)
    with pytest.raises(ValueError, match="steward.authentication") as error:
        load_config(repo_root=repo, config_path=path)
    assert KEY not in str(error.value)
    assert len(str(error.value)) < 200


@pytest.mark.parametrize(
    "proxy_url",
    (
        None, False, 17, [], {}, "", "proxy.example.test", "//proxy.test/v1",
        "ftp://proxy.test", "http:///v1", "http://:8080", "http://proxy.test:",
        "http://proxy.test:0", "http://proxy.test:-1", "http://proxy.test:65536",
        "http://proxy.test:not-a-port", "http://[::1", "http://[::1]junk:80",
        f"http://proxy.test:{KEY}", f"http://[{KEY}]",
        "http://user@proxy.test", "http://user:password@proxy.test",
        "http://proxy.test/?query=value", "http://proxy.test/?", "http://proxy.test/#",
        "http://proxy.test/#fragment", "http://proxy.test\\v1", "http://invalid%20host",
        "http://proxy..test", "http://-proxy.test", "http://{proxy}",
        " http://proxy.test", "http://proxy.test ", "http://proxy.test/a b",
        "http://proxy.test/\t", "http://proxy.test/\r", "http://proxy.test/\n",
        "http://proxy.test/\x00", "http://proxy.test/\x7f", "http://proxy.test/\x9f",
        "http://proxy.test/\u200b", "http://proxy.test/\ud800",
        "https://proxy.test/" + "a" * 2048,
    ),
)
def test_invalid_proxy_url_is_rejected_without_echo(proxy_url) -> None:
    with pytest.raises(ValueError, match="invalid steward.authentication") as error:
        StewardAuthenticationConfig(proxy_url, KEY)
    assert str(error.value) == "invalid steward.authentication settings"
    assert KEY not in "".join(traceback.format_exception(error.value))


@pytest.mark.parametrize(
    "api_key",
    (
        None, False, 17, b"bytes-not-text", [], {}, "", " ", " leading", "trailing ",
        "two words", "key\n", "key\r", "key\t", "key\x00", "key\x7f", "key\x9f",
        "key\u00a0", "key\u200b", "key\ud800", "k" * 4097, "é" * 2049,
        SecretStr("invalid key"),
    ),
)
def test_invalid_key_is_rejected_without_echo(api_key) -> None:
    with pytest.raises(ValueError, match="invalid steward.authentication") as error:
        StewardAuthenticationConfig(PROXY, api_key)
    assert str(error.value) == "invalid steward.authentication settings"
    rendered = "".join(traceback.format_exception(error.value))
    assert "UnicodeEncodeError" not in rendered
    assert "input_value" not in rendered


@pytest.mark.parametrize(
    "field,value",
    (("proxy_url", False), ("proxy_url", []), ("api_key", 42), ("api_key", {})),
)
def test_toml_authentication_does_not_coerce_types(
    repo: Path, tmp_path: Path, field: str, value: object
) -> None:
    value_text = "{}" if value == {} else json.dumps(value)
    other = f"api_key = '{KEY}'" if field == "proxy_url" else f"proxy_url = '{PROXY}'"
    path = _write_config(tmp_path, f"[steward.authentication]\n{other}\n{field} = {value_text}\n")
    with pytest.raises(ValueError, match="invalid steward.authentication"):
        load_config(repo_root=repo, config_path=path)


@pytest.mark.parametrize("source", ("direct", "toml", "env"))
@pytest.mark.parametrize("profile", ("legacy-profile", " ", KEY + "\n" + "x" * 4096))
def test_legacy_profile_rejected_without_reading_global_config_or_echoing_values(
    repo, tmp_path, monkeypatch, source, profile,
) -> None:
    global_home = tmp_path / "global-home" / ".codex"
    global_home.mkdir(parents=True)
    global_config = global_home / "config.toml"
    global_config.write_text(f"[profiles.legacy-profile]\nmodel = '{KEY}'\n")
    monkeypatch.setenv("HOME", str(global_home.parent))
    monkeypatch.setenv("CODEX_HOME", str(global_home))
    monkeypatch.delenv("COQUIC_STEWARD_CODEX_PROFILE", raising=False)
    path = _write_config(
        tmp_path,
        (f"[steward]\ncodex_profile = {json.dumps(profile)}\n" if source == "toml" else "")
        + _authentication_toml(),
    )
    if source == "env":
        monkeypatch.setenv("COQUIC_STEWARD_CODEX_PROFILE", profile)
    for module in (builtins, io, os):
        original_open = module.open

        def guarded_open(filename, *args, _open=original_open, **kwargs):
            assert filename not in (global_config, str(global_config)), "global Codex config was read"
            return _open(filename, *args, **kwargs)

        monkeypatch.setattr(module, "open", guarded_open)

    with pytest.raises(ValueError, match="codex_profile is no longer supported") as error:
        if source == "direct":
            StewardConfig(
                repo_root=repo, codex_profile=profile,
                authentication=StewardAuthenticationConfig(PROXY, KEY),
            )
        else:
            load_config(repo_root=repo, config_path=path)
    message = str(error.value)
    assert len(message) < 256
    assert KEY not in "".join(traceback.format_exception(error.value))
    assert "legacy-profile" not in message
    for setting in (
        "COQUIC_STEWARD_CODEX_PROFILE", "steward.codex_model",
        "steward.codex_reasoning_effort", "[steward.codex.<stage>]",
        "[steward.authentication]", "proxy_url", "api_key",
    ):
        assert setting in message


@pytest.mark.parametrize("source", ("direct", "toml", "env"))
@pytest.mark.parametrize("profile", (None, ""))
def test_absent_or_empty_legacy_profile_remains_accepted(repo, tmp_path, monkeypatch, source, profile):
    monkeypatch.delenv("COQUIC_STEWARD_CODEX_PROFILE", raising=False)
    if source == "direct":
        config = StewardConfig(repo_root=repo, codex_profile=profile)
    else:
        contents = "[steward]\n"
        if profile is not None:
            if source == "toml":
                contents += 'codex_profile = ""\n'
            else:
                monkeypatch.setenv("COQUIC_STEWARD_CODEX_PROFILE", profile)
        config = load_config(repo_root=repo, config_path=_write_config(tmp_path, contents))
    assert config.codex_profile in (None, "")


@pytest.mark.parametrize(
    "section,key",
    (("container", "codex_api_key_path"), ("deployment", "codex_credential_path")),
)
@pytest.mark.parametrize("inline", (False, True))
def test_legacy_codex_keyfiles_fail_with_bounded_migration_guidance(
    repo: Path, tmp_path: Path, section: str, key: str, inline: bool
) -> None:
    path = _write_config(
        tmp_path,
        (_authentication_toml() if inline else "")
        + f"[steward.{section}]\n{key} = '/{KEY}'\n",
    )
    with pytest.raises(ValueError, match=r"\[steward.authentication\]") as error:
        load_config(repo_root=repo, config_path=path)
    assert KEY not in str(error.value)
    assert len(str(error.value)) < 200
    assert "no longer supported" in str(error.value)


@pytest.mark.parametrize(
    "value",
    (
        {"api_key": KEY},
        {"authentication.api_key": KEY},
        {"authentication": {"api-key": KEY}},
        {"authentication": {"API_KEY": KEY}},
        {"authentication": {"api_key": {"token": KEY}}},
        {"authentication": [{"api_key": KEY}]},
        {"codex": {"api_key": KEY}},
        {"signals": {"authentication": {"api_key": KEY}}},
        {"publication": {"secret": KEY}},
        {"deployment": {"password": KEY}},
    ),
)
def test_inline_secret_exemption_is_exact(value: object) -> None:
    with pytest.raises(ValueError, match="must reference a secret file") as error:
        config_module._reject_embedded_secrets(value)
    assert KEY not in str(error.value)


def test_inline_secret_exemption_preserves_other_secret_path_settings() -> None:
    config_module._reject_embedded_secrets(
        {
            "authentication": {"proxy_url": PROXY, "api_key": KEY},
            "deployment": {"github_token_path": "/unused/token"},
            "publication": {"r2_secret_access_key_path": "/unused/key"},
        }
    )


@pytest.mark.parametrize("mode", (0o400, 0o600))
def test_inline_authentication_accepts_private_config_modes(repo, tmp_path, mode) -> None:
    path = _write_config(tmp_path, _authentication_toml(), mode=mode)
    assert load_config(repo_root=repo, config_path=path).read_codex_api_key_bytes() == KEY.encode()


@pytest.mark.parametrize("mode", (0o444, 0o640, 0o644, 0o660, 0o700, 0o1600))
def test_inline_authentication_rejects_nonprivate_config_modes(repo, tmp_path, mode) -> None:
    path = _write_config(tmp_path, _authentication_toml(), mode=mode)
    with pytest.raises(ValueError, match="mode 0600 or 0400"):
        load_config(repo_root=repo, config_path=path)


def test_inline_authentication_rejects_wrong_owner(repo, tmp_path, monkeypatch) -> None:
    path = _write_config(tmp_path, _authentication_toml())
    monkeypatch.setattr(os, "geteuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(ValueError, match="owned by the current user"):
        load_config(repo_root=repo, config_path=path)


@pytest.mark.parametrize("opened_mode", (0o600, 0o644))
def test_config_validates_and_reads_open_descriptor_not_replaced_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, opened_mode: int
) -> None:
    path = _write_config(tmp_path, _authentication_toml(), mode=opened_mode)
    replacement = tmp_path / "replacement.toml"
    replacement.write_text(_authentication_toml(api_key="replacement-key"))
    replacement.chmod(0o644 if opened_mode == 0o600 else 0o600)
    original_open = os.open

    def open_then_replace(filename, flags):
        descriptor = original_open(filename, flags)
        replacement.replace(path)
        return descriptor

    monkeypatch.setattr(os, "open", open_then_replace)
    if opened_mode == 0o600:
        data = config_module._read_toml(path, required=True)
        assert data["steward"]["authentication"]["api_key"] == KEY
    else:
        with pytest.raises(ValueError, match="mode 0600 or 0400"):
            config_module._read_toml(path, required=True)


@pytest.mark.parametrize("kind", ("symlink", "dangling-symlink", "directory", "fifo"))
@pytest.mark.parametrize("required", (False, True))
def test_config_rejects_nonregular_files_without_blocking(tmp_path, kind, required) -> None:
    path = tmp_path / "unsafe.toml"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        target = tmp_path / "target.toml"
        if kind == "symlink":
            target.write_text("[steward]\n")
        path.symlink_to(target)
    result = subprocess.run(
        [
            sys.executable, "-c",
            "from pathlib import Path; "
            "from coquic_steward.core.config import _read_toml; "
            f"_read_toml(Path({str(path)!r}), required={required!r})",
        ],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0
    assert "ValueError: Steward configuration must be" in result.stderr


def test_nonregular_config_rejection_closes_descriptor(tmp_path, monkeypatch) -> None:
    path = tmp_path / "directory.toml"
    path.mkdir()
    opened = []
    original_open = os.open

    def record_open(filename, flags):
        descriptor = original_open(filename, flags)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", record_open)
    with pytest.raises(ValueError, match="regular file"):
        config_module._read_toml(path, required=True)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_missing_optional_config_remains_credential_free(tmp_path) -> None:
    path = tmp_path / "missing.toml"
    assert config_module._read_toml(path, required=False) == {}
    with pytest.raises(FileNotFoundError):
        config_module._read_toml(path, required=True)


@pytest.mark.parametrize(
    "contents",
    (
        f'[steward.authentication]\napi_key = "{KEY}" invalid\n',
        f'[steward.authentication]\n"api_key-{KEY} = "broken"\n',
        _authentication_toml() + f'"{KEY}" = false\n',
        _authentication_toml() + '[steward.telemetry]\nbilling_mode = "invalid"\n',
        f"[steward]\ncodex_profile = '{KEY}'\n" + _authentication_toml(),
    ),
)
def test_cli_authentication_failures_never_render_values_or_locals(repo, tmp_path, contents) -> None:
    path = _write_config(tmp_path, contents)
    result = subprocess.run(
        [sys.executable, "-m", "coquic_steward.cli", "health", "--store-only"],
        cwd=repo,
        env={**os.environ, "COQUIC_STEWARD_CONFIG_PATH": str(path), "COQUIC_REPOSITORY": str(repo)},
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0
    assert KEY not in result.stdout + result.stderr
    assert "ValueError" in result.stderr
    for app in (cli.app, cli.enqueue_app, cli.publication_app):
        assert app.pretty_exceptions_show_locals is False


@pytest.mark.parametrize("contents", (b'api_key = "' + KEY.encode() + b'" invalid', b'api_key = "\xff"'))
def test_toml_parse_errors_are_sanitized_with_suppressed_context(tmp_path, contents) -> None:
    path = tmp_path / "malformed.toml"
    path.write_bytes(contents)
    with pytest.raises(ValueError, match="invalid Steward TOML configuration") as error:
        config_module._read_toml(path, required=True)
    assert error.value.__suppress_context__
    assert error.value.__cause__ is None
    assert KEY not in "".join(traceback.format_exception(error.value))


@pytest.mark.parametrize("boundary", ("container", "deployment", "both"))
def test_enabled_preflight_requires_authentication_before_other_boundaries(config, boundary) -> None:
    deployment = StewardDeploymentConfig(
        enabled=boundary != "container",
        home=config.coquic_home,
        repository=config.coquic_home / "repository",
        min_free_bytes=1, recovery_free_bytes=2,
        max_owned_docker_bytes=2, recovery_owned_docker_bytes=1,
    )
    container = StewardContainerConfig(
        enabled=boundary != "deployment",
        repository_host_path=config.repo_root,
        state_host_path=config.coquic_home,
    )
    configured = replace(config, container=container, deployment=deployment)
    with pytest.raises(preflight.StewardPreflightError, match=r"\[steward.authentication\]"):
        preflight.run_preflight(configured, check_remote_push=False)


def test_load_allows_container_without_authentication_for_inspection(repo, tmp_path) -> None:
    path = _write_config(tmp_path, "[steward.container]\nenabled = true\n", mode=0o644)
    config = load_config(repo_root=repo, config_path=path)
    assert config.container.enabled
    assert config.read_codex_api_key_bytes() is None


def test_deployment_preflight_keeps_other_credentials_but_no_codex_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repository = home / "repository"
    repository.mkdir(parents=True)
    credential_paths = {}
    for field in ("github_token_path", "git_ssh_key_path", "git_known_hosts_path"):
        path = home / field
        path.write_text("other-credential")
        path.chmod(0o600)
        credential_paths[field] = path
    socket_path = tmp_path / "docker.sock"
    with socket.socket(socket.AF_UNIX) as docker_socket:
        docker_socket.bind(str(socket_path))
        deployment = StewardDeploymentConfig(
            enabled=True, home=home, repository=repository, docker_socket=socket_path,
            min_free_bytes=1, recovery_free_bytes=2,
            max_owned_docker_bytes=2, recovery_owned_docker_bytes=1,
            **credential_paths,
        )
        config = StewardConfig(
            repo_root=repository, deployment=deployment,
            authentication=StewardAuthenticationConfig(PROXY, KEY),
        )
        monkeypatch.setattr(preflight, "_validate_remote_policy", lambda *_: None)

        def command(args, **_kwargs):
            output = "main\n" if args[1] == "symbolic-ref" else ""
            if args[1] == "worktree":
                output = f"worktree {repository}\n"
            return SimpleNamespace(ok=True, stdout=output)

        monkeypatch.setattr(preflight, "run_command", command)
        preflight.run_preflight(config, check_remote_push=False)
        credential_paths["github_token_path"].chmod(0o644)
        with pytest.raises(preflight.StewardPreflightError, match="GitHub API token file permissions"):
            preflight.run_preflight(config, check_remote_push=False)
