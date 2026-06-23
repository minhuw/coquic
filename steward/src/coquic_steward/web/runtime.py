from __future__ import annotations

import os
import http.client
import ipaddress
import json
import signal
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8765
DEFAULT_UI_HOST = "127.0.0.1"
DEFAULT_UI_PORT = 3000


@dataclass(frozen=True)
class _ResolvedCommand:
    args: tuple[str, ...]


class _TrustedProcess(subprocess.Popen[str]):
    def __init__(
        self,
        command: _ResolvedCommand,
        *,
        cwd: Path | None,
        env: dict[str, str] | None,
        output: object,
    ):
        super().__init__(
            list(command.args),
            cwd=cwd,
            env=env,
            shell=False,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=os.name != "nt",
        )


class StewardWebRuntime:
    def __init__(
        self,
        *,
        api_host: str = DEFAULT_API_HOST,
        api_port: int = DEFAULT_API_PORT,
        web_ui_dir: Path | None = None,
        log_dir: Path | None = None,
    ):
        self.api_host = api_host
        self.api_port = api_port
        self.web_ui_dir = web_ui_dir or default_web_ui_dir()
        self.log_dir = log_dir
        self._api_process: subprocess.Popen[str] | None = None
        self._ui_process: subprocess.Popen[str] | None = None

    @property
    def api_url(self) -> str:
        return f"http://{self.api_host}:{self.api_port}"

    @property
    def ui_url(self) -> str:
        return f"http://{DEFAULT_UI_HOST}:{DEFAULT_UI_PORT}"

    def __enter__(self) -> StewardWebRuntime:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def start(self) -> None:
        if not self.web_ui_dir.exists():
            raise RuntimeError(f"web UI directory does not exist: {self.web_ui_dir}")
        try:
            if not _api_ready(self.api_url):
                if _api_responding(self.api_url):
                    raise RuntimeError(
                        "incompatible Steward API is already running at "
                        f"{self.api_url}; stop the stale API process and restart "
                        "the daemon"
                    )
                self._api_process = _popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "coquic_steward.web.app:create_app",
                        "--factory",
                        "--host",
                        self.api_host,
                        "--port",
                        str(self.api_port),
                    ],
                    log_path=self._log_path("api.log"),
                )
                _wait_until_ready(
                    self._api_process,
                    "Steward API",
                    lambda: _api_ready(self.api_url),
                )
            if not _ui_ready(self.ui_url):
                _clear_next_cache(self.web_ui_dir)
                self._ui_process = _popen(
                    ["npm", "run", "dev"],
                    cwd=self.web_ui_dir,
                    env={
                        **os.environ,
                        "STEWARD_API_URL": self.api_url,
                    },
                    log_path=self._log_path("web-ui.log"),
                )
                _wait_until_ready(
                    self._ui_process,
                    "Steward web UI",
                    lambda: _ui_ready(self.ui_url),
                    timeout_seconds=45,
                )
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        _stop_process(self._ui_process)
        _stop_process(self._api_process)
        self._ui_process = None
        self._api_process = None

    def _log_path(self, name: str) -> Path | None:
        if self.log_dir is None:
            return None
        path = self.log_dir / "web" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


def default_web_ui_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "web-ui"


def _clear_next_cache(web_ui_dir: Path) -> None:
    cache_dir = web_ui_dir / ".next"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)


def _popen(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    log_path: Path | None = None,
) -> subprocess.Popen[str]:
    safe_command = _resolve_command(command, cwd=cwd, env=env)
    try:
        with ExitStack() as stack:
            output = (
                stack.enter_context(log_path.open("a", encoding="utf-8"))
                if log_path is not None
                else subprocess.DEVNULL
            )
            return _TrustedProcess(
                safe_command,
                cwd=cwd,
                env=env,
                output=output,
            )
    except FileNotFoundError as exc:
        raise RuntimeError(f"unable to start {command[0]!r}: command not found") from exc


def _resolve_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> _ResolvedCommand:
    if not command:
        raise RuntimeError("unable to start process: command is empty")
    if not all(isinstance(part, str) and part for part in command):
        raise RuntimeError(
            "unable to start process: command arguments must be non-empty strings"
        )
    executable = command[0]
    path = Path(executable)
    if path.parent != Path("."):
        if not path.is_absolute() and cwd is not None:
            path = cwd / path
        trusted_path = _validated_executable_path(path, executable)
    else:
        trusted_path = _resolve_bare_executable(executable, cwd=cwd, env=env)
    return _ResolvedCommand((trusted_path, *command[1:]))


def _resolve_bare_executable(
    executable: str,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> str:
    resolved_text = shutil.which(
        executable,
        path=os.pathsep.join(_path_entries_for_child_cwd(cwd=cwd, env=env)),
    )
    if resolved_text is None:
        raise RuntimeError(f"unable to start {executable!r}: command not found")
    return _validated_executable_path(Path(resolved_text), executable)


def _path_entries_for_child_cwd(
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> list[str]:
    child_cwd = cwd if cwd is not None else Path.cwd()
    if not child_cwd.is_absolute():
        child_cwd = Path.cwd() / child_cwd
    entries: list[str] = []
    for entry in os.get_exec_path(env):
        search_dir = Path(entry) if entry else Path(".")
        if not search_dir.is_absolute():
            search_dir = child_cwd / search_dir
        entries.append(str(search_dir))
    return entries


def _validated_executable_path(path: Path, executable: str) -> str:
    absolute_path = path if path.is_absolute() else Path.cwd() / path
    if not absolute_path.exists():
        raise RuntimeError(f"unable to start {executable!r}: command not found")
    if not absolute_path.is_file() or not os.access(absolute_path, os.X_OK):
        raise RuntimeError(f"unable to start {executable!r}: command is not executable")
    return str(absolute_path)


def _wait_until_ready(
    process: subprocess.Popen[str],
    label: str,
    ready: Callable[[], bool],
    *,
    timeout_seconds: int = 20,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            raise RuntimeError(f"{label} exited during startup with code {exit_code}")
        if ready():
            return
        time.sleep(0.25)
    raise RuntimeError(f"{label} did not become ready within {timeout_seconds}s")


def _stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        process.terminate()
    else:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def _api_responding(api_url: str) -> bool:
    return _read_url(f"{api_url}/healthz") is not None


def _api_ready(api_url: str) -> bool:
    if _read_url(f"{api_url}/healthz") != "ok":
        return False
    runtime = _read_json(f"{api_url}/api/runtime")
    features = runtime.get("features") if isinstance(runtime, dict) else None
    required = {"line-tail", "signal-inbox", "signal-items-v2"}
    return isinstance(features, list) and required.issubset(set(features))


def _ui_ready(ui_url: str) -> bool:
    body = _read_url(ui_url)
    return body is not None and "CoQUIC Steward" in body


def _read_url(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or not _is_loopback_host(parsed.hostname)
    ):
        return None
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    try:
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=1)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            if response.status >= 500:
                return None
            return response.read(4096).decode("utf-8", errors="replace")
        finally:
            connection.close()
    except (OSError, ValueError, http.client.HTTPException):
        return None


def _is_loopback_host(hostname: str) -> bool:
    if hostname.casefold().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _read_json(url: str) -> object:
    text = _read_url(url)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
