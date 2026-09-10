"""Offline authentication checks: synthetic keys and executable stubs only."""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

from coquic_steward.agents.invocation import InvocationOutcome, InvocationRequest, launch_local
from coquic_steward.agents.runner import CodexRunner
from coquic_steward.core.config import StewardAuthenticationConfig
from coquic_steward.core.models import CodexStage, TaskKind, TaskSpec, WorkerKind
from coquic_steward.execution.session import FreshPlannerSession, LocalSessionInvoker, SessionSupervisor
from coquic_steward.storage import TaskStore


PROXY_URL = "http://127.0.0.1:12345/v1"
SYNTHETIC_KEY = "synthetic-inline-key"


@pytest.fixture
def authenticated_config(config):
    return replace(
        config,
        authentication=StewardAuthenticationConfig(proxy_url=PROXY_URL, api_key=SYNTHETIC_KEY),
        codex_model="test-model",
        codex_reasoning_effort="high",
    )


def _assert_provider(args, proxy_url=PROXY_URL):
    overrides = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "--config"]
    assert [value for value in overrides if value.startswith("model_provider")] == [
        'model_provider="steward"',
        'model_providers.steward.name="Steward proxy"',
        f"model_providers.steward.base_url={json.dumps(proxy_url)}",
        'model_providers.steward.wire_api="responses"',
        'model_providers.steward.env_key="CODEX_API_KEY"',
        'model_providers.steward.requires_openai_auth=false',
    ]
    assert SYNTHETIC_KEY not in repr(args)


@pytest.mark.parametrize("stage", list(CodexStage))
@pytest.mark.parametrize("resume", [None, "exact-provider-session"])
def test_provider_overrides_preserve_stage_and_resume_options(authenticated_config, stage, resume):
    config = authenticated_config
    schema = config.private_dir / "schema.json"
    last = config.private_dir / "last.md"
    request = InvocationRequest(
        codex_bin=config.codex_bin, cwd=config.repo_root, prompt="synthetic", stage=stage,
        output_last_message=last, output_schema=schema, model="test-model",
        reasoning_effort="high", provider_session_id=resume, proxy_url=PROXY_URL,
        sandbox="read-only",
    )
    legacy = CodexRunner(config)._args(
        config.repo_root, last, output_schema=schema, resume_session=resume,
        stage=stage, sandbox="read-only",
    )
    for args in (request.argv(), legacy):
        _assert_provider(args)
        assert any(
            args[index:index + 2] == ["--config", 'shell_environment_policy.inherit="none"']
            for index in range(len(args) - 1)
        )
        assert args[:2] == [config.codex_bin, "exec"]
        assert "--profile" not in args
        assert "--dangerously-bypass-approvals-and-sandbox" not in args
        assert args[args.index("--model") + 1] == "test-model"
        assert 'model_reasoning_effort="high"' in args
        assert ("--dangerously-bypass-hook-trust" in args) == (stage == CodexStage.code)
        assert args[args.index("--output-schema") + 1] == str(schema)
        assert args[args.index("--output-last-message") + 1] == str(last)
        if resume:
            assert args[2] == "resume"
            assert args[-2:] == [resume, "-"]
            assert "--cd" not in args and "--sandbox" not in args
        else:
            assert args[args.index("--cd") + 1] == str(config.repo_root)
            assert args[args.index("--sandbox") + 1] == "read-only"
            assert args[-1] == "-"
    assert ("--skip-git-repo-check" in request.argv()) == (stage == CodexStage.signal_planner)
    assert not any(value.startswith("model_provider") for value in replace(request, proxy_url=None).argv())


@pytest.mark.parametrize("stage", list(CodexStage))
@pytest.mark.parametrize("resume", [None, "exact-provider-session"])
def test_container_argv_uses_external_sandbox_only(config, stage, resume):
    request = InvocationRequest(
        codex_bin="codex", cwd=config.repo_root, prompt="synthetic", stage=stage,
        output_last_message=config.private_dir / "last.md", sandbox="read-only",
        provider_session_id=resume,
    )
    args = request.argv(externally_sandboxed=True)
    assert args.count("--dangerously-bypass-approvals-and-sandbox") == 1
    assert "--sandbox" not in args
    assert ("--cd" in args) == (resume is None)
    assert args[-1] == "-"
    if resume:
        assert args[2] == "resume"
        assert args[-2] == resume
    else:
        assert args[args.index("--cd") + 1] == str(config.repo_root)
    assert "--dangerously-bypass-approvals-and-sandbox" not in request.argv()


def test_provider_url_is_json_escaped(config):
    url = 'https://proxy.invalid/v1/"quoted"\\path'
    request = InvocationRequest(
        codex_bin="fake", cwd=config.repo_root, prompt="synthetic", stage=CodexStage.code,
        output_last_message=config.private_dir / "last.md", proxy_url=url,
    )
    _assert_provider(request.argv(), url)
    override = next(arg for arg in request.argv() if arg.startswith("model_providers.steward.base_url="))
    assert tomllib.loads(override)["model_providers"]["steward"]["base_url"] == url


class RecordingInvoker(LocalSessionInvoker):
    def __init__(self):
        super().__init__()
        self.requests = []
        self.keys = []
        self.interrupted = False

    def invoke(self, request, *, api_key, append, **kwargs):
        self.requests.append(request)
        self.keys.append(api_key)
        request.output_last_message.write_text("done\n", encoding="utf-8")
        append(b'{"type":"completed"}\n')
        return InvocationOutcome(
            exit_code=130 if self.interrupted else 0, stdout=b"", stderr=b"",
            incomplete_suffix=b"", events=(), provider_session_id="exact-provider-session",
            interrupted=self.interrupted,
        )


@pytest.mark.parametrize("supplied", [None, "explicit-fixture-key", b"explicit-fixture-key"])
def test_fresh_planner_uses_config_unless_key_explicitly_supplied(authenticated_config, monkeypatch, supplied):
    monkeypatch.setenv("CODEX_API_KEY", "ambient-must-not-win")
    invoker = RecordingInvoker()
    result = FreshPlannerSession(authenticated_config, invoker=invoker).run(
        "planner-run", prompt="synthetic", api_key=supplied,
    )
    assert result.outcome.completed
    assert invoker.keys == [supplied if supplied is not None else SYNTHETIC_KEY.encode()]
    _assert_provider(invoker.requests[0].argv())
    assert invoker.requests[0].role == "planner"
    assert not list(result.request.home.rglob("auth.json"))
    assert all(SYNTHETIC_KEY.encode() not in path.read_bytes()
               for path in result.request.home.rglob("*") if path.is_file())


@pytest.mark.parametrize("role,stage", [
    ("planner", CodexStage.implementation_plan),
    ("implementation", CodexStage.code),
    ("reviewer", CodexStage.review),
])
@pytest.mark.parametrize("follow_up", ["resume", "recover"])
def test_tasks_use_inline_auth_for_start_resume_and_recovery(authenticated_config, monkeypatch, role, stage, follow_up):
    config = authenticated_config
    monkeypatch.setenv("CODEX_API_KEY", "ambient-must-not-win")
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="auth", prompt="synthetic"))
    invoker = RecordingInvoker()
    invoker.interrupted = True
    supervisor = SessionSupervisor(config, store, invoker=invoker, image_digest="sha256:" + "a" * 64)
    first = supervisor.start(
        task.id, store.list_pipelines(task.id)[0].id, role=role, stage=stage,
        prompt="synthetic", cwd=config.repo_root, checkpoint_id="exact-checkpoint",
    )
    session = store.get_session(first.session_id)
    (session.private_home_path / "sessions" / "provider.json").write_text("{}")
    invoker.interrupted = False
    if follow_up == "resume":
        result = supervisor.resume(first.run_id, prompt="continue", checkpoint_id="exact-checkpoint")
        assert invoker.requests[-1].provider_session_id == "exact-provider-session"
    else:
        result = supervisor.recover(first.run_id)
        assert invoker.requests[-1].provider_session_id is None
        assert result.result.session_id != first.session_id
    assert result.category.value == "success"
    assert invoker.keys == [SYNTHETIC_KEY.encode()] * 2
    for request in invoker.requests:
        _assert_provider(request.argv())
        assert request.role == role
        assert SYNTHETIC_KEY not in repr(request)
    assert not list(config.private_sessions_dir.rglob("auth.json"))
    for root in (config.private_sessions_dir, config.tasks_dir):
        assert all(SYNTHETIC_KEY.encode() not in path.read_bytes()
                   for path in root.rglob("*") if path.is_file())


@pytest.mark.parametrize("harness", [False, True])
def test_keyless_supervisor_does_not_consult_environment(config, monkeypatch, harness):
    monkeypatch.setenv("CODEX_API_KEY", "ambient-must-not-win")
    supervisor = SessionSupervisor(replace(config, local_codex_test_harness=harness), None, invoker=LocalSessionInvoker())
    assert supervisor._configured_api_key(None) is None
    assert supervisor._configured_api_key(b"explicit-fixture") == b"explicit-fixture"


def _fake_codex(tmp_path, key):
    """Assert the key in memory; publish only nonsecret launch observations."""
    fake = tmp_path / "fake-codex"
    digest = hashlib.sha256(key).hexdigest() if key is not None else None
    fake.write_text(
        f"#!{sys.executable}\n"
        "import hashlib, json, os, pathlib, stat, sys\n"
        "key = os.environ.get('CODEX_API_KEY')\n"
        "assert 'OPENAI_API_KEY' not in os.environ\n"
        f"assert (hashlib.sha256(key.encode()).hexdigest() if key is not None else None) == {digest!r}\n"
        "home = pathlib.Path(os.environ['CODEX_HOME'])\n"
        "assert home.is_dir()\n"
        "assert stat.S_IMODE(home.stat().st_mode) == 0o700\n"
        "assert not (home / 'auth.json').exists()\n"
        "assert not (home / 'config.toml').exists()\n"
        "sys.stdin.buffer.read()\n"
        "last = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
        "last.write_text('done\\n')\n"
        "print(json.dumps({'args': sys.argv[1:], 'home': str(home), 'hook': os.environ.get('COQUIC_STEWARD_HOOK_CONTEXT')}))\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


@pytest.mark.parametrize("existing_home", [False, True])
@pytest.mark.parametrize("key", [None, "synthetic-utf8-\u00e9", b"synthetic-utf8-\xc3\xa9"])
def test_local_launch_uses_explicit_key_and_private_home(config, tmp_path, monkeypatch, key, existing_home):
    expected = key.encode() if isinstance(key, str) else key
    fake = _fake_codex(tmp_path, expected)
    monkeypatch.setenv("CODEX_API_KEY", "ambient-must-not-win")
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-upstream-must-not-win")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "ambient-home"))
    request = InvocationRequest(
        codex_bin=str(fake), cwd=config.repo_root, prompt="synthetic", stage=CodexStage.code,
        output_last_message=config.private_dir / "local" / "last.md", proxy_url=PROXY_URL if key else None,
    )
    if existing_home:
        home = request.output_last_message.parent
        home.mkdir()
        home.chmod(0o755)
    process = launch_local(request, api_key=key)
    stdout, stderr = process.communicate(b"synthetic\n", timeout=5)
    assert process.returncode == 0, stderr
    observed = json.loads(stdout)
    assert observed["home"] == str(request.output_last_message.parent)
    if key:
        _assert_provider(observed["args"])
        assert expected not in stdout + stderr + request.output_last_message.read_bytes()
    assert not list(config.private_dir.rglob("auth.json"))


def test_local_supervisor_resumes_fake_codex_store_with_authentication(
    authenticated_config, tmp_path, monkeypatch,
):
    provider_id = "01958f6e-65f4-7bd4-bb54-890253078c2d"
    key_digest = hashlib.sha256(SYNTHETIC_KEY.encode()).hexdigest()
    fake = tmp_path / "resumable-codex"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import hashlib, json, os, pathlib, sys, time\n"
        "assert 'OPENAI_API_KEY' not in os.environ\n"
        f"assert hashlib.sha256(os.environ['CODEX_API_KEY'].encode()).hexdigest() == {key_digest!r}\n"
        "home = pathlib.Path(os.environ['CODEX_HOME'])\n"
        "assert not (home / 'auth.json').exists()\n"
        "sessions = home / 'sessions'\n"
        "sessions.mkdir(exist_ok=True)\n"
        f"provider_id = {provider_id!r}\n"
        "session_file = sessions / ('rollout-' + provider_id + '.jsonl')\n"
        "resume = sys.argv[2] == 'resume'\n"
        "if resume:\n"
        "    assert sys.argv[-2] == provider_id\n"
        "    assert json.loads(session_file.read_text())['payload']['id'] == provider_id\n"
        "else:\n"
        "    session_file.write_text(json.dumps({'type': 'session_meta', 'payload': {'id': provider_id}}) + '\\n')\n"
        "sys.stdin.buffer.read()\n"
        "print(json.dumps({'type': 'thread.started', 'thread_id': provider_id, 'home': str(home), 'args': sys.argv[1:]}), flush=True)\n"
        "if not resume:\n"
        "    time.sleep(60)\n"
        "last = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
        "last.write_text('resumed\\n')\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = replace(authenticated_config, codex_bin=str(fake))
    monkeypatch.setenv("CODEX_API_KEY", "ambient-must-not-win")
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-upstream-must-not-win")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "ambient-home"))
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="resume", prompt="synthetic")
    )
    supervisor = SessionSupervisor(
        config, store, invoker=LocalSessionInvoker(), image_digest="sha256:" + "a" * 64,
    )
    first = supervisor.start(
        task.id, store.list_pipelines(task.id)[0].id, role="implementation",
        prompt="synthetic", cwd=config.repo_root, checkpoint_id="exact-checkpoint",
        timeout_seconds=2,
    )
    assert store.get_run(first.run_id).state == "interrupted"
    session = store.get_session(first.session_id)
    assert session.provider_session_id == provider_id
    observed = json.loads(first.transcript_path.read_text())
    assert observed["home"] == str(session.private_home_path)
    session_file = session.private_home_path / "sessions" / f"rollout-{provider_id}.jsonl"
    assert json.loads(session_file.read_text())["payload"]["id"] == provider_id
    assert not (session.private_home_path / "codex-home").exists()

    resumed = supervisor.resume(
        first.run_id, prompt="continue", checkpoint_id="exact-checkpoint", timeout_seconds=5,
    )
    assert resumed.category.value == "success"
    assert resumed.result.session_id == first.session_id
    assert store.get_run(resumed.result.run_id).resume_of_run_id == first.run_id
    resumed_observed = json.loads(resumed.result.transcript_path.read_text())
    assert resumed_observed["home"] == observed["home"]
    assert resumed_observed["args"][:2] == ["exec", "resume"]
    assert resumed_observed["args"][-2:] == [provider_id, "-"]
    for invocation in (observed, resumed_observed):
        _assert_provider(invocation["args"])
    assert resumed.result.last_message_path.read_text() == "resumed\n"
    assert not list(session.private_home_path.rglob("auth.json"))
    for root in (config.private_sessions_dir, config.tasks_dir):
        assert all(SYNTHETIC_KEY.encode() not in path.read_bytes()
                   for path in root.rglob("*") if path.is_file())


def test_local_launch_rejects_invalid_utf8_before_popen(config, monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: pytest.fail("invalid key launched process"))
    request = InvocationRequest(codex_bin="fake", cwd=config.repo_root, prompt="synthetic",
                                stage=CodexStage.code, output_last_message=config.private_dir / "last.md")
    with pytest.raises(UnicodeDecodeError):
        launch_local(request, api_key=b"\xff")


@pytest.mark.parametrize("existing_home", [False, True])
@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("stage", [CodexStage.code, CodexStage.review])
def test_legacy_runner_uses_config_and_preserves_capture_environment(config, authenticated_config, tmp_path, monkeypatch, configured, stage, existing_home):
    config = authenticated_config if configured else config
    key = SYNTHETIC_KEY.encode() if configured else None
    fake = _fake_codex(tmp_path, key)
    config = replace(config, codex_bin=str(fake))
    monkeypatch.setenv("CODEX_API_KEY", "ambient-must-not-win")
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-upstream-must-not-win")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "ambient-home"))
    monkeypatch.setenv("COQUIC_STEWARD_HOOK_CONTEXT", "ambient-hook-must-not-win")
    task, _ = TaskStore.create(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="auth", prompt="synthetic")
    )
    runner = CodexRunner(config)
    if existing_home:
        home = runner.paths(task)[1].parent / "codex-home"
        home.mkdir(parents=True)
        home.chmod(0o755)
    result = runner.run(task, "synthetic", config.repo_root, stage=stage)
    assert result.completed
    observed = json.loads(result.transcript_path.read_text())
    assert observed["home"] == str(result.last_message_path.parent / "codex-home")
    assert observed["hook"] == (str(result.transcript_path.parent / "tool-changes" / "context.json") if stage == CodexStage.code else None)
    if configured:
        _assert_provider(result.command)
    assert SYNTHETIC_KEY not in repr(result)
    assert not list(config.transcripts_dir.rglob("auth.json"))
    assert all(SYNTHETIC_KEY.encode() not in path.read_bytes()
               for path in config.transcripts_dir.rglob("*") if path.is_file())


@pytest.mark.parametrize("launch", ["local", "legacy"])
@pytest.mark.parametrize("kind", ["home-link", "parent-link", "auth-file", "auth-link", "dangling-auth-link"])
def test_launch_rejects_linked_homes_and_persisted_auth_before_popen(
    authenticated_config, tmp_path, monkeypatch, launch, kind,
):
    config = authenticated_config
    runner = CodexRunner(config)
    task, _ = TaskStore.create(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="auth", prompt="synthetic")
    )
    last = runner.paths(task)[1] if launch == "legacy" else config.private_dir / "local" / "home" / "last.md"
    home = last.parent / "codex-home" if launch == "legacy" else last.parent
    home.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o751)
    target = outside / "sentinel"
    sentinel = b"synthetic-persisted-login-secret"
    target.write_bytes(sentinel)
    before = outside.stat(), target.stat()
    if kind == "home-link":
        home.symlink_to(outside, target_is_directory=True)
    elif kind == "parent-link":
        home.parent.rmdir()
        home.parent.symlink_to(outside, target_is_directory=True)
    else:
        home.mkdir()
        auth = home / "auth.json"
        if kind == "auth-file":
            auth.write_bytes(sentinel)
        else:
            auth.symlink_to(target if kind == "auth-link" else outside / "missing")
    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: pytest.fail("unsafe home launched process"))
    with pytest.raises((OSError, RuntimeError)) as caught:
        if launch == "local":
            request = InvocationRequest(
                codex_bin="fake", cwd=config.repo_root, prompt="synthetic",
                stage=CodexStage.review, output_last_message=last,
            )
            launch_local(request, api_key=config.read_codex_api_key_bytes())
        else:
            runner.run(task, "synthetic", config.repo_root, stage=CodexStage.review)
    if kind.startswith("auth") or kind == "dangling-auth-link":
        assert str(caught.value) == "auth.json is forbidden in private Codex homes"
    assert SYNTHETIC_KEY not in str(caught.value)
    assert sentinel.decode() not in str(caught.value)
    assert outside.stat().st_mode == before[0].st_mode
    assert target.stat().st_atime_ns == before[1].st_atime_ns
    assert target.stat().st_mode == before[1].st_mode
    assert target.read_bytes() == sentinel
    assert list(outside.iterdir()) == [target]
    assert not (home / "config.toml").exists()
