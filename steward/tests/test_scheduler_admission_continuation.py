from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from urllib.parse import parse_qs, urlparse

import pytest

from coquic_steward.core.models import (
    ProjectSignals,
    SignalCollectionCursor,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    TaskKind,
    TaskSpec,
    WorkerKind,
    utc_now,
)
from coquic_steward.core.subprocesses import CommandResult
from coquic_steward.orchestration.daemon import (
    StewardDaemon,
    TickResult,
    wait_for_scheduler_event,
)
from coquic_steward.planning import PlannerRun
from coquic_steward.planning.planner import render_planner_prompt
from coquic_steward.planning.verifier import PlanVerifier
from coquic_steward.signals import (
    CodeScanningProvider,
    CodacyProvider,
    collect_signal_items,
)
from coquic_steward.storage import TaskStore, scheduler_state


def _item():
    return SignalItem(
        id="wi-current",
        provider="synthetic",
        kind="synthetic.alert",
        fingerprint="current",
        title="Unique evidence title",
        payload={"detail": "Unique evidence content"},
    )


def _proposal():
    return {
        "dedupe_key": "current",
        "kind": "custom",
        "worker": "custom",
        "title": "Fix finding",
        "prompt": "Fix only this finding",
        "evidence": ["wi-current"],
        "metadata": {"selected_signal_item_ids": ["wi-current"]},
    }


@pytest.mark.parametrize(
    "change",
    [
        {"evidence": ["project"], "metadata": {"selected_signal_item_ids": []}},
        {"evidence": []},
        {"evidence": ["wi-current", "wi-current"]},
        {"metadata": {"selected_signal_item_ids": []}},
        {"metadata": {"selected_signal_item_ids": ["unknown"]}},
        {"metadata": {"selected_signal_item_ids": ["wi-current", "unknown"]}},
        {"metadata": {"selected_signal_item_ids": "wi-current"}},
        {"metadata": {"evidence": ["unknown"]}},
        {"metadata": {"source_context": {"selected_signal_item_ids": ["unknown"]}}},
        {"unknown_field": True},
        {"title": 123},
    ],
)
def test_rejected_proposals_never_consume(change):
    result = PlanVerifier().verify_plan(
        json.dumps(
            {"tasks": [{**_proposal(), **change}], "consumed_item_ids": ["wi-current"]}
        ),
        ProjectSignals(repository="owner/repo", items=[_item()]),
        [],
    )
    assert not result.planned
    assert not result.consumed_item_ids


@pytest.mark.parametrize(
    "envelope",
    [
        {"unknown": True},
        {"consumed_item_ids": ["unknown"]},
        {"consumed_item_ids": ["wi-current", "unknown"]},
        {"consumed_item_ids": "wi-current"},
        {"consumed_item_ids": [1]},
    ],
)
def test_invalid_envelope_is_enforced_in_code(envelope):
    result = PlanVerifier().verify_plan(
        json.dumps({"tasks": [_proposal()], **envelope}),
        ProjectSignals(repository="owner/repo", items=[_item()]),
        [],
    )
    assert result.invalid_output
    assert not result.planned and not result.consumed_item_ids


def test_maintained_defaults_receive_exact_code_authored_context():
    proposal = _proposal()
    proposal.pop("metadata")
    item = _item()
    result = PlanVerifier().verify_plan(
        json.dumps({"tasks": [proposal]}),
        ProjectSignals(repository="owner/repo", items=[item]),
        [],
    )
    metadata = result.planned[0][0].metadata
    assert (
        metadata["evidence"] == metadata["selected_signal_item_ids"] == ["wi-current"]
    )
    assert metadata["source_context"]["selected_signal_item_ids"] == ["wi-current"]
    assert metadata["source_context"]["selected_signal_items"] == [
        item.model_dump(mode="json")
    ]


def test_context_cannot_be_silently_truncated():
    items = [_item().model_copy(update={"id": f"wi-{i}"}) for i in range(9)]
    proposal = {**_proposal(), "evidence": [item.id for item in items], "metadata": {}}
    result = PlanVerifier().verify_plan(
        json.dumps({"tasks": [proposal]}),
        ProjectSignals(repository="owner/repo", items=items),
        [],
    )
    assert not result.planned


def test_prompt_has_one_canonical_evidence_representation(config):
    signals = ProjectSignals(
        repository="owner/repo",
        items=[_item()],
        fetches=[
            SignalFetchRun(
                provider="synthetic",
                status=SignalFetchStatus.ok,
                summary="Unique fetch summary",
            )
        ],
    )
    prompt = render_planner_prompt(signals, [], config)
    for text in (
        "Unique evidence title",
        "Unique evidence content",
        "Unique fetch summary",
    ):
        assert prompt.count(text) == 1


def _ingest(store, item):
    store.ingest_signal_collection(
        SignalFetchRun(provider=item.provider, status=SignalFetchStatus.ok), [item]
    )
    store.consume_wakeups([w.id for w in store.pending_wakeups()])


def test_retry_wakes_without_provider_and_survives_restart(config, monkeypatch):
    config = replace(config, enabled_signals=(), scheduler_wait_interval_sec=60)
    store = TaskStore.create(config.db_path)
    _ingest(store, _item())
    clock = [utc_now().replace(microsecond=0)]
    _, eligible = store.control_loop.schedule_retry(
        "planner", now=clock[0], initial_seconds=7
    )
    store.engine.dispose()
    store = TaskStore.open(config.db_path)
    monkeypatch.setattr("coquic_steward.storage._now", lambda: clock[0])
    monkeypatch.setattr("coquic_steward.orchestration.daemon._now", lambda: clock[0])
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += timedelta(seconds=seconds)

    monkeypatch.setattr("coquic_steward.orchestration.daemon.time.sleep", sleep)
    trigger = wait_for_scheduler_event(config, store)
    assert trigger.reason == "planner-retry" and trigger.providers == []
    assert sleeps == [7]
    assert clock[0] == eligible


@pytest.mark.parametrize(
    "inactive", ["no-work", "capacity", "integration-capacity", "pressure", "blocked"]
)
def test_inactive_retry_does_not_busy_poll(config, monkeypatch, inactive):
    config = replace(config, enabled_signals=(), scheduler_wait_interval_sec=5)
    store = TaskStore.create(config.db_path)
    if inactive != "no-work":
        _ingest(store, _item())
    if inactive in {"capacity", "integration-capacity"}:
        for i in range(config.limits.max_active_tasks):
            store.add_task(
                TaskSpec(
                    kind=(
                        TaskKind.integration
                        if inactive == "integration-capacity"
                        else TaskKind.custom
                    ),
                    worker=(
                        WorkerKind.integration_manager
                        if inactive == "integration-capacity"
                        else WorkerKind.custom
                    ),
                    title=str(i),
                    prompt="P",
                )
            )
        store.consume_wakeups([w.id for w in store.pending_wakeups()])
    if inactive == "pressure":
        store.record_resource_pressure(
            state="resource_pressure", home_free_bytes=0, owned_docker_bytes=None
        )
    if inactive == "blocked":
        store.control_loop.set_planning_blocked(True)
    store.control_loop.schedule_retry("planner", now=utc_now() - timedelta(hours=1))
    assert scheduler_state(config, store).state.planner_retry_at is None
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        store.request_wakeup("test-stop")

    monkeypatch.setattr("coquic_steward.orchestration.daemon.time.sleep", sleep)
    assert wait_for_scheduler_event(config, store).reason == "wakeup"
    assert sleeps == [5]


@pytest.mark.parametrize("output", ["invalid", "rejected", "empty"])
def test_unchanged_no_progress_output_backs_off(config, monkeypatch, output):
    store = TaskStore.create(config.db_path)
    _ingest(store, _item())
    calls = []

    def plan(*args, **kwargs):
        calls.append(kwargs)
        verified = PlanVerifier().verify_plan(
            (
                "not JSON"
                if output == "invalid"
                else json.dumps(
                    {
                        "tasks": (
                            []
                            if output == "empty"
                            else [{**_proposal(), "evidence": ["project"]}]
                        )
                    }
                )
            ),
            ProjectSignals(repository=config.github_repository, items=[_item()]),
            [],
        )
        return PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=len(verified.dispositions),
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.logs_dir / "none.jsonl",
            thread_id=None,
            invalid_output=verified.invalid_output,
            dispositions=verified.dispositions,
        )

    monkeypatch.setattr("coquic_steward.orchestration.daemon.run_planner", plan)
    daemon = StewardDaemon(config, store)
    daemon._plan_until_idle(TickResult())
    retry = store.control_loop.pending_retry("planner")
    assert retry is not None and retry[0] == 1 and retry[1] > utc_now()
    daemon._plan_until_idle(TickResult())
    assert len(calls) == 1
    assert [item.id for item in store.pending_signal_items()] == ["wi-current"]


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return json.dumps(self.payload).encode()


@pytest.mark.parametrize("provider", ["code-scanning", "codacy"])
def test_provider_continuation_ingests_all_open_items_across_restart(
    config, monkeypatch, provider
):
    config = replace(
        config,
        signal_providers={
            **config.signal_providers,
            provider: replace(config.signal_providers[provider], max_items=2),
        },
    )
    requested = []

    def payload(url):
        params = parse_qs(urlparse(url).query)
        page = int(params.get("page", params.get("cursor", ["1"]))[0])
        requested.append(page)
        numbers = list(range(1, 6))[(page - 1) * 2 : page * 2]
        if provider == "code-scanning":
            return [{"number": number, "rule": {"id": "rule"}} for number in numbers]
        return {
            "data": [
                {"filePath": f"file-{number}", "patternId": "rule"}
                for number in numbers
            ],
            "pagination": {"cursor": str(page + 1) if page < 3 else None},
        }

    def command(args, cwd, **kwargs):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload(args[-1])),
            stderr="",
        )

    monkeypatch.setattr("coquic_steward.signals.providers.run_command", command)
    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        lambda request, **kw: _Response(payload(request.full_url)),
    )
    store = TaskStore.create(config.db_path)
    for page in (1, 2, 3, 1):
        # Fresh daemon and Store instances must continue, not sample page one forever.
        daemon = StewardDaemon(config, store)
        result = TickResult()
        daemon._fetch_signals(result, [provider])
        assert result.signal_items <= 2
        assert store.list_signal_fetch_runs(limit=1)[0].has_more == (page < 3)
        cursor = store.signal_collection_cursors([provider])[provider]
        assert (cursor.page if cursor else None) == (page + 1 if page < 3 else None)
        store.engine.dispose()
        store = TaskStore.open(config.db_path)
    assert requested == [1, 2, 3, 1]
    assert len(store.pending_signal_items()) == 5


@pytest.mark.parametrize("provider", [CodeScanningProvider(), CodacyProvider()])
def test_fetch_error_and_ingestion_failure_never_advance_cursor(
    config, monkeypatch, provider
):
    store = TaskStore.create(config.db_path)
    cursor = SignalCollectionCursor(
        page=2, page_size=12, token="next" if provider.name == "codacy" else None
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=provider.name, status=SignalFetchStatus.ok),
        [],
        next_cursor=cursor,
    )
    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        lambda args, cwd, **kw: CommandResult(
            args=args, cwd=cwd, returncode=1, stdout="", stderr="offline"
        ),
    )

    def fail(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr("coquic_steward.signals.providers._open_codacy_request", fail)
    collection = collect_signal_items(
        config, providers=[provider], cursors={provider.name: cursor}
    )[0]
    assert collection.fetch.error and not collection.items
    store.ingest_signal_collection(
        collection.fetch, [], next_cursor=collection.next_cursor
    )
    assert store.signal_collection_cursors([provider.name])[provider.name] == cursor
    monkeypatch.setattr(store.control_loop, "ingest_fetch", fail)
    with pytest.raises(OSError):
        store.ingest_signal_collection(
            SignalFetchRun(provider=provider.name, status=SignalFetchStatus.ok),
            [],
            next_cursor=None,
        )
    assert store.signal_collection_cursors([provider.name])[provider.name] == cursor


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {"data": {}},
        {"data": [None]},
        {
            "data": [{"patternId": "rule", "filePath": "file"}],
            "pagination": {"next": "unknown"},
        },
        {
            "data": [{"patternId": "rule", "filePath": "file"}],
            "pagination": {"cursor": "x" * 2049},
        },
        {"data": [{"patternId": "rule", "filePath": "file"}]},
    ],
)
def test_codacy_malformed_or_unknown_pagination_fails_closed(
    config, monkeypatch, payload
):
    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        lambda *a, **kw: _Response(payload),
    )
    result = CodacyProvider()._collect_issue_search("owner", "repo", None, max_items=1)
    assert result.error and not result.items and result.next_cursor is None


def test_code_scanning_full_page_probes_end_and_errors_fail_closed(config, monkeypatch):
    payloads = [[{"number": 1}], [], {}, [None]]

    def command(args, cwd, **kw):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payloads.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("coquic_steward.signals.providers.run_command", command)
    provider = CodeScanningProvider()
    first = provider.collect(config, max_items=1)
    assert first.has_more and first.next_cursor.page == 2
    last = provider.collect(config, max_items=1, cursor=first.next_cursor)
    assert not last.has_more and last.next_cursor is None
    for _ in range(2):
        result = provider.collect(config)
        assert result.error and not result.items and result.next_cursor is None


@pytest.mark.parametrize("provider", [CodeScanningProvider(), CodacyProvider()])
def test_malformed_page_resets_cursor_only_after_ingestion(
    config, monkeypatch, provider
):
    store = TaskStore.create(config.db_path)
    cursor = SignalCollectionCursor(
        page=2, page_size=12, token="next" if provider.name == "codacy" else None
    )
    store.ingest_signal_collection(
        SignalFetchRun(provider=provider.name, status=SignalFetchStatus.ok),
        [],
        next_cursor=cursor,
    )
    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        lambda args, cwd, **kw: CommandResult(
            args=args, cwd=cwd, returncode=0, stdout="{}", stderr=""
        ),
    )
    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        lambda *a, **kw: _Response({}),
    )
    collection = collect_signal_items(
        config, providers=[provider], cursors={provider.name: cursor}
    )[0]
    assert collection.fetch.error and collection.next_cursor is None
    assert store.signal_collection_cursors([provider.name])[provider.name] == cursor
    store.ingest_signal_collection(
        collection.fetch, [], next_cursor=collection.next_cursor
    )
    assert store.signal_collection_cursors([provider.name])[provider.name] is None


def test_evidence_and_selected_current_ids_must_match():
    first = _item()
    second = first.model_copy(update={"id": "wi-other"})
    result = PlanVerifier().verify_plan(
        json.dumps(
            {
                "tasks": [
                    {
                        **_proposal(),
                        "metadata": {"selected_signal_item_ids": [second.id]},
                    }
                ]
            }
        ),
        ProjectSignals(repository="owner/repo", items=[first, second]),
        [],
    )
    assert not result.planned and not result.consumed_item_ids


def test_codacy_encodes_cursor_and_rejects_nonprogressing_token(config, monkeypatch):
    cursor = SignalCollectionCursor(page=2, page_size=1, token="a&b/c")
    urls = []

    def response(request, **kwargs):
        urls.append(request.full_url)
        return _Response(
            {
                "data": [{"filePath": "file", "patternId": "rule"}],
                "pagination": {"cursor": cursor.token},
            }
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request", response
    )
    result = CodacyProvider()._collect_issue_search(
        "owner", "repo", None, max_items=1, cursor=cursor
    )
    assert urls[0].endswith("&cursor=a%26b%2Fc")
    assert result.error and result.next_cursor is None


@pytest.mark.parametrize("provider", [CodeScanningProvider(), CodacyProvider()])
def test_cursor_bounds_restart_instead_of_skipping(config, monkeypatch, provider):
    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        lambda args, cwd, **kw: CommandResult(
            args=args, cwd=cwd, returncode=0, stdout='[{"number":1}]', stderr=""
        ),
    )
    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        lambda *a, **kw: _Response(
            {"data": [{"filePath": "file"}], "pagination": {"cursor": "next"}}
        ),
    )
    cursor = SignalCollectionCursor(
        page=10000, page_size=1, token="previous" if provider.name == "codacy" else None
    )
    result = provider.collect(config, max_items=1, cursor=cursor)
    assert result.has_more and result.next_cursor is None
    assert len(result.items) == 1


def test_replayed_fetch_cannot_rewind_a_newer_cursor(config):
    store = TaskStore.create(config.db_path)
    first = SignalFetchRun(provider="code-scanning", status=SignalFetchStatus.ok)
    second = SignalFetchRun(provider="code-scanning", status=SignalFetchStatus.ok)
    page_two = SignalCollectionCursor(page=2, page_size=12)
    page_three = SignalCollectionCursor(page=3, page_size=12)
    store.ingest_signal_collection(first, [], next_cursor=page_two)
    store.ingest_signal_collection(second, [], next_cursor=page_three)
    store.ingest_signal_collection(first, [], next_cursor=page_two)
    assert (
        store.signal_collection_cursors(["code-scanning"])["code-scanning"]
        == page_three
    )
