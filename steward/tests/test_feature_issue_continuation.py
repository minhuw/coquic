from dataclasses import replace
import json
import sqlite3
from urllib.parse import parse_qs, urlparse

import pytest

from coquic_steward.core.models import SignalCollectionCursor
from coquic_steward.core.subprocesses import CommandResult
from coquic_steward.orchestration.daemon import StewardDaemon, TickResult
from coquic_steward.signals.providers import (
    GITHUB_FEATURE_ISSUE_LABELS,
    GitHubFeatureIssuesProvider,
)
from coquic_steward.storage import TaskStore


PROVIDER = "github-issues:features"


def _issue(number, labels=GITHUB_FEATURE_ISSUE_LABELS):
    return {
        "number": number,
        "title": f"Feature {number}",
        "state": "open",
        "html_url": f"https://github.com/minhuw/coquic/issues/{number}",
        "url": f"https://api.github.com/repos/minhuw/coquic/issues/{number}",
        "labels": [{"name": label} for label in labels],
        "user": {"login": "alice"},
        "body": "Implement this scoped feature.",
        "created_at": "2026-06-01T00:00:00Z",
        "updated_at": "2026-06-02T00:00:00Z",
    }


def _command(monkeypatch, payload):
    def command(args, cwd, **kwargs):
        return CommandResult(
            args=args, cwd=cwd, returncode=0, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr("coquic_steward.signals.providers.run_command", command)


def test_both_label_backlogs_progress_across_restart_and_dedupe_overlap(
    config, monkeypatch
):
    config = replace(
        config,
        signal_providers={
            **config.signal_providers,
            PROVIDER: replace(config.signal_providers[PROVIDER], max_items=2),
        },
    )
    numbers = [[1, 2, 3, 4, 5], [3, 6, 7, 8, 9]]
    requests = []
    failure = [False]

    def command(args, cwd, **kwargs):
        assert args[:4] == ["gh", "api", "-X", "GET"]
        endpoint = urlparse(args[-1])
        assert endpoint.path == "repos/minhuw/coquic/issues"
        query = parse_qs(endpoint.query)
        assert query["state"] == ["open"]
        assert query["sort"] == ["created"] and query["direction"] == ["asc"]
        assert query["per_page"] == ["2"]
        label = GITHUB_FEATURE_ISSUE_LABELS.index(query["labels"][0])
        page = int(query["page"][0])
        requests.append((label, page))
        if failure[0]:
            failure[0] = False
            return CommandResult(
                args=args, cwd=cwd, returncode=1, stdout="", stderr="offline"
            )
        payload = [
            _issue(number) for number in numbers[label][(page - 1) * 2 : page * 2]
        ]
        return CommandResult(
            args=args, cwd=cwd, returncode=0, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr("coquic_steward.signals.providers.run_command", command)
    store = TaskStore.create(config.db_path)
    for turn in range(8):
        if turn == 1:
            failure[0] = True
        previous = store.signal_collection_cursors([PROVIDER])[PROVIDER]
        result = TickResult()
        StewardDaemon(config, store)._fetch_signals(result, [PROVIDER])
        assert result.signal_items <= 2
        current = store.signal_collection_cursors([PROVIDER])[PROVIDER]
        if turn == 1:
            assert current == previous
        if turn == 6:
            assert current is None
        store.engine.dispose()
        store = TaskStore.open(config.db_path)
    assert requests == [(0, 1), (1, 1), (1, 1), (0, 2), (1, 2), (0, 3), (1, 3), (0, 1)]
    items = store.pending_signal_items()
    assert sorted(item.payload["issue_number"] for item in items) == list(range(1, 10))
    assert all(item.payload["author"] == "alice" for item in items)
    assert all(item.payload["created_at"] == "2026-06-01T00:00:00Z" for item in items)
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM control_loop_signals").fetchone()[0] == 9
        )


def test_full_page_probes_end_and_does_not_restart_finished_label(config, monkeypatch):
    provider = GitHubFeatureIssuesProvider()
    _command(monkeypatch, [_issue(1)])
    first = provider.collect(config, max_items=1)
    assert first.next_cursor == SignalCollectionCursor(page=1, page_size=1, token="1:2")
    _command(monkeypatch, [])
    second = provider.collect(config, max_items=1, cursor=first.next_cursor)
    assert second.next_cursor == SignalCollectionCursor(
        page=2, page_size=1, token="0:0"
    )
    _command(monkeypatch, [_issue(2)])
    third = provider.collect(config, max_items=1, cursor=second.next_cursor)
    assert third.next_cursor == SignalCollectionCursor(page=3, page_size=1, token="0:0")
    _command(monkeypatch, [])
    last = provider.collect(config, max_items=1, cursor=third.next_cursor)
    assert not last.has_more and last.next_cursor is None


@pytest.mark.parametrize(
    "token", ["https://evil.test", "2:1", "0:-1", "1:10001", "0:1:2", "０:1"]
)
def test_invalid_cursor_never_becomes_request(config, monkeypatch, token):
    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        lambda *a, **k: pytest.fail("invalid cursor reached network"),
    )
    result = GitHubFeatureIssuesProvider().collect(
        config, cursor=SignalCollectionCursor(page_size=12, token=token)
    )
    assert result.error and not result.items and result.next_cursor is None


@pytest.mark.parametrize(
    "change",
    [
        {"state": "closed"},
        {"labels": [{"name": "unrelated"}]},
        {"number": True},
        {"html_url": "https://github.com/other/repo/issues/1"},
        {"url": "https://api.github.com/repos/other/repo/issues/1"},
        {"body": {}},
        {"title": None},
    ],
)
def test_rest_scope_and_identity_fail_closed_without_advancing(
    config, monkeypatch, change
):
    cursor = SignalCollectionCursor(page=2, page_size=12, token="0:3")
    _command(monkeypatch, [{**_issue(1), **change}])
    result = GitHubFeatureIssuesProvider().collect(config, cursor=cursor)
    assert result.error and not result.items and result.next_cursor == cursor


def test_prs_do_not_become_features_but_still_advance_page(config, monkeypatch):
    _command(
        monkeypatch,
        [
            {
                **_issue(1),
                "pull_request": {
                    "url": "https://api.github.com/repos/minhuw/coquic/pulls/1"
                },
                "html_url": "https://github.com/minhuw/coquic/pull/1",
            }
        ],
    )
    result = GitHubFeatureIssuesProvider().collect(config, max_items=1)
    assert not result.items
    assert result.has_more and result.next_cursor.page == 1


def test_issue_identity_survives_label_and_title_changes(config, monkeypatch):
    provider = GitHubFeatureIssuesProvider()
    _command(monkeypatch, [_issue(1)])
    first = provider.collect(config).items[0]
    _command(
        monkeypatch,
        [
            {
                **_issue(1, [GITHUB_FEATURE_ISSUE_LABELS[1]]),
                "title": "Edited",
                "body": "Updated",
            }
        ],
    )
    second = provider.collect(
        config, cursor=SignalCollectionCursor(page_size=12, token="1:0")
    ).items[0]
    assert first.id == second.id and first.fingerprint == second.fingerprint
    assert second.payload["issue_title"] == "Edited"
    assert second.payload["body_excerpt"] == "Updated"
