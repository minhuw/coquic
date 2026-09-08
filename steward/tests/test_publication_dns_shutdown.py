"""Real HTTP stacks with only the OS resolver stalled; no provider traffic."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from coquic_steward.core.config import StewardConfig
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.orchestration.transport import (
    BotocoreR2TransportAdapter,
    HttpxD1TransportAdapter,
)
from coquic_steward.publication import publisher as publisher_module
from coquic_steward.publication.d1 import D1PublicationClient
from coquic_steward.publication.publisher import CloudPublisher, PublicationStatus
from coquic_steward.publication.r2 import R2Client
from test_cloud_publisher import (
    IDENTITY,
    NOW,
    POLICY,
    _SQLitePublicationProvider,
    _compose_generation,
    _sqlite_generation,
    _sqlite_store,
)


SHUTDOWN_GRACE = 1.0


def _start_stalled_dns(tmp_path, monkeypatch, backend):
    store = _sqlite_store(tmp_path / "dns.sqlite")
    store.enqueue_publication(_sqlite_generation())
    renewals = []
    renew_lease = store.renew_publication_lease

    def observed_renew_lease(*args, **kwargs):
        renewals.append(kwargs)
        return renew_lease(*args, **kwargs)

    monkeypatch.setattr(store, "renew_publication_lease", observed_renew_lease)
    config = StewardConfig(repo_root=tmp_path, dry_run=False, local_codex_test_harness=True)
    object.__setattr__(config, "shutdown_grace_seconds", SHUTDOWN_GRACE)
    daemon = StewardDaemon(config, store)
    store.claim_daemon_instance(daemon.runtime.instance_id, lifecycle="running")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    endpoint = f"http://publication.example.test:{listener.getsockname()[1]}"
    entered, release, stopped = threading.Event(), threading.Event(), threading.Event()
    resolver_threads = []

    def stalled_dns(*_args, **_kwargs):
        resolver_threads.append(threading.current_thread())
        entered.set()
        release.wait()  # Deliberately no timeout, including in the exit test.
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", listener.getsockname())]

    monkeypatch.setattr(socket, "getaddrinfo", stalled_dns)
    provider = _SQLitePublicationProvider()
    if backend == "httpx":
        client = httpx.Client(trust_env=False)
        d1 = D1PublicationClient(
            account_id="a" * 32,
            database_id="00000000-0000-4000-8000-000000000000",
            token="test-token", http_client=client, timeout_seconds=0.05,
        )
        monkeypatch.setattr(D1PublicationClient, "endpoint", property(lambda _self: endpoint))
        adapter = HttpxD1TransportAdapter(d1)
        # The envelope fixture is synthetic; exercise D1's real request boundary
        # at staging without replacing HTTPX, httpcore, or their network backend.
        monkeypatch.setattr(d1, "stage", lambda _payload: d1._post([("SELECT 1", ())]))
        r2 = provider
    else:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3", endpoint_url=endpoint,
            aws_access_key_id="test-key", aws_secret_access_key="test-secret",
            region_name="auto",
            config=Config(
                connect_timeout=0.05, read_timeout=0.05, proxies={},
                retries={"max_attempts": 0, "mode": "standard"},
            ),
        )
        r2 = R2Client(
            endpoint="https://publication.example.test",
            public_bucket="publication-public", private_bucket="publication-private",
            client=client,
        )
        adapter = BotocoreR2TransportAdapter(r2)
        d1 = provider
    work_items = []
    renew = publisher_module._LeaseWork._renew

    def observe_renew(work, generation):
        if not work_items:
            work_items.append(work)
        renew(work, generation)
        if work.failure is not None:
            stopped.set()

    monkeypatch.setattr(publisher_module._LeaseWork, "_renew", observe_renew)
    publisher = CloudPublisher(
        store, r2, d1, "worker-1", compose=_compose_generation(), now=lambda: NOW,
        lease_seconds=9, retry_policy=POLICY, cancel_event=daemon._publication_stop,
    )
    results, errors = [], []

    def publish():
        try:
            results.append(publisher.publish(IDENTITY.publication_id, source={"stable": True}))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=publish, name="dns-publication-owner", daemon=True)
    daemon._publication_thread = worker
    daemon._publication_cancel = adapter
    worker.start()
    assert entered.wait(5), errors
    row = store.get_publication_generation(IDENTITY.publication_id)
    receipts = store.list_publication_receipts(IDENTITY.publication_id)
    return SimpleNamespace(
        daemon=daemon, store=store, listener=listener, release=release, stopped=stopped,
        worker=worker, resolver_threads=resolver_threads, work_items=work_items,
        adapter=adapter, client=client, results=results, errors=errors,
        row=row, receipts=receipts, renewals=renewals,
    )


def _shutdown_unresolved(op):
    started = time.monotonic()
    result = op.daemon.shutdown()
    assert time.monotonic() - started < SHUTDOWN_GRACE + 0.5
    assert result.state.value == "stopping"
    assert op.daemon.lifecycle_state.value == "stopping"
    state = op.store.get_daemon_state()
    assert state["lifecycle"] == "stopping"
    assert state.get("publication_worker_stopped") is not True
    assert op.stopped.is_set()
    assert op.worker.is_alive()
    assert op.daemon._publication_thread is op.worker
    assert not op.results and not op.errors
    assert op.store.get_publication_generation(IDENTITY.publication_id) == op.row
    assert op.store.list_publication_receipts(IDENTITY.publication_id) == op.receipts


@pytest.mark.parametrize("backend", ["httpx", "botocore"])
def test_dns_release_after_cancel_cannot_publish(tmp_path, monkeypatch, backend):
    op = _start_stalled_dns(tmp_path, monkeypatch, backend)
    try:
        _shutdown_unresolved(op)
        renewals = len(op.renewals)
        assert len(op.resolver_threads) == 1
        assert op.resolver_threads[0].daemon
        assert op.resolver_threads[0] is op.work_items[0].worker
        op.release.set()
        # A late TCP connect may finish, but the adapter must close it before
        # sending HTTP bytes (including any upload or subsequent HEAD request).
        connection, _address = op.listener.accept()
        with connection:
            connection.settimeout(2)
            assert connection.recv(65536) == b""
        op.worker.join(3)
        assert not op.worker.is_alive()
        assert not op.work_items[0].worker.is_alive()
        assert not op.errors
        assert len(op.results) == 1
        assert op.results[0].status is PublicationStatus.blocked
        assert op.store.get_publication_generation(IDENTITY.publication_id) == op.row
        assert op.store.list_publication_receipts(IDENTITY.publication_id) == op.receipts
        assert len(op.renewals) == renewals
        assert len(op.resolver_threads) == 1
    finally:
        op.release.set()
        op.worker.join(3)
        op.adapter.close()
        op.client.close()
        op.listener.close()
        op.store.engine.dispose()


@pytest.mark.parametrize("backend", ["httpx", "botocore"])
def test_process_exits_with_dns_still_blocked(tmp_path, backend):
    import select

    script = """
import sys
from pathlib import Path
import pytest
from test_publication_dns_shutdown import _start_stalled_dns, _shutdown_unresolved
patch = pytest.MonkeyPatch()
patch.setenv('COQUIC_HOME', str(Path(sys.argv[1]) / 'home'))
op = _start_stalled_dns(Path(sys.argv[1]), patch, sys.argv[2])
print('ready', flush=True)
assert sys.stdin.readline() == 'stop\\n'
_shutdown_unresolved(op)
assert not op.release.is_set()
print('unresolved', flush=True)
# No resolver release, cleanup, os._exit(), or forced signal: normal Python exit.
"""
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", script, str(tmp_path), backend],
        cwd=Path(__file__).parent, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert select.select([process.stdout], [], [], 10)[0], "child did not start"
        assert process.stdout.readline() == "ready\n"
        started = time.monotonic()
        stdout, stderr = process.communicate("stop\n", timeout=SHUTDOWN_GRACE + 0.75)
        assert time.monotonic() - started < SHUTDOWN_GRACE + 0.75
        assert process.returncode == 0, stderr
        assert stdout == "unresolved\n"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=3)
