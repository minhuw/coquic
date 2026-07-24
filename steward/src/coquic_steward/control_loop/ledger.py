"""Private SQLite ledger for the scheduler control loop.

This module intentionally uses a small dedicated SQLite connection.  The
existing task ledger remains authoritative for task execution; this ledger
records the causal scheduler graph and is joined to tasks by stable IDs.  All
mutating operations are idempotent and allocate archive sequence values while
holding ``BEGIN IMMEDIATE``.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from ..core.models import SignalFetchRun, SignalItem
from .models import (
    CONTROL_LOOP_FORMAT_VERSION,
    CONTROL_LOOP_POLICY,
    CanonicalSignal,
    Cycle,
    Event,
    EventKind,
    GraphEdge,
    Observation,
    PlannerRun,
    ProposalDisposition,
    SignalFetch,
    Wakeup,
    new_id,
    timestamp,
    utc_now,
    validate_id,
)


class LedgerConflictError(RuntimeError):
    """An immutable identity or graph relation conflicts with stored bytes."""


class LedgerBlockedError(RuntimeError):
    """Planning is blocked by a shared epoch or visible archive conflict."""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return default
    return parsed


def _dt(value: str | datetime | None = None) -> str:
    return timestamp(value)


class ControlLoopLedger:
    """Transactional graph ledger and ordered archive outbox."""

    format_version = CONTROL_LOOP_FORMAT_VERSION
    policy = CONTROL_LOOP_POLICY

    def __init__(self, database: Path | str | Any, *, epoch_id: str | None = None):
        path = getattr(database, "path", database)
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._epoch_id = validate_id(epoch_id) if epoch_id else None
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS control_loop_meta (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS control_loop_fetches (
                  fetch_id TEXT PRIMARY KEY,
                  epoch_id TEXT NOT NULL,
                  provider TEXT NOT NULL,
                  status TEXT NOT NULL,
                  started_at TEXT NOT NULL,
                  completed_at TEXT NOT NULL,
                  item_count INTEGER NOT NULL CHECK(item_count >= 0),
                  new_item_count INTEGER NOT NULL CHECK(new_item_count >= 0),
                  has_more INTEGER NOT NULL CHECK(has_more IN (0, 1)),
                  error TEXT,
                  summary TEXT NOT NULL,
                  normalized_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS control_loop_signals (
                  signal_id TEXT PRIMARY KEY,
                  epoch_id TEXT NOT NULL,
                  provider TEXT NOT NULL,
                  fingerprint TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('pending','planned','superseded','errored')),
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  normalized_json TEXT NOT NULL,
                  UNIQUE(epoch_id, provider, fingerprint)
                );
                CREATE TABLE IF NOT EXISTS control_loop_observations (
                  observation_id TEXT PRIMARY KEY,
                  fetch_id TEXT NOT NULL REFERENCES control_loop_fetches(fetch_id),
                  signal_id TEXT NOT NULL REFERENCES control_loop_signals(signal_id),
                  provider TEXT NOT NULL,
                  fingerprint TEXT NOT NULL,
                  dedupe_result TEXT NOT NULL CHECK(dedupe_result IN ('new','existing')),
                  observed_at TEXT NOT NULL,
                  normalized_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS control_loop_wakeups (
                  wakeup_id TEXT PRIMARY KEY,
                  epoch_id TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('pending','consumed')),
                  created_at TEXT NOT NULL,
                  consumed_at TEXT,
                  input_signal_ids_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS control_loop_cycles (
                  cycle_id TEXT PRIMARY KEY,
                  epoch_id TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  started_at TEXT NOT NULL,
                  completed_at TEXT,
                  runtime_state TEXT NOT NULL,
                  input_signal_ids_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS control_loop_planner_runs (
                  planner_run_id TEXT PRIMARY KEY,
                  epoch_id TEXT NOT NULL,
                  state TEXT NOT NULL CHECK(state IN ('claimed','running','succeeded','failed','interrupted','cancelled')),
                  started_at TEXT NOT NULL,
                  completed_at TEXT,
                  input_signal_ids_json TEXT NOT NULL,
                  active_task_ids_json TEXT NOT NULL,
                  prompt_json TEXT,
                  result_json TEXT,
                  diagnostics_json TEXT NOT NULL,
                  retry_eligible_at TEXT,
                  attempt INTEGER NOT NULL CHECK(attempt >= 1),
                  UNIQUE(epoch_id, planner_run_id)
                );
                CREATE TABLE IF NOT EXISTS control_loop_proposals (
                  proposal_id TEXT PRIMARY KEY,
                  planner_run_id TEXT NOT NULL REFERENCES control_loop_planner_runs(planner_run_id),
                  ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
                  outcome TEXT NOT NULL CHECK(outcome IN ('accepted','invalid','policy_rejected','duplicate','capacity_skipped')),
                  reason_code TEXT NOT NULL,
                  signal_ids_json TEXT NOT NULL,
                  dedupe_key TEXT,
                  task_id TEXT,
                  proposal_json TEXT NOT NULL,
                  UNIQUE(planner_run_id, ordinal)
                );
                CREATE TABLE IF NOT EXISTS control_loop_edges (
                  edge_id TEXT PRIMARY KEY,
                  epoch_id TEXT NOT NULL,
                  edge_type TEXT NOT NULL,
                  source_id TEXT NOT NULL,
                  target_id TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  UNIQUE(edge_type, source_id, target_id)
                );
                CREATE TABLE IF NOT EXISTS control_loop_events (
                  sequence INTEGER PRIMARY KEY,
                  event_id TEXT NOT NULL UNIQUE,
                  epoch_id TEXT NOT NULL,
                  occurred_at TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS control_loop_outbox (
                  sequence INTEGER PRIMARY KEY REFERENCES control_loop_events(sequence),
                  event_id TEXT NOT NULL UNIQUE,
                  payload_json TEXT NOT NULL,
                  materialized_at TEXT
                );
                CREATE TABLE IF NOT EXISTS control_loop_retry (
                  key TEXT PRIMARY KEY,
                  attempt INTEGER NOT NULL CHECK(attempt >= 0),
                  eligible_at TEXT,
                  updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_control_loop_observations_signal
                  ON control_loop_observations(signal_id, observed_at);
                CREATE INDEX IF NOT EXISTS ix_control_loop_events_epoch_sequence
                  ON control_loop_events(epoch_id, sequence);
                CREATE INDEX IF NOT EXISTS ix_control_loop_outbox_pending
                  ON control_loop_outbox(materialized_at, sequence);
                """
            )
            existing = db.execute(
                "SELECT value FROM control_loop_meta WHERE key='epoch_id'"
            ).fetchone()
            if existing is None:
                selected = self._epoch_id or new_id("epoch")
                db.execute(
                    "INSERT INTO control_loop_meta(key,value) VALUES('epoch_id',?)",
                    (selected,),
                )
            else:
                selected = existing[0]
                if self._epoch_id is not None and selected != self._epoch_id:
                    raise LedgerConflictError("control-loop epoch id mismatch")
            self._epoch_id = selected
            db.execute(
                "INSERT OR IGNORE INTO control_loop_meta(key,value) VALUES('next_sequence','0')"
            )
            db.execute(
                "INSERT OR IGNORE INTO control_loop_meta(key,value) VALUES('planning_blocked','0')"
            )

    @property
    def epoch_id(self) -> str:
        assert self._epoch_id is not None
        return self._epoch_id

    @property
    def planning_blocked(self) -> bool:
        with self._connect() as db:
            row = db.execute(
                "SELECT value FROM control_loop_meta WHERE key='planning_blocked'"
            ).fetchone()
        return bool(row and row[0] == "1")

    def set_planning_blocked(self, blocked: bool, *, reason: str | None = None) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO control_loop_meta(key,value) VALUES('planning_blocked',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("1" if blocked else "0",),
            )
            if reason:
                db.execute(
                    "INSERT INTO control_loop_meta(key,value) VALUES('planning_block_reason',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (reason[:512],),
                )
            db.commit()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _next_sequence(self, db: sqlite3.Connection) -> int:
        row = db.execute(
            "SELECT value FROM control_loop_meta WHERE key='next_sequence'"
        ).fetchone()
        sequence = int(row[0]) if row else 0
        db.execute(
            "INSERT INTO control_loop_meta(key,value) VALUES('next_sequence',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(sequence + 1),),
        )
        return sequence

    def _event(
        self,
        db: sqlite3.Connection,
        kind: str,
        payload: Mapping[str, Any],
        *,
        event_id: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> Event:
        selected_id = validate_id(event_id or new_id("event"))
        sequence = self._next_sequence(db)
        event = Event(
            eventId=selected_id,
            epochId=self.epoch_id,
            sequence=sequence,
            occurredAt=_dt(occurred_at),
            kind=kind,
            payload=dict(payload),
        )
        values = event.model_dump(by_alias=True, mode="json")
        db.execute(
            "INSERT INTO control_loop_events(sequence,event_id,epoch_id,occurred_at,kind,payload_json) VALUES(?,?,?,?,?,?)",
            (sequence, selected_id, self.epoch_id, values["occurredAt"], kind, _json(values["payload"])),
        )
        db.execute(
            "INSERT INTO control_loop_outbox(sequence,event_id,payload_json) VALUES(?,?,?)",
            (sequence, selected_id, _json(values)),
        )
        return event

    def ingest_fetch(
        self,
        fetch: SignalFetch | SignalFetchRun,
        observations: Iterable[Observation | SignalItem],
        *,
        wakeup: Wakeup | None = None,
    ) -> tuple[list[Observation], list[CanonicalSignal]]:
        """Persist a fetch and every normalized observation in one transaction."""

        fetch_value = _signal_fetch(fetch)
        normalized_observations = [_observation(item, fetch_value.fetch_id) for item in observations]
        signals: list[CanonicalSignal] = []
        saved: list[Observation] = []
        with self.transaction() as db:
            existing_fetch = db.execute(
                "SELECT normalized_json FROM control_loop_fetches WHERE fetch_id=?",
                (fetch_value.fetch_id,),
            ).fetchone()
            fetch_json = fetch_value.model_dump(by_alias=True, mode="json")
            if existing_fetch is not None and _loads(existing_fetch[0], {}) != fetch_json:
                raise LedgerConflictError(f"fetch {fetch_value.fetch_id} conflicts with stored bytes")
            if existing_fetch is None:
                db.execute(
                    "INSERT INTO control_loop_fetches(fetch_id,epoch_id,provider,status,started_at,completed_at,item_count,new_item_count,has_more,error,summary,normalized_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        fetch_value.fetch_id,
                        self.epoch_id,
                        fetch_value.provider,
                        fetch_value.status,
                        _dt(fetch_value.started_at),
                        _dt(fetch_value.completed_at),
                        fetch_value.item_count,
                        fetch_value.new_item_count,
                        int(fetch_value.has_more),
                        fetch_value.error,
                        fetch_value.summary,
                        _json(fetch_json),
                    ),
                )
                self._event(db, EventKind.fetch_finished.value, {"fetch": fetch_json})
            for observation in normalized_observations:
                signal_row = db.execute(
                    "SELECT signal_id,status,created_at,updated_at,normalized_json FROM control_loop_signals WHERE epoch_id=? AND provider=? AND fingerprint=?",
                    (self.epoch_id, observation.provider, observation.fingerprint),
                ).fetchone()
                if signal_row is None:
                    signal = CanonicalSignal(
                        signalId=new_id("signal"),
                        provider=observation.provider,
                        fingerprint=observation.fingerprint,
                        status="pending",
                    )
                    signal_json = signal.model_dump(by_alias=True, mode="json")
                    db.execute(
                        "INSERT INTO control_loop_signals(signal_id,epoch_id,provider,fingerprint,status,created_at,updated_at,normalized_json) VALUES(?,?,?,?,?,?,?,?)",
                        (signal.signal_id, self.epoch_id, signal.provider, signal.fingerprint, signal.status, _dt(signal.created_at), _dt(signal.updated_at), _json(signal_json)),
                    )
                    self._event(db, EventKind.signal_created.value, {"signal": signal_json})
                    dedupe = "new"
                else:
                    signal = CanonicalSignal(
                        signalId=signal_row[0],
                        provider=observation.provider,
                        fingerprint=observation.fingerprint,
                        status=signal_row[1],
                        createdAt=signal_row[2],
                        updatedAt=signal_row[3],
                    )
                    dedupe = "existing"
                observation = observation.model_copy(
                    update={"canonical_signal_id": signal.signal_id, "dedupe_result": dedupe}
                )
                observation_json = observation.model_dump(by_alias=True, mode="json")
                previous = db.execute(
                    "SELECT normalized_json FROM control_loop_observations WHERE observation_id=?",
                    (observation.observation_id,),
                ).fetchone()
                if previous is not None:
                    if _loads(previous[0], {}) != observation_json:
                        raise LedgerConflictError(f"observation {observation.observation_id} conflicts with stored bytes")
                else:
                    db.execute(
                        "INSERT INTO control_loop_observations(observation_id,fetch_id,signal_id,provider,fingerprint,dedupe_result,observed_at,normalized_json) VALUES(?,?,?,?,?,?,?,?)",
                        (observation.observation_id, observation.fetch_id, signal.signal_id, observation.provider, observation.fingerprint, dedupe, _dt(observation.observed_at), _json(observation_json)),
                    )
                    self._event(db, EventKind.observation.value, {"observation": observation_json})
                    self._edge(db, "observation_signal", observation.observation_id, signal.signal_id)
                saved.append(observation)
                signals.append(signal)
            if wakeup is not None:
                self._insert_wakeup(db, wakeup)
        return saved, signals

    def _edge(self, db: sqlite3.Connection, edge_type: str, source: str, target: str) -> GraphEdge:
        existing = db.execute(
            "SELECT edge_id,epoch_id,created_at FROM control_loop_edges WHERE edge_type=? AND source_id=? AND target_id=?",
            (edge_type, source, target),
        ).fetchone()
        if existing is not None:
            return GraphEdge(edgeId=existing[0], edgeType=edge_type, sourceId=source, targetId=target, createdAt=existing[2])
        edge = GraphEdge(edgeId=new_id("edge"), edgeType=edge_type, sourceId=source, targetId=target)
        db.execute(
            "INSERT INTO control_loop_edges(edge_id,epoch_id,edge_type,source_id,target_id,created_at) VALUES(?,?,?,?,?,?)",
            (edge.edge_id, self.epoch_id, edge.edge_type, edge.source_id, edge.target_id, _dt(edge.created_at)),
        )
        self._event(db, EventKind.edge.value, {"edge": edge.model_dump(by_alias=True, mode="json")})
        return edge

    def add_edge(self, edge_type: str, source_id: str, target_id: str) -> GraphEdge:
        with self.transaction() as db:
            return self._edge(db, edge_type, validate_id(source_id), validate_id(target_id))

    def _insert_wakeup(self, db: sqlite3.Connection, wakeup: Wakeup) -> None:
        payload = wakeup.model_dump(by_alias=True, mode="json")
        existing = db.execute(
            "SELECT input_signal_ids_json,reason,status FROM control_loop_wakeups WHERE wakeup_id=?",
            (wakeup.wakeup_id,),
        ).fetchone()
        if existing is not None:
            if _loads(existing[0], []) != wakeup.input_signal_ids or existing[1] != wakeup.reason:
                raise LedgerConflictError(f"wakeup {wakeup.wakeup_id} conflicts with stored bytes")
            return
        db.execute(
            "INSERT INTO control_loop_wakeups(wakeup_id,epoch_id,reason,status,created_at,consumed_at,input_signal_ids_json) VALUES(?,?,?,?,?,?,?)",
            (wakeup.wakeup_id, self.epoch_id, wakeup.reason, wakeup.status, _dt(wakeup.created_at), _dt(wakeup.consumed_at) if wakeup.consumed_at else None, _json(wakeup.input_signal_ids)),
        )
        self._event(db, EventKind.wakeup.value, {"wakeup": payload})

    def record_wakeup(self, wakeup: Wakeup) -> Wakeup:
        with self.transaction() as db:
            self._insert_wakeup(db, wakeup)
        return wakeup

    def record_cycle(self, cycle: Cycle) -> Cycle:
        with self.transaction() as db:
            payload = cycle.model_dump(by_alias=True, mode="json")
            existing = db.execute(
                "SELECT reason,started_at,input_signal_ids_json,completed_at,runtime_state "
                "FROM control_loop_cycles WHERE cycle_id=?",
                (cycle.cycle_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing[0] != cycle.reason
                    or existing[1] != _dt(cycle.started_at)
                    or _loads(existing[2], []) != cycle.input_signal_ids
                ):
                    raise LedgerConflictError(f"cycle {cycle.cycle_id} conflicts with stored bytes")
                if existing[3] is not None and cycle.completed_at is None:
                    return cycle.model_copy(
                        update={"completed_at": existing[3], "runtime_state": existing[4]}
                    )
                db.execute(
                    "UPDATE control_loop_cycles SET completed_at=?,runtime_state=? WHERE cycle_id=?",
                    (_dt(cycle.completed_at) if cycle.completed_at else existing[3], cycle.runtime_state, cycle.cycle_id),
                )
            else:
                db.execute(
                    "INSERT INTO control_loop_cycles(cycle_id,epoch_id,reason,started_at,completed_at,runtime_state,input_signal_ids_json) VALUES(?,?,?,?,?,?,?)",
                    (cycle.cycle_id, self.epoch_id, cycle.reason, _dt(cycle.started_at), _dt(cycle.completed_at) if cycle.completed_at else None, cycle.runtime_state, _json(cycle.input_signal_ids)),
                )
            event_id = f"cycle-event-{cycle.cycle_id}-{cycle.runtime_state}"
            if db.execute("SELECT 1 FROM control_loop_events WHERE event_id=?", (event_id,)).fetchone() is None:
                self._event(db, EventKind.cycle.value, {"cycle": payload}, event_id=event_id)
        return cycle

    def record_runtime(self, state: str, payload: Mapping[str, Any] | None = None) -> Event:
        """Append one bounded daemon runtime transition to the event ledger."""

        with self.transaction() as db:
            return self._event(
                db,
                EventKind.runtime.value,
                {"state": state, **dict(payload or {})},
            )

    def claim_planner_run(
        self,
        planner_run_id: str,
        signal_ids: Iterable[str],
        active_task_ids: Iterable[str] = (),
        *,
        prompt: Mapping[str, Any] | None = None,
        attempt: int = 1,
    ) -> PlannerRun:
        run_id = validate_id(planner_run_id)
        selected_signals = [validate_id(value) for value in signal_ids]
        selected_tasks = [validate_id(value) for value in active_task_ids]
        with self.transaction() as db:
            existing = db.execute(
                "SELECT * FROM control_loop_planner_runs WHERE planner_run_id=?",
                (run_id,),
            ).fetchone()
            if existing is not None:
                saved = _planner_from_row(existing)
                if (
                    saved.epoch_id != self.epoch_id
                    or saved.input_signal_ids != selected_signals
                    or saved.active_task_ids != selected_tasks
                    or (saved.prompt or None) != (dict(prompt) if prompt is not None else None)
                ):
                    raise LedgerConflictError(
                        f"planner run {run_id} conflicts with its claimed inputs"
                    )
                return saved
            for signal_id in selected_signals:
                if db.execute("SELECT 1 FROM control_loop_signals WHERE signal_id=?", (signal_id,)).fetchone() is None:
                    raise LedgerConflictError(f"planner input signal does not exist: {signal_id}")
            started = utc_now()
            run = PlannerRun(
                plannerRunId=run_id,
                epochId=self.epoch_id,
                state="claimed",
                startedAt=started,
                inputSignalIds=selected_signals,
                activeTaskIds=selected_tasks,
                prompt=dict(prompt) if prompt is not None else None,
            )
            values = run.model_dump(by_alias=True, mode="json")
            db.execute(
                "INSERT INTO control_loop_planner_runs(planner_run_id,epoch_id,state,started_at,completed_at,input_signal_ids_json,active_task_ids_json,prompt_json,result_json,diagnostics_json,retry_eligible_at,attempt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, self.epoch_id, run.state, _dt(started), None, _json(selected_signals), _json(selected_tasks), _json(values["prompt"]) if values["prompt"] is not None else None, None, "{}", None, attempt),
            )
            self._event(db, EventKind.planner_started.value, {"plannerRun": values})
            for signal_id in selected_signals:
                self._edge(db, "signal_planner_run", signal_id, run_id)
        return run

    def complete_planner_run(
        self,
        planner_run_id: str,
        dispositions: Iterable[ProposalDisposition | Mapping[str, Any]],
        *,
        state: str = "succeeded",
        result: Mapping[str, Any] | None = None,
        diagnostics: Mapping[str, Any] | None = None,
        retry_after: timedelta | None = None,
        consume_signal_ids: Iterable[str] = (),
    ) -> PlannerRun:
        run_id = validate_id(planner_run_id)
        values = [
            item if isinstance(item, ProposalDisposition) else ProposalDisposition.model_validate(item)
            for item in dispositions
        ]
        if state not in {"succeeded", "failed", "interrupted", "cancelled"}:
            raise ValueError(f"invalid terminal planner state: {state}")
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM control_loop_planner_runs WHERE planner_run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise KeyError(run_id)
            if row["state"] in {"succeeded", "failed", "interrupted", "cancelled"}:
                return _planner_from_row(row)
            ordinals = [item.ordinal for item in values]
            if ordinals != list(range(1, len(ordinals) + 1)):
                raise LedgerConflictError("planner proposal ordinals must be contiguous")
            input_signal_ids = set(_loads(row["input_signal_ids_json"], []))
            for item in values:
                if item.planner_run_id != run_id:
                    raise LedgerConflictError("proposal belongs to another planner run")
                if not set(item.signal_ids).issubset(input_signal_ids):
                    raise LedgerConflictError(
                        "proposal cites a signal outside the planner input set"
                    )
                payload = item.model_dump(by_alias=True, mode="json")
                db.execute(
                    "INSERT INTO control_loop_proposals(proposal_id,planner_run_id,ordinal,outcome,reason_code,signal_ids_json,dedupe_key,task_id,proposal_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (item.proposal_id, run_id, item.ordinal, item.outcome, item.reason_code, _json(item.signal_ids), item.dedupe_key, item.task_id, _json(payload["proposal"])),
                )
                self._event(db, EventKind.proposal.value, {"proposal": payload})
                self._edge(db, "planner_proposal", run_id, item.proposal_id)
                for signal_id in item.signal_ids:
                    self._edge(db, "signal_proposal", signal_id, item.proposal_id)
                if item.task_id is not None:
                    self._edge(db, "proposal_task", item.proposal_id, item.task_id)
            consume = {validate_id(value) for value in consume_signal_ids}
            if not consume.issubset(input_signal_ids):
                raise LedgerConflictError(
                    "planner completion consumes a signal outside its input set"
                )
            for signal_id in consume:
                db.execute(
                    "UPDATE control_loop_signals SET status='planned',updated_at=? WHERE signal_id=? AND status='pending'",
                    (_dt(), signal_id),
                )
            completed = utc_now()
            retry_at = completed + retry_after if retry_after is not None else None
            db.execute(
                "UPDATE control_loop_planner_runs SET state=?,completed_at=?,result_json=?,diagnostics_json=?,retry_eligible_at=? WHERE planner_run_id=?",
                (state, _dt(completed), _json(dict(result or {})), _json(dict(diagnostics or {})), _dt(retry_at) if retry_at else None, run_id),
            )
            self._event(
                db,
                EventKind.planner_finished.value,
                {"plannerRunId": run_id, "state": state, "result": dict(result or {}), "diagnostics": dict(diagnostics or {})},
                event_id=f"planner-finished-{run_id}",
            )
            row = db.execute("SELECT * FROM control_loop_planner_runs WHERE planner_run_id=?", (run_id,)).fetchone()
        assert row is not None
        return _planner_from_row(row)

    def list_events(self, *, after_sequence: int = -1, limit: int | None = None) -> list[Event]:
        sql = "SELECT * FROM control_loop_events WHERE sequence>? ORDER BY sequence"
        params: list[Any] = [after_sequence]
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        return [
            Event(
                eventId=row["event_id"],
                epochId=row["epoch_id"],
                sequence=row["sequence"],
                occurredAt=row["occurred_at"],
                kind=row["kind"],
                payload=_loads(row["payload_json"], {}),
            )
            for row in rows
        ]

    def outbox(self, *, limit: int = 100, include_materialized: bool = False) -> list[dict[str, Any]]:
        predicate = "" if include_materialized else " WHERE materialized_at IS NULL"
        with self._connect() as db:
            rows = db.execute(
                f"SELECT sequence,event_id,payload_json,materialized_at FROM control_loop_outbox{predicate} ORDER BY sequence LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {"sequence": row[0], "event_id": row[1], "event": _loads(row[2], {}), "materialized_at": row[3]}
            for row in rows
        ]

    def mark_materialized(self, sequence: int, *, event_id: str) -> bool:
        with self.transaction() as db:
            row = db.execute(
                "SELECT event_id,materialized_at FROM control_loop_outbox WHERE sequence=?",
                (sequence,),
            ).fetchone()
            if row is None:
                raise KeyError(sequence)
            if row[0] != event_id:
                raise LedgerConflictError("outbox event identity mismatch")
            if row[1] is not None:
                return False
            db.execute(
                "UPDATE control_loop_outbox SET materialized_at=? WHERE sequence=?",
                (_dt(), sequence),
            )
            return True

    def pending_retry(self, key: str) -> tuple[int, datetime | None] | None:
        with self._connect() as db:
            row = db.execute("SELECT attempt,eligible_at FROM control_loop_retry WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        eligible = datetime.fromisoformat(row[1].replace("Z", "+00:00")) if row[1] else None
        return int(row[0]), eligible

    def schedule_retry(self, key: str, *, initial_seconds: int = 30, max_seconds: int = 300, now: datetime | None = None) -> tuple[int, datetime]:
        selected_now = now or utc_now()
        with self.transaction() as db:
            row = db.execute("SELECT attempt FROM control_loop_retry WHERE key=?", (key,)).fetchone()
            attempt = int(row[0]) + 1 if row else 1
            delay = min(max_seconds, initial_seconds * (2 ** (attempt - 1)))
            eligible = selected_now + timedelta(seconds=delay)
            db.execute(
                "INSERT INTO control_loop_retry(key,attempt,eligible_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET attempt=excluded.attempt,eligible_at=excluded.eligible_at,updated_at=excluded.updated_at",
                (key, attempt, _dt(eligible), _dt(selected_now)),
            )
        return attempt, eligible

    def reset_retry(self, key: str) -> None:
        with self.transaction() as db:
            db.execute("DELETE FROM control_loop_retry WHERE key=?", (key,))

    def list_proposals(self, planner_run_id: str) -> list[ProposalDisposition]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM control_loop_proposals WHERE planner_run_id=? ORDER BY ordinal", (planner_run_id,)).fetchall()
        return [
            ProposalDisposition(
                proposalId=row["proposal_id"], plannerRunId=row["planner_run_id"], ordinal=row["ordinal"],
                outcome=row["outcome"], reasonCode=row["reason_code"], signalIds=_loads(row["signal_ids_json"], []),
                dedupeKey=row["dedupe_key"], taskId=row["task_id"], proposal=_loads(row["proposal_json"], {}),
            )
            for row in rows
        ]

    def list_edges(self, *, epoch_id: str | None = None) -> list[GraphEdge]:
        selected_epoch = epoch_id or self.epoch_id
        with self._connect() as db:
            rows = db.execute(
                "SELECT edge_id,edge_type,source_id,target_id,created_at "
                "FROM control_loop_edges WHERE epoch_id=? ORDER BY rowid",
                (selected_epoch,),
            ).fetchall()
        return [
            GraphEdge(
                edgeId=row[0],
                edgeType=row[1],
                sourceId=row[2],
                targetId=row[3],
                createdAt=row[4],
            )
            for row in rows
        ]

    def list_planner_runs(self, *, include_terminal: bool = True) -> list[PlannerRun]:
        query = "SELECT * FROM control_loop_planner_runs"
        if not include_terminal:
            query += " WHERE state IN ('claimed','running')"
        query += " ORDER BY started_at"
        with self._connect() as db:
            rows = db.execute(query).fetchall()
        return [_planner_from_row(row) for row in rows]

    def canonical_signal_id(self, provider: str, fingerprint: str) -> str | None:
        """Return the epoch-local canonical signal for one normalized source."""

        with self._connect() as db:
            row = db.execute(
                "SELECT signal_id FROM control_loop_signals "
                "WHERE epoch_id=? AND provider=? AND fingerprint=?",
                (self.epoch_id, provider, fingerprint),
            ).fetchone()
        return str(row[0]) if row is not None else None

    def event_at(self, sequence: int) -> Event | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT event_id,epoch_id,sequence,occurred_at,kind,payload_json "
                "FROM control_loop_events WHERE sequence=?",
                (sequence,),
            ).fetchone()
        if row is None:
            return None
        return Event(
            eventId=row[0],
            epochId=row[1],
            sequence=row[2],
            occurredAt=row[3],
            kind=row[4],
            payload=_loads(row[5], {}),
        )


def _signal_fetch(value: SignalFetch | SignalFetchRun) -> SignalFetch:
    if isinstance(value, SignalFetch):
        return value
    return SignalFetch(
        fetchId=value.id,
        provider=value.provider,
        status=str(value.status),
        startedAt=value.started_at,
        completedAt=value.completed_at,
        itemCount=value.item_count,
        newItemCount=value.new_item_count,
        hasMore=value.has_more,
        error=value.error,
        summary=value.summary,
    )


def _observation(value: Observation | SignalItem, fetch_id: str) -> Observation:
    if isinstance(value, Observation):
        if value.fetch_id != fetch_id:
            return value.model_copy(update={"fetch_id": fetch_id})
        return value
    return Observation(
        observationId=value.id,
        fetchId=fetch_id,
        provider=value.provider,
        kind=value.kind,
        fingerprint=value.fingerprint,
        title=value.title,
        summary=value.summary,
        severity=value.severity,
        location=value.location,
        links=value.links,
        normalized=value.payload,
        observedAt=value.created_at,
    )


def _planner_from_row(row: sqlite3.Row) -> PlannerRun:
    return PlannerRun(
        plannerRunId=row["planner_run_id"], epochId=row["epoch_id"], state=row["state"],
        startedAt=row["started_at"], completedAt=row["completed_at"],
        inputSignalIds=_loads(row["input_signal_ids_json"], []), activeTaskIds=_loads(row["active_task_ids_json"], []),
        prompt=_loads(row["prompt_json"], None), result=_loads(row["result_json"], None), diagnostics=_loads(row["diagnostics_json"], {}),
    )


__all__ = ["ControlLoopLedger", "LedgerBlockedError", "LedgerConflictError"]
