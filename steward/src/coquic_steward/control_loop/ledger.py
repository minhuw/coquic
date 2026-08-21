"""Private SQLite ledger for the scheduler control loop.

This module intentionally uses a small dedicated SQLite connection.  The
existing task ledger remains authoritative for task execution; this ledger
records the causal scheduler graph and is joined to tasks by stable IDs.  All
mutating operations are idempotent and allocate archive sequence values while
holding ``BEGIN IMMEDIATE``.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
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
    StewardOverheadUsage,
    UsageCosts,
    UsageCoverage,
    UsageTokens,
    Wakeup,
    new_id,
    timestamp,
    utc_now,
    validate_id,
    validate_relative_path,
)


class LedgerConflictError(RuntimeError):
    """An immutable identity or graph relation conflicts with stored bytes."""


class LedgerBlockedError(RuntimeError):
    """Planning is blocked by a shared epoch or visible archive conflict."""


class _MissingEventError(LedgerConflictError):
    """A requested event sequence is absent from the ledger."""


_EVENT_LOOKUP_CHUNK_SIZE = 500


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
        self._epoch_id = validate_id(epoch_id) if epoch_id else None
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        uri = self.path.resolve().as_uri() + "?mode=rw"
        connection = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _validate_schema(db: sqlite3.Connection) -> None:
        # The current Store metadata is the schema authority.  Read its table
        # and index declarations rather than repeating a second catalog here.
        from ..storage.schema import Base

        required_tables = {
            table.name: tuple(column.name for column in table.columns)
            for table in Base.metadata.tables.values()
        }
        table_names = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        missing_tables = sorted(set(required_tables) - table_names)
        if missing_tables:
            raise LedgerConflictError(
                "current Store schema is incomplete: " + ", ".join(missing_tables)
            )

        for table, columns in required_tables.items():
            projection = ", ".join(f'"{column}"' for column in columns)
            try:
                db.execute(f'SELECT {projection} FROM "{table}" LIMIT 0')
            except sqlite3.Error as exc:
                raise LedgerConflictError(
                    f"current Store table {table} has an incomplete shape"
                ) from exc

        required_indexes = {
            index.name
            for table in Base.metadata.tables.values()
            for index in table.indexes
            if index.name is not None
        }
        index_names = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
        missing_indexes = sorted(required_indexes - index_names)
        if missing_indexes:
            raise LedgerConflictError(
                "current Store schema indexes are incomplete: "
                + ", ".join(missing_indexes)
            )

    def _initialize(self) -> None:
        if not self.path.is_file():
            raise LedgerConflictError("control-loop schema is unavailable")
        try:
            with self._connect() as db:
                self._validate_schema(db)
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
        except LedgerConflictError:
            raise
        except sqlite3.Error as exc:
            raise LedgerConflictError("control-loop schema is invalid") from exc

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
    def transaction(
        self, connection: sqlite3.Connection | None = None
    ) -> Iterator[sqlite3.Connection]:
        if connection is not None:
            yield connection
            return
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
        connection: sqlite3.Connection | None = None,
    ) -> tuple[list[Observation], list[CanonicalSignal]]:
        """Persist a fetch and every normalized observation in one transaction."""

        fetch_value = _signal_fetch(fetch)
        normalized_observations = [_observation(item, fetch_value.fetch_id) for item in observations]
        signals: list[CanonicalSignal] = []
        saved: list[Observation] = []
        with self.transaction(connection) as db:
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
                previous = db.execute(
                    "SELECT normalized_json FROM control_loop_observations WHERE observation_id=?",
                    (observation.observation_id,),
                ).fetchone()
                if previous is not None:
                    stored = Observation.model_validate(_loads(previous[0], {}))
                    candidate = observation.model_copy(
                        update={
                            "canonical_signal_id": stored.canonical_signal_id,
                            "dedupe_result": stored.dedupe_result,
                        }
                    )
                    if (
                        stored.canonical_signal_id != signal.signal_id
                        or candidate.model_dump(by_alias=True, mode="json")
                        != stored.model_dump(by_alias=True, mode="json")
                    ):
                        raise LedgerConflictError(f"observation {observation.observation_id} conflicts with stored bytes")
                    observation = stored
                else:
                    observation = observation.model_copy(
                        update={
                            "canonical_signal_id": signal.signal_id,
                            "dedupe_result": dedupe,
                        }
                    )
                    observation_json = observation.model_dump(by_alias=True, mode="json")
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

    def record_wakeup(
        self,
        wakeup: Wakeup,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> Wakeup:
        with self.transaction(connection) as db:
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
            for task_id in selected_tasks:
                if db.execute("SELECT 1 FROM tasks WHERE id=?", (task_id,)).fetchone() is None:
                    raise LedgerConflictError(f"active planner task does not exist: {task_id}")
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
            for ordinal, signal_id in enumerate(selected_signals, 1):
                db.execute(
                    "INSERT INTO control_loop_planner_signals(planner_run_id,ordinal,signal_id) VALUES(?,?,?)",
                    (run_id, ordinal, signal_id),
                )
            for ordinal, task_id in enumerate(selected_tasks, 1):
                db.execute(
                    "INSERT INTO control_loop_planner_tasks(planner_run_id,ordinal,task_id) VALUES(?,?,?)",
                    (run_id, ordinal, task_id),
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
        artifact_sources: Mapping[str, tuple[str, bool]] | None = None,
        reset_retry_key: str | None = None,
        schedule_retry_key: str | None = None,
        retry_initial_seconds: int = 30,
        retry_max_seconds: int = 300,
        connection: sqlite3.Connection | None = None,
    ) -> PlannerRun:
        run_id = validate_id(planner_run_id)
        values = [
            item if isinstance(item, ProposalDisposition) else ProposalDisposition.model_validate(item)
            for item in dispositions
        ]
        if state not in {"succeeded", "failed", "interrupted", "cancelled"}:
            raise ValueError(f"invalid terminal planner state: {state}")
        with self.transaction(connection) as db:
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
                for ordinal, signal_id in enumerate(item.signal_ids, 1):
                    db.execute(
                        "INSERT INTO control_loop_proposal_signals(proposal_id,ordinal,signal_id) VALUES(?,?,?)",
                        (item.proposal_id, ordinal, signal_id),
                    )
                if item.task_id is not None:
                    db.execute(
                        "INSERT INTO control_loop_proposal_tasks(proposal_id,task_id) VALUES(?,?)",
                        (item.proposal_id, item.task_id),
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
                changed = db.execute(
                    "UPDATE control_loop_signals SET status='planned',updated_at=? WHERE signal_id=? AND status='pending'",
                    (_dt(), signal_id),
                ).rowcount
                if changed:
                    self._signal_transition(
                        db,
                        signal_id,
                        "pending",
                        "planned",
                        planner_run_id=run_id,
                        reason="planner_consumed",
                    )
            for name, (source_path, required) in dict(artifact_sources or {}).items():
                db.execute(
                    "INSERT INTO control_loop_planner_artifacts(planner_run_id,name,source_path,required) VALUES(?,?,?,?)",
                    (run_id, validate_relative_path(name), str(source_path), int(required)),
                )
            completed = utc_now()
            retry_at = completed + retry_after if retry_after is not None else None
            diagnostic_values = dict(diagnostics or {})
            if schedule_retry_key is not None:
                attempt, retry_at = self._schedule_retry(
                    db,
                    schedule_retry_key,
                    initial_seconds=retry_initial_seconds,
                    max_seconds=retry_max_seconds,
                    now=completed,
                )
                diagnostic_values.update(
                    {
                        "attempt": attempt,
                        "retry_eligible_at": _dt(retry_at),
                    }
                )
            db.execute(
                "UPDATE control_loop_planner_runs SET state=?,completed_at=?,result_json=?,diagnostics_json=?,retry_eligible_at=? WHERE planner_run_id=?",
                (state, _dt(completed), _json(dict(result or {})), _json(diagnostic_values), _dt(retry_at) if retry_at else None, run_id),
            )
            if reset_retry_key is not None:
                db.execute("DELETE FROM control_loop_retry WHERE key=?", (reset_retry_key,))
            self._event(
                db,
                EventKind.planner_finished.value,
                {"plannerRunId": run_id, "state": state, "result": dict(result or {}), "diagnostics": diagnostic_values},
                event_id=f"planner-finished-{run_id}",
            )
            row = db.execute("SELECT * FROM control_loop_planner_runs WHERE planner_run_id=?", (run_id,)).fetchone()
        assert row is not None
        return _planner_from_row(row)

    def _signal_transition(
        self,
        db: sqlite3.Connection,
        signal_id: str,
        previous: str,
        status: str,
        *,
        planner_run_id: str | None,
        reason: str,
    ) -> Event:
        return self._event(
            db,
            EventKind.signal_transition.value,
            {
                "transition": {
                    "signalId": signal_id,
                    "fromStatus": previous,
                    "toStatus": status,
                    "plannerRunId": planner_run_id,
                    "reasonCode": reason,
                }
            },
        )

    def transition_signal_identities(
        self,
        identities: Iterable[tuple[str, str]],
        status: str,
        *,
        planner_run_id: str | None = None,
        reason: str,
        connection: sqlite3.Connection | None = None,
    ) -> int:
        if status not in {"pending", "planned", "superseded", "errored"}:
            raise ValueError(f"invalid canonical signal status: {status}")
        changed = 0
        with self.transaction(connection) as db:
            for provider, fingerprint in dict.fromkeys(identities):
                row = db.execute(
                    "SELECT signal_id,status FROM control_loop_signals WHERE epoch_id=? AND provider=? AND fingerprint=?",
                    (self.epoch_id, provider, fingerprint),
                ).fetchone()
                if row is None or row[1] == status:
                    continue
                db.execute(
                    "UPDATE control_loop_signals SET status=?,updated_at=? WHERE signal_id=?",
                    (status, _dt(), row[0]),
                )
                self._signal_transition(
                    db,
                    row[0],
                    row[1],
                    status,
                    planner_run_id=planner_run_id,
                    reason=reason,
                )
                changed += 1
        return changed

    def planner_artifact_sources(self, planner_run_id: str) -> dict[str, tuple[Path, bool]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT name,source_path,required FROM control_loop_planner_artifacts WHERE planner_run_id=? ORDER BY name",
                (validate_id(planner_run_id),),
            ).fetchall()
        return {row[0]: (Path(row[1]), bool(row[2])) for row in rows}

    def overhead_usage_watermark(self) -> str | None:
        """Return the latest sealed planner run consumed by the reducer.

        Per-run markers remain authoritative for replay safety; this compact
        value is an operational watermark for callers that need to avoid a
        full historical walk during a normal daemon drain.
        """

        with self._connect() as db:
            row = db.execute(
                "SELECT planner_run_id FROM control_loop_overhead_usage_runs "
                "ORDER BY processed_at DESC, planner_run_id DESC LIMIT 1"
            ).fetchone()
        return str(row[0]) if row is not None else None

    def overhead_usage_processed_at(self) -> str | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT processed_at FROM control_loop_overhead_usage_runs "
                "ORDER BY processed_at DESC, planner_run_id DESC LIMIT 1"
            ).fetchone()
        return str(row[0]) if row is not None else None

    def overhead_usage_processed(self, planner_run_id: str) -> str | None:
        run_id = validate_id(planner_run_id)
        with self._connect() as db:
            row = db.execute(
                "SELECT archive_digest FROM control_loop_overhead_usage_runs "
                "WHERE planner_run_id=?",
                (run_id,),
            ).fetchone()
        return str(row[0]) if row is not None else None

    def record_overhead_usage(
        self,
        planner_run_id: str,
        rows: Iterable[StewardOverheadUsage | Mapping[str, Any]],
        *,
        archive_digest: str,
        connection: sqlite3.Connection | None = None,
        fill_missing_costs: bool = False,
    ) -> bool:
        """Merge one verified planner run's aggregate rows exactly once."""

        run_id = validate_id(planner_run_id)
        if not isinstance(archive_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", archive_digest):
            raise ValueError("overhead usage archive digest is invalid")
        values = [
            row if isinstance(row, StewardOverheadUsage) else StewardOverheadUsage.model_validate(row)
            for row in rows
        ]
        rows_json = _json(
            [value.model_dump(by_alias=True, mode="json") for value in values]
        )
        cost_pending = int(any(value.cost.status == "N.A." for value in values))
        with self.transaction(connection) as db:
            marker = db.execute(
                "SELECT archive_digest,rows_json,cost_pending "
                "FROM control_loop_overhead_usage_runs WHERE planner_run_id=?",
                (run_id,),
            ).fetchone()
            if marker is not None:
                if marker[0] != archive_digest:
                    raise LedgerConflictError("overhead usage run bytes conflict with prior reduction")
                if fill_missing_costs:
                    prior_payload = _loads(marker[1], [])
                    if not isinstance(prior_payload, list):
                        raise LedgerConflictError(
                            "overhead usage contribution state is invalid"
                        )
                    if prior_payload:
                        prior_values = [
                            StewardOverheadUsage.model_validate(item)
                            for item in prior_payload
                        ]
                        replacement = _fill_contribution_rows(prior_values, values)
                        replacement_json = _json(
                            [
                                item.model_dump(by_alias=True, mode="json")
                                for item in replacement
                            ]
                        )
                        pending = int(any(item.cost.status == "N.A." for item in replacement))
                        db.execute(
                            "UPDATE control_loop_overhead_usage_runs "
                            "SET rows_json=?,cost_pending=? WHERE planner_run_id=?",
                            (replacement_json, pending, run_id),
                        )
                        self._rebuild_overhead_usage(db)
                    else:
                        # Ledgers created by the original Plan 030 schema have
                        # no per-run contribution bytes.  Preserve their
                        # aggregate while allowing a one-time cost fill.
                        for value in values:
                            existing = db.execute(
                                "SELECT costs_json FROM control_loop_overhead_usage "
                                "WHERE usage_date=? AND model=? AND owner_class=?",
                                (value.date, value.model, value.owner_class),
                            ).fetchone()
                            if existing is None:
                                continue
                            merged_cost = _fill_usage_costs(
                                UsageCosts.model_validate(_loads(existing[0], {})), value.cost
                            )
                            db.execute(
                                "UPDATE control_loop_overhead_usage SET costs_json=? "
                                "WHERE usage_date=? AND model=? AND owner_class=?",
                                (
                                    _json(merged_cost.model_dump(by_alias=True, mode="json")),
                                    value.date,
                                    value.model,
                                    value.owner_class,
                                ),
                            )
                return False
            run_exists = db.execute(
                "SELECT 1 FROM control_loop_planner_runs WHERE planner_run_id=? AND epoch_id=?",
                (run_id, self.epoch_id),
            ).fetchone()
            if run_exists is None:
                raise LedgerConflictError("overhead usage run is not ledger-owned")

            for value in values:
                existing = db.execute(
                    "SELECT tokens_json,costs_json,coverage_json FROM control_loop_overhead_usage "
                    "WHERE usage_date=? AND model=? AND owner_class=?",
                    (value.date, value.model, value.owner_class),
                ).fetchone()
                if existing is None:
                    merged = value
                else:
                    old_tokens = UsageTokens.model_validate(_loads(existing[0], {}))
                    old_costs = UsageCosts.model_validate(_loads(existing[1], {}))
                    old_coverage = UsageCoverage.model_validate(_loads(existing[2], {}))
                    merged = StewardOverheadUsage(
                        date=value.date,
                        model=value.model,
                        ownerClass=value.owner_class,
                        tokens=_merge_usage_tokens(old_tokens, value.tokens),
                        cost=_merge_usage_costs(old_costs, value.cost),
                        coverage=_merge_usage_coverage(old_coverage, value.coverage),
                    )
                db.execute(
                    "INSERT INTO control_loop_overhead_usage(usage_date,model,owner_class,tokens_json,costs_json,coverage_json) "
                    "VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(usage_date,model,owner_class) DO UPDATE SET "
                    "tokens_json=excluded.tokens_json,costs_json=excluded.costs_json,coverage_json=excluded.coverage_json",
                    (
                        merged.date,
                        merged.model,
                        merged.owner_class,
                        _json(merged.tokens.model_dump(by_alias=True, mode="json")),
                        _json(merged.cost.model_dump(by_alias=True, mode="json")),
                        _json(merged.coverage.model_dump(by_alias=True, mode="json")),
                    ),
                )
            db.execute(
                "INSERT INTO control_loop_overhead_usage_runs "
                "(planner_run_id,archive_digest,processed_at,rows_json,cost_pending) "
                "VALUES(?,?,?,?,?)",
                (run_id, archive_digest, _dt(), rows_json, cost_pending),
            )
            if values and self._all_overhead_contributions_available(db):
                self._rebuild_overhead_usage(db)
        return True

    def _all_overhead_contributions_available(self, db: sqlite3.Connection) -> bool:
        rows = db.execute(
            "SELECT rows_json FROM control_loop_overhead_usage_runs"
        ).fetchall()
        return bool(rows) and all(bool(_loads(row[0], [])) for row in rows)

    def _rebuild_overhead_usage(self, db: sqlite3.Connection) -> None:
        """Rebuild aggregate rows from immutable per-run contribution bytes."""

        grouped: dict[tuple[str, str, str], StewardOverheadUsage] = {}
        marker_rows = db.execute(
            "SELECT rows_json FROM control_loop_overhead_usage_runs ORDER BY processed_at,planner_run_id"
        ).fetchall()
        for marker in marker_rows:
            payload = _loads(marker[0], [])
            if not isinstance(payload, list):
                raise LedgerConflictError("overhead usage contribution state is invalid")
            for item in payload:
                value = StewardOverheadUsage.model_validate(item)
                key = (value.date, value.model, value.owner_class)
                previous = grouped.get(key)
                grouped[key] = (
                    value
                    if previous is None
                    else StewardOverheadUsage(
                        date=value.date,
                        model=value.model,
                        ownerClass=value.owner_class,
                        tokens=_merge_usage_tokens(previous.tokens, value.tokens),
                        cost=_merge_usage_costs(previous.cost, value.cost),
                        coverage=_merge_usage_coverage(previous.coverage, value.coverage),
                    )
                )
        db.execute("DELETE FROM control_loop_overhead_usage")
        for value in grouped.values():
            db.execute(
                "INSERT INTO control_loop_overhead_usage "
                "(usage_date,model,owner_class,tokens_json,costs_json,coverage_json) "
                "VALUES(?,?,?,?,?,?)",
                (
                    value.date,
                    value.model,
                    value.owner_class,
                    _json(value.tokens.model_dump(by_alias=True, mode="json")),
                    _json(value.cost.model_dump(by_alias=True, mode="json")),
                    _json(value.coverage.model_dump(by_alias=True, mode="json")),
                ),
            )

    def list_overhead_usage(self) -> list[StewardOverheadUsage]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT usage_date,model,owner_class,tokens_json,costs_json,coverage_json "
                "FROM control_loop_overhead_usage ORDER BY usage_date,model,owner_class"
            ).fetchall()
        return [
            StewardOverheadUsage(
                date=row[0],
                model=row[1],
                ownerClass=row[2],
                tokens=UsageTokens.model_validate(_loads(row[3], {})),
                cost=UsageCosts.model_validate(_loads(row[4], {})),
                coverage=UsageCoverage.model_validate(_loads(row[5], {})),
            )
            for row in rows
        ]

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
            return self._schedule_retry(
                db,
                key,
                initial_seconds=initial_seconds,
                max_seconds=max_seconds,
                now=selected_now,
            )

    def _schedule_retry(
        self,
        db: sqlite3.Connection,
        key: str,
        *,
        initial_seconds: int,
        max_seconds: int,
        now: datetime,
    ) -> tuple[int, datetime]:
        row = db.execute(
            "SELECT attempt FROM control_loop_retry WHERE key=?", (key,)
        ).fetchone()
        attempt = int(row[0]) + 1 if row else 1
        delay = min(max_seconds, initial_seconds * (2 ** (attempt - 1)))
        eligible = now + timedelta(seconds=delay)
        db.execute(
            "INSERT INTO control_loop_retry(key,attempt,eligible_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET attempt=excluded.attempt,eligible_at=excluded.eligible_at,updated_at=excluded.updated_at",
            (key, attempt, _dt(eligible), _dt(now)),
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

    def list_unprocessed_planner_runs(self, *, limit: int = 128) -> list[PlannerRun]:
        """Return a bounded stable-ordered page of newly sealed planner runs.

        The per-run overhead marker is the durable cursor.  A left join keeps
        late terminal transitions visible even when their completion timestamp
        predates the previous drain, while the deterministic timestamp/ID
        ordering makes restart replay stable.
        """

        if type(limit) is not int or limit < 1 or limit > 4096:
            raise ValueError("planner run page limit is invalid")
        with self._connect() as db:
            rows = db.execute(
                "SELECT p.* FROM control_loop_planner_runs AS p "
                "LEFT JOIN control_loop_overhead_usage_runs AS u "
                "ON u.planner_run_id=p.planner_run_id "
                "WHERE p.epoch_id=? AND p.state IN "
                "('succeeded','failed','interrupted','cancelled') "
                "AND p.completed_at IS NOT NULL AND u.planner_run_id IS NULL "
                "ORDER BY p.completed_at,p.planner_run_id LIMIT ?",
                (self.epoch_id, limit),
            ).fetchall()
        return [_planner_from_row(row) for row in rows]

    def list_overhead_usage_runs_needing_cost(
        self, *, limit: int = 128
    ) -> list[PlannerRun]:
        """Return a bounded page of previously reduced runs with N.A. costs."""

        if type(limit) is not int or limit < 1 or limit > 4096:
            raise ValueError("planner run page limit is invalid")
        with self._connect() as db:
            rows = db.execute(
                "SELECT p.* FROM control_loop_planner_runs AS p "
                "JOIN control_loop_overhead_usage_runs AS u "
                "ON u.planner_run_id=p.planner_run_id "
                "WHERE p.epoch_id=? AND u.cost_pending=1 AND p.state IN "
                "('succeeded','failed','interrupted','cancelled') "
                "AND p.completed_at IS NOT NULL "
                "ORDER BY p.completed_at,p.planner_run_id LIMIT ?",
                (self.epoch_id, limit),
            ).fetchall()
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

    def events_at(self, sequences: Iterable[int]) -> dict[int, Event]:
        """Return ledger events for a strictly ordered sequence request.

        SQLite parameters are bounded explicitly so a large archive file is
        verified through one connection without relying on the connection's
        variable limit.  The request is intentionally strict: duplicate or
        out-of-order sequences are evidence that the caller's archive view is
        ambiguous and must be rejected rather than normalized.
        """

        requested = list(sequences)
        if not requested:
            return {}
        if any(
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 0
            for sequence in requested
        ):
            raise LedgerConflictError("event sequences must be non-negative integers")
        seen: set[int] = set()
        duplicates: list[int] = []
        for sequence in requested:
            if sequence in seen:
                duplicates.append(sequence)
            else:
                seen.add(sequence)
        if duplicates:
            duplicate = duplicates[0]
            raise LedgerConflictError(f"duplicate event sequence request: {duplicate}")
        if any(left >= right for left, right in zip(requested, requested[1:])):
            raise LedgerConflictError("event sequence request is out of order")

        events: dict[int, Event] = {}
        event_ids: dict[str, int] = {}
        with self._connect() as db:
            for offset in range(0, len(requested), _EVENT_LOOKUP_CHUNK_SIZE):
                chunk = requested[offset : offset + _EVENT_LOOKUP_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                rows = db.execute(
                    "SELECT event_id,epoch_id,sequence,occurred_at,kind,payload_json "
                    f"FROM control_loop_events WHERE sequence IN ({placeholders}) ORDER BY sequence",
                    chunk,
                ).fetchall()
                for row in rows:
                    sequence = int(row["sequence"])
                    if sequence in events:
                        raise LedgerConflictError(
                            f"ambiguous ledger rows for event sequence {sequence}"
                        )
                    event_id = str(row["event_id"])
                    prior_sequence = event_ids.get(event_id)
                    if prior_sequence is not None and prior_sequence != sequence:
                        raise LedgerConflictError(
                            f"ambiguous ledger event identity {event_id}"
                        )
                    events[sequence] = Event(
                        eventId=event_id,
                        epochId=row["epoch_id"],
                        sequence=sequence,
                        occurredAt=row["occurred_at"],
                        kind=row["kind"],
                        payload=_loads(row["payload_json"], {}),
                    )
                    event_ids[event_id] = sequence

        missing = [sequence for sequence in requested if sequence not in events]
        if missing:
            values = ", ".join(str(sequence) for sequence in missing)
            raise _MissingEventError(f"missing ledger event sequence(s): {values}")
        return events

    def event_at(self, sequence: int) -> Event | None:
        """Return one event while preserving the historical missing-row API."""

        try:
            return self.events_at([sequence])[sequence]
        except LedgerConflictError:
            return None


def _merge_optional_numbers(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return left + right


def _merge_usage_tokens(left: UsageTokens, right: UsageTokens) -> UsageTokens:
    return UsageTokens(
        inputTokens=_merge_optional_numbers(left.input_tokens, right.input_tokens),
        cachedInputTokens=_merge_optional_numbers(
            left.cached_input_tokens, right.cached_input_tokens
        ),
        uncachedInputTokens=_merge_optional_numbers(
            left.uncached_input_tokens, right.uncached_input_tokens
        ),
        outputTokens=_merge_optional_numbers(left.output_tokens, right.output_tokens),
        reasoningOutputTokens=_merge_optional_numbers(
            left.reasoning_output_tokens, right.reasoning_output_tokens
        ),
        totalTokens=_merge_optional_numbers(left.total_tokens, right.total_tokens),
    )


def _merge_usage_costs(left: UsageCosts, right: UsageCosts) -> UsageCosts:
    components = {
        "uncachedInputMicroUsd": _merge_optional_numbers(
            left.uncached_input_micro_usd, right.uncached_input_micro_usd
        ),
        "cachedInputMicroUsd": _merge_optional_numbers(
            left.cached_input_micro_usd, right.cached_input_micro_usd
        ),
        "outputMicroUsd": _merge_optional_numbers(
            left.output_micro_usd, right.output_micro_usd
        ),
        "totalMicroUsd": _merge_optional_numbers(
            left.total_micro_usd, right.total_micro_usd
        ),
    }
    present = [components[key] is not None for key in (
        "uncachedInputMicroUsd",
        "cachedInputMicroUsd",
        "outputMicroUsd",
        "totalMicroUsd",
    )]
    if all(present) and left.status == right.status == "Complete":
        status = "Complete"
    elif any(present):
        status = "Partial"
    else:
        status = "N.A."
    return UsageCosts(status=status, **components)


def _fill_usage_costs(left: UsageCosts, right: UsageCosts) -> UsageCosts:
    values = {
        "uncachedInputMicroUsd": (
            left.uncached_input_micro_usd
            if left.uncached_input_micro_usd is not None
            else right.uncached_input_micro_usd
        ),
        "cachedInputMicroUsd": (
            left.cached_input_micro_usd
            if left.cached_input_micro_usd is not None
            else right.cached_input_micro_usd
        ),
        "outputMicroUsd": (
            left.output_micro_usd
            if left.output_micro_usd is not None
            else right.output_micro_usd
        ),
        "totalMicroUsd": (
            left.total_micro_usd
            if left.total_micro_usd is not None
            else right.total_micro_usd
        ),
    }
    components = (
        values["uncachedInputMicroUsd"],
        values["cachedInputMicroUsd"],
        values["outputMicroUsd"],
    )
    if values["totalMicroUsd"] is not None and all(item is not None for item in components):
        if values["totalMicroUsd"] != sum(item for item in components if item is not None):
            values["totalMicroUsd"] = None
    present = [item is not None for item in values.values()]
    if all(present):
        # A catalog can fill an unavailable contribution without turning a
        # partial capture into complete evidence.  Existing numeric costs are
        # otherwise immutable and retain their original coverage status.
        status = (
            "Partial"
            if left.status == "Partial" or right.status == "Partial"
            else "Complete"
        )
    else:
        status = "Partial" if any(present) else "N.A."
    return UsageCosts(status=status, **values)


def _fill_contribution_rows(
    previous: Iterable[StewardOverheadUsage],
    replacement: Iterable[StewardOverheadUsage],
) -> list[StewardOverheadUsage]:
    """Fill only N.A. costs in one run's private contribution state."""

    incoming = {
        (value.date, value.model, value.owner_class): value for value in replacement
    }
    result: list[StewardOverheadUsage] = []
    seen: set[tuple[str, str, str]] = set()
    for old in previous:
        key = (old.date, old.model, old.owner_class)
        new = incoming.get(key)
        if new is None:
            result.append(old)
        else:
            result.append(
                StewardOverheadUsage(
                    date=old.date,
                    model=old.model,
                    ownerClass=old.owner_class,
                    tokens=old.tokens,
                    cost=_fill_usage_costs(old.cost, new.cost),
                    coverage=old.coverage,
                )
            )
            seen.add(key)
    result.extend(
        value
        for key, value in incoming.items()
        if key not in seen
        and not any(
            (old.date, old.model, old.owner_class) == key for old in previous
        )
    )
    return result


def _merge_usage_coverage(left: UsageCoverage, right: UsageCoverage) -> UsageCoverage:
    covered = left.covered_invocations + right.covered_invocations
    expected = left.expected_invocations + right.expected_invocations
    if expected == 0 or covered == 0:
        status = "N.A."
    elif covered == expected and left.status == right.status == "Complete":
        status = "Complete"
    else:
        status = "Partial"
    return UsageCoverage(
        coveredInvocations=covered,
        expectedInvocations=expected,
        status=status,
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
