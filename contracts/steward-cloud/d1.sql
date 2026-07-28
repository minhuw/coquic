-- Clean public metadata schema.  D1 runs SQLite with foreign keys enabled.
PRAGMA foreign_keys = ON;

CREATE TABLE publication_generations (
    publication_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    metadata_digest TEXT NOT NULL
        CHECK (length(metadata_digest) = 64 AND metadata_digest NOT GLOB '*[^0-9a-f]*'),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    state TEXT NOT NULL DEFAULT 'staged'
        CHECK (state IN ('staged', 'visible', 'superseded')),
    expected_task_count INTEGER NOT NULL CHECK (typeof(expected_task_count) = 'integer' AND expected_task_count >= 0),
    expected_pipeline_count INTEGER NOT NULL CHECK (typeof(expected_pipeline_count) = 'integer' AND expected_pipeline_count >= 0),
    expected_run_count INTEGER NOT NULL CHECK (typeof(expected_run_count) = 'integer' AND expected_run_count >= 0),
    expected_event_count INTEGER NOT NULL CHECK (typeof(expected_event_count) = 'integer' AND expected_event_count >= 0),
    expected_artifact_count INTEGER NOT NULL CHECK (typeof(expected_artifact_count) = 'integer' AND expected_artifact_count >= 0),
    created_at TEXT NOT NULL,
    exposed_at TEXT,
    UNIQUE (task_id, run_id),
    UNIQUE (task_id, idempotency_key)
);

CREATE TABLE task_heads (
    task_id TEXT PRIMARY KEY,
    publication_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('visible', 'hidden')),
    updated_at TEXT NOT NULL,
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE tasks (
    publication_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 512),
    lifecycle_state TEXT NOT NULL
        CHECK (lifecycle_state IN ('active', 'completed', 'failed', 'cancelled')),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (publication_id, task_id)
);

CREATE TABLE pipelines (
    publication_id TEXT NOT NULL,
    pipeline_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    created_at TEXT NOT NULL,
    PRIMARY KEY (publication_id, pipeline_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id)
);

CREATE TABLE runs (
    publication_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    pipeline_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (length(role) BETWEEN 1 AND 128),
    run_state TEXT NOT NULL
        CHECK (run_state IN ('completed', 'failed', 'cancelled')),
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL CHECK (typeof(duration_ms) = 'integer' AND duration_ms >= 0),
    atif_digest TEXT NOT NULL
        CHECK (length(atif_digest) = 64 AND atif_digest NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (publication_id, run_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id),
    FOREIGN KEY (publication_id, pipeline_id)
        REFERENCES pipelines (publication_id, pipeline_id)
);

CREATE TABLE task_events (
    publication_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (typeof(sequence) = 'integer' AND sequence >= 1),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    occurred_at TEXT NOT NULL,
    summary TEXT NOT NULL CHECK (length(summary) <= 4096),
    PRIMARY KEY (publication_id, task_id, sequence),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id)
);

CREATE TABLE artifacts (
    publication_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    logical_path TEXT NOT NULL
        CHECK (length(logical_path) BETWEEN 1 AND 1024
            AND logical_path NOT GLOB '/*'
            AND logical_path NOT LIKE '%://%'
            AND logical_path NOT LIKE '%..%'),
    public_key TEXT NOT NULL
        CHECK (length(public_key) BETWEEN 40 AND 256
            AND public_key LIKE 'v1/tasks/%/objects/sha256/%'
            AND public_key NOT LIKE '%://%'),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128 AND media_type NOT LIKE '% %'),
    byte_size INTEGER NOT NULL CHECK (typeof(byte_size) = 'integer' AND byte_size >= 0),
    sha256 TEXT NOT NULL
        CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    availability TEXT NOT NULL CHECK (availability IN ('available', 'unavailable')),
    redaction_applied INTEGER NOT NULL CHECK (redaction_applied IN (0, 1)),
    original_retained INTEGER NOT NULL CHECK (original_retained IN (0, 1)),
    PRIMARY KEY (publication_id, artifact_id),
    UNIQUE (publication_id, logical_path),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id),
    FOREIGN KEY (publication_id, run_id)
        REFERENCES runs (publication_id, run_id)
);

CREATE UNIQUE INDEX one_visible_generation_per_task
    ON publication_generations (task_id) WHERE state = 'visible';
CREATE INDEX publication_task_state_order
    ON publication_generations (task_id, state, created_at);
CREATE INDEX task_head_visibility_order
    ON task_heads (state, updated_at, task_id);
CREATE INDEX task_publication_order
    ON tasks (publication_id, created_at, task_id);
CREATE INDEX task_lifecycle_order
    ON tasks (lifecycle_state, created_at, task_id);
CREATE INDEX pipeline_task_lookup
    ON pipelines (publication_id, task_id, pipeline_id);
CREATE INDEX run_task_pipeline_order
    ON runs (publication_id, task_id, pipeline_id, started_at, run_id);
CREATE INDEX run_history_order
    ON runs (task_id, started_at, run_id);
CREATE INDEX task_event_order
    ON task_events (publication_id, task_id, sequence);
CREATE INDEX artifact_logical_path_lookup
    ON artifacts (publication_id, task_id, logical_path);
CREATE INDEX artifact_digest_lookup
    ON artifacts (task_id, sha256);
