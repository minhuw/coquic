-- Clean public metadata and usage schema. D1 runs SQLite with foreign keys enabled.
-- All bounded counters use the largest exactly representable JSON integer.
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
    expected_task_count INTEGER NOT NULL CHECK (typeof(expected_task_count) = 'integer' AND expected_task_count BETWEEN 0 AND 9007199254740991),
    expected_pipeline_count INTEGER NOT NULL CHECK (typeof(expected_pipeline_count) = 'integer' AND expected_pipeline_count BETWEEN 0 AND 9007199254740991),
    expected_run_count INTEGER NOT NULL CHECK (typeof(expected_run_count) = 'integer' AND expected_run_count BETWEEN 0 AND 9007199254740991),
    expected_event_count INTEGER NOT NULL CHECK (typeof(expected_event_count) = 'integer' AND expected_event_count BETWEEN 0 AND 9007199254740991),
    expected_artifact_count INTEGER NOT NULL CHECK (typeof(expected_artifact_count) = 'integer' AND expected_artifact_count BETWEEN 0 AND 9007199254740991),
    created_at TEXT NOT NULL,
    exposed_at TEXT,
    UNIQUE (task_id, run_id),
    UNIQUE (task_id, idempotency_key),
    UNIQUE (publication_id, task_id),
    UNIQUE (publication_id, task_id, run_id)
);

CREATE TABLE usage_generations (
    usage_generation_id TEXT PRIMARY KEY,
    publication_id TEXT,
    task_id TEXT,
    ownership_class TEXT NOT NULL DEFAULT 'task-owned'
        CHECK (ownership_class IN ('task-owned', 'steward-overhead')),
    schema_version TEXT NOT NULL CHECK (schema_version = '1.0'),
    metadata_digest TEXT NOT NULL
        CHECK (length(metadata_digest) = 64 AND metadata_digest NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL DEFAULT 'staged'
        CHECK (state IN ('staged', 'visible', 'superseded')),
    expected_summary_count INTEGER NOT NULL CHECK (typeof(expected_summary_count) = 'integer' AND expected_summary_count BETWEEN 0 AND 9007199254740991),
    expected_invocation_count INTEGER NOT NULL CHECK (typeof(expected_invocation_count) = 'integer' AND expected_invocation_count BETWEEN 0 AND 9007199254740991),
    expected_turn_count INTEGER NOT NULL CHECK (typeof(expected_turn_count) = 'integer' AND expected_turn_count BETWEEN 0 AND 9007199254740991),
    expected_price_count INTEGER NOT NULL CHECK (typeof(expected_price_count) = 'integer' AND expected_price_count BETWEEN 0 AND 9007199254740991),
    expected_global_count INTEGER NOT NULL CHECK (typeof(expected_global_count) = 'integer' AND expected_global_count BETWEEN 0 AND 9007199254740991),
    created_at TEXT NOT NULL,
    exposed_at TEXT,
    UNIQUE (usage_generation_id, task_id),
    CHECK ((ownership_class = 'task-owned' AND publication_id IS NOT NULL AND task_id IS NOT NULL AND expected_summary_count >= 1)
        OR (ownership_class = 'steward-overhead' AND publication_id IS NULL AND task_id IS NULL
            AND expected_summary_count = 0 AND expected_invocation_count = 0
            AND expected_turn_count = 0 AND expected_price_count = 0
            AND expected_global_count = 1)),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES publication_generations (publication_id, task_id)
);

CREATE TABLE tasks (
    publication_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 512),
    lifecycle_state TEXT NOT NULL
        CHECK (lifecycle_state IN ('active', 'completed', 'failed', 'cancelled')),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (publication_id, task_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES publication_generations (publication_id, task_id)
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
    duration_ms INTEGER NOT NULL CHECK (typeof(duration_ms) = 'integer' AND duration_ms BETWEEN 0 AND 9007199254740991),
    atif_digest TEXT NOT NULL
        CHECK (length(atif_digest) = 64 AND atif_digest NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (publication_id, run_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id),
    FOREIGN KEY (publication_id, pipeline_id)
        REFERENCES pipelines (publication_id, pipeline_id),
    FOREIGN KEY (publication_id, task_id, run_id)
        REFERENCES publication_generations (publication_id, task_id, run_id)
);

CREATE TABLE task_events (
    publication_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991),
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
            AND public_key NOT LIKE '%://%'
            AND public_key = 'v1/tasks/' || task_id || '/objects/sha256/'
                || substr(sha256, 1, 2) || '/' || sha256),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128 AND media_type NOT LIKE '% %'),
    byte_size INTEGER NOT NULL CHECK (typeof(byte_size) = 'integer' AND byte_size BETWEEN 0 AND 9007199254740991),
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

-- A price row is provenance only. Actual catalog rates stay outside this public contract.
CREATE TABLE usage_prices (
    price_entry_digest TEXT PRIMARY KEY
        CHECK (length(price_entry_digest) = 64 AND price_entry_digest NOT GLOB '*[^0-9a-f]*'),
    usage_generation_id TEXT NOT NULL,
    catalog_digest TEXT NOT NULL
        CHECK (length(catalog_digest) = 64 AND catalog_digest NOT GLOB '*[^0-9a-f]*'),
    model TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 256),
    effective_at TEXT NOT NULL,
    effective_until TEXT,
    FOREIGN KEY (usage_generation_id)
        REFERENCES usage_generations (usage_generation_id)
);

CREATE TABLE usage_heads (
    task_id TEXT PRIMARY KEY,
    usage_generation_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('visible', 'hidden')),
    updated_at TEXT NOT NULL,
    UNIQUE (task_id, usage_generation_id),
    FOREIGN KEY (usage_generation_id, task_id)
        REFERENCES usage_generations (usage_generation_id, task_id)
);

CREATE TABLE task_heads (
    task_id TEXT PRIMARY KEY,
    publication_id TEXT NOT NULL,
    usage_generation_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('visible', 'hidden')),
    updated_at TEXT NOT NULL,
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES publication_generations (publication_id, task_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (usage_generation_id, task_id)
        REFERENCES usage_generations (usage_generation_id, task_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Summary rows are task and run rollups. Null usage means evidence is unknown,
-- while zero is a known zero-token result.
CREATE TABLE usage_summaries (
    summary_id TEXT PRIMARY KEY,
    usage_generation_id TEXT NOT NULL,
    publication_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT,
    scope TEXT NOT NULL CHECK (scope IN ('task', 'run')),
    coverage TEXT NOT NULL CHECK (coverage IN ('complete', 'partial', 'unavailable')),
    covered_invocations INTEGER NOT NULL CHECK (typeof(covered_invocations) = 'integer' AND covered_invocations BETWEEN 0 AND 9007199254740991),
    expected_invocations INTEGER NOT NULL CHECK (typeof(expected_invocations) = 'integer' AND expected_invocations BETWEEN 0 AND 9007199254740991),
    known_token_subtotal INTEGER CHECK (known_token_subtotal IS NULL OR (typeof(known_token_subtotal) = 'integer' AND known_token_subtotal BETWEEN 0 AND 9007199254740991)),
    known_cost_subtotal_micro_usd INTEGER CHECK (known_cost_subtotal_micro_usd IS NULL OR (typeof(known_cost_subtotal_micro_usd) = 'integer' AND known_cost_subtotal_micro_usd BETWEEN 0 AND 9007199254740991)),
    prompt_tokens INTEGER CHECK (prompt_tokens IS NULL OR (typeof(prompt_tokens) = 'integer' AND prompt_tokens BETWEEN 0 AND 9007199254740991)),
    cached_tokens INTEGER CHECK (cached_tokens IS NULL OR (typeof(cached_tokens) = 'integer' AND cached_tokens BETWEEN 0 AND 9007199254740991)),
    uncached_tokens INTEGER CHECK (uncached_tokens IS NULL OR (typeof(uncached_tokens) = 'integer' AND uncached_tokens BETWEEN 0 AND 9007199254740991)),
    completion_tokens INTEGER CHECK (completion_tokens IS NULL OR (typeof(completion_tokens) = 'integer' AND completion_tokens BETWEEN 0 AND 9007199254740991)),
    reasoning_tokens INTEGER CHECK (reasoning_tokens IS NULL OR (typeof(reasoning_tokens) = 'integer' AND reasoning_tokens BETWEEN 0 AND 9007199254740991)),
    total_tokens INTEGER CHECK (total_tokens IS NULL OR (typeof(total_tokens) = 'integer' AND total_tokens BETWEEN 0 AND 9007199254740991)),
    uncached_input_cost_micro_usd INTEGER CHECK (uncached_input_cost_micro_usd IS NULL OR (typeof(uncached_input_cost_micro_usd) = 'integer' AND uncached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    cached_input_cost_micro_usd INTEGER CHECK (cached_input_cost_micro_usd IS NULL OR (typeof(cached_input_cost_micro_usd) = 'integer' AND cached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    output_cost_micro_usd INTEGER CHECK (output_cost_micro_usd IS NULL OR (typeof(output_cost_micro_usd) = 'integer' AND output_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    total_cost_micro_usd INTEGER CHECK (total_cost_micro_usd IS NULL OR (typeof(total_cost_micro_usd) = 'integer' AND total_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    price_provenance_digest TEXT CHECK (price_provenance_digest IS NULL OR (length(price_provenance_digest) = 64 AND price_provenance_digest NOT GLOB '*[^0-9a-f]*')),
    UNIQUE (usage_generation_id, scope, run_id),
    CHECK (covered_invocations <= expected_invocations),
    CHECK ((scope = 'task' AND run_id IS NULL) OR (scope = 'run' AND run_id IS NOT NULL)),
    CHECK ((coverage = 'complete' AND covered_invocations = expected_invocations)
        OR coverage IN ('partial', 'unavailable')),
    CHECK ((coverage = 'unavailable' AND known_token_subtotal IS NULL AND known_cost_subtotal_micro_usd IS NULL)
        OR coverage <> 'unavailable'),
    FOREIGN KEY (usage_generation_id)
        REFERENCES usage_generations (usage_generation_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id)
);

-- The duplicated publication identity in summary rows is deliberately avoided;
-- this index and the generation/task foreign key are the ownership boundary.
CREATE TABLE usage_invocations (
    invocation_id TEXT PRIMARY KEY,
    usage_generation_id TEXT NOT NULL,
    publication_id TEXT,
    task_id TEXT,
    pipeline_id TEXT,
    run_id TEXT,
    ownership_class TEXT NOT NULL CHECK (ownership_class IN ('task-owned', 'steward-overhead')),
    retry_ordinal INTEGER NOT NULL CHECK (typeof(retry_ordinal) = 'integer' AND retry_ordinal BETWEEN 0 AND 9007199254740991),
    started_at TEXT,
    completed_at TEXT,
    model TEXT,
    billing_mode TEXT CHECK (billing_mode IS NULL OR billing_mode IN ('unknown', 'chatgpt', 'api')),
    process_outcome TEXT,
    coverage TEXT NOT NULL CHECK (coverage IN ('complete', 'partial', 'unavailable')),
    issue_count INTEGER NOT NULL CHECK (typeof(issue_count) = 'integer' AND issue_count BETWEEN 0 AND 9007199254740991),
    covered_turns INTEGER NOT NULL CHECK (typeof(covered_turns) = 'integer' AND covered_turns BETWEEN 0 AND 4096),
    expected_turns INTEGER NOT NULL CHECK (typeof(expected_turns) = 'integer' AND expected_turns BETWEEN 0 AND 4096),
    prompt_tokens INTEGER CHECK (prompt_tokens IS NULL OR (typeof(prompt_tokens) = 'integer' AND prompt_tokens BETWEEN 0 AND 9007199254740991)),
    cached_tokens INTEGER CHECK (cached_tokens IS NULL OR (typeof(cached_tokens) = 'integer' AND cached_tokens BETWEEN 0 AND 9007199254740991)),
    uncached_tokens INTEGER CHECK (uncached_tokens IS NULL OR (typeof(uncached_tokens) = 'integer' AND uncached_tokens BETWEEN 0 AND 9007199254740991)),
    completion_tokens INTEGER CHECK (completion_tokens IS NULL OR (typeof(completion_tokens) = 'integer' AND completion_tokens BETWEEN 0 AND 9007199254740991)),
    reasoning_tokens INTEGER CHECK (reasoning_tokens IS NULL OR (typeof(reasoning_tokens) = 'integer' AND reasoning_tokens BETWEEN 0 AND 9007199254740991)),
    total_tokens INTEGER CHECK (total_tokens IS NULL OR (typeof(total_tokens) = 'integer' AND total_tokens BETWEEN 0 AND 9007199254740991)),
    uncached_input_cost_micro_usd INTEGER CHECK (uncached_input_cost_micro_usd IS NULL OR (typeof(uncached_input_cost_micro_usd) = 'integer' AND uncached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    cached_input_cost_micro_usd INTEGER CHECK (cached_input_cost_micro_usd IS NULL OR (typeof(cached_input_cost_micro_usd) = 'integer' AND cached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    output_cost_micro_usd INTEGER CHECK (output_cost_micro_usd IS NULL OR (typeof(output_cost_micro_usd) = 'integer' AND output_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    total_cost_micro_usd INTEGER CHECK (total_cost_micro_usd IS NULL OR (typeof(total_cost_micro_usd) = 'integer' AND total_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    price_entry_digest TEXT CHECK (price_entry_digest IS NULL OR (length(price_entry_digest) = 64 AND price_entry_digest NOT GLOB '*[^0-9a-f]*')),
    UNIQUE (usage_generation_id, task_id, run_id, retry_ordinal),
    CHECK (covered_turns <= expected_turns),
    CHECK ((ownership_class = 'task-owned' AND task_id IS NOT NULL AND pipeline_id IS NOT NULL AND run_id IS NOT NULL)
        OR (ownership_class = 'steward-overhead' AND task_id IS NULL AND pipeline_id IS NULL AND run_id IS NULL AND covered_turns = 0 AND expected_turns = 0)),
    CHECK ((coverage = 'complete' AND covered_turns = expected_turns)
        OR coverage IN ('partial', 'unavailable')),
    CHECK ((coverage = 'unavailable' AND prompt_tokens IS NULL AND cached_tokens IS NULL AND uncached_tokens IS NULL AND completion_tokens IS NULL AND reasoning_tokens IS NULL AND total_tokens IS NULL AND uncached_input_cost_micro_usd IS NULL AND cached_input_cost_micro_usd IS NULL AND output_cost_micro_usd IS NULL AND total_cost_micro_usd IS NULL)
        OR coverage <> 'unavailable'),
    FOREIGN KEY (usage_generation_id)
        REFERENCES usage_generations (usage_generation_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id),
    CHECK ((ownership_class = 'task-owned' AND publication_id IS NOT NULL)
        OR (ownership_class = 'steward-overhead' AND publication_id IS NULL))
);

CREATE TABLE usage_turns (
    turn_id TEXT PRIMARY KEY,
    usage_generation_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    publication_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (typeof(ordinal) = 'integer' AND ordinal BETWEEN 1 AND 4096),
    prompt_tokens INTEGER NOT NULL CHECK (typeof(prompt_tokens) = 'integer' AND prompt_tokens BETWEEN 0 AND 9007199254740991),
    cached_tokens INTEGER NOT NULL CHECK (typeof(cached_tokens) = 'integer' AND cached_tokens BETWEEN 0 AND 9007199254740991),
    uncached_tokens INTEGER NOT NULL CHECK (typeof(uncached_tokens) = 'integer' AND uncached_tokens BETWEEN 0 AND 9007199254740991),
    completion_tokens INTEGER NOT NULL CHECK (typeof(completion_tokens) = 'integer' AND completion_tokens BETWEEN 0 AND 9007199254740991),
    reasoning_tokens INTEGER NOT NULL CHECK (typeof(reasoning_tokens) = 'integer' AND reasoning_tokens BETWEEN 0 AND 9007199254740991),
    total_tokens INTEGER NOT NULL CHECK (typeof(total_tokens) = 'integer' AND total_tokens BETWEEN 0 AND 9007199254740991),
    uncached_input_cost_micro_usd INTEGER CHECK (uncached_input_cost_micro_usd IS NULL OR (typeof(uncached_input_cost_micro_usd) = 'integer' AND uncached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    cached_input_cost_micro_usd INTEGER CHECK (cached_input_cost_micro_usd IS NULL OR (typeof(cached_input_cost_micro_usd) = 'integer' AND cached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    output_cost_micro_usd INTEGER CHECK (output_cost_micro_usd IS NULL OR (typeof(output_cost_micro_usd) = 'integer' AND output_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    total_cost_micro_usd INTEGER CHECK (total_cost_micro_usd IS NULL OR (typeof(total_cost_micro_usd) = 'integer' AND total_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    price_entry_digest TEXT CHECK (price_entry_digest IS NULL OR (length(price_entry_digest) = 64 AND price_entry_digest NOT GLOB '*[^0-9a-f]*')),
    UNIQUE (invocation_id, ordinal),
    CHECK (cached_tokens <= prompt_tokens),
    CHECK (uncached_tokens = prompt_tokens - cached_tokens),
    CHECK (reasoning_tokens <= completion_tokens),
    CHECK (total_tokens = prompt_tokens + completion_tokens),
    FOREIGN KEY (usage_generation_id)
        REFERENCES usage_generations (usage_generation_id),
    FOREIGN KEY (invocation_id)
        REFERENCES usage_invocations (invocation_id),
    FOREIGN KEY (publication_id, task_id)
        REFERENCES tasks (publication_id, task_id),
    FOREIGN KEY (publication_id, run_id)
        REFERENCES runs (publication_id, run_id)
);

CREATE TABLE usage_globals (
    global_id TEXT PRIMARY KEY,
    usage_generation_id TEXT NOT NULL,
    period_kind TEXT NOT NULL CHECK (period_kind IN ('lifetime', 'daily')),
    period_key TEXT NOT NULL,
    model TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 256),
    ownership_class TEXT NOT NULL CHECK (ownership_class IN ('task-owned', 'steward-overhead')),
    coverage TEXT NOT NULL CHECK (coverage IN ('complete', 'partial', 'unavailable')),
    covered_invocations INTEGER NOT NULL CHECK (typeof(covered_invocations) = 'integer' AND covered_invocations BETWEEN 0 AND 9007199254740991),
    expected_invocations INTEGER NOT NULL CHECK (typeof(expected_invocations) = 'integer' AND expected_invocations BETWEEN 0 AND 9007199254740991),
    known_token_subtotal INTEGER CHECK (known_token_subtotal IS NULL OR (typeof(known_token_subtotal) = 'integer' AND known_token_subtotal BETWEEN 0 AND 9007199254740991)),
    known_cost_subtotal_micro_usd INTEGER CHECK (known_cost_subtotal_micro_usd IS NULL OR (typeof(known_cost_subtotal_micro_usd) = 'integer' AND known_cost_subtotal_micro_usd BETWEEN 0 AND 9007199254740991)),
    prompt_tokens INTEGER CHECK (prompt_tokens IS NULL OR (typeof(prompt_tokens) = 'integer' AND prompt_tokens BETWEEN 0 AND 9007199254740991)),
    cached_tokens INTEGER CHECK (cached_tokens IS NULL OR (typeof(cached_tokens) = 'integer' AND cached_tokens BETWEEN 0 AND 9007199254740991)),
    uncached_tokens INTEGER CHECK (uncached_tokens IS NULL OR (typeof(uncached_tokens) = 'integer' AND uncached_tokens BETWEEN 0 AND 9007199254740991)),
    completion_tokens INTEGER CHECK (completion_tokens IS NULL OR (typeof(completion_tokens) = 'integer' AND completion_tokens BETWEEN 0 AND 9007199254740991)),
    reasoning_tokens INTEGER CHECK (reasoning_tokens IS NULL OR (typeof(reasoning_tokens) = 'integer' AND reasoning_tokens BETWEEN 0 AND 9007199254740991)),
    total_tokens INTEGER CHECK (total_tokens IS NULL OR (typeof(total_tokens) = 'integer' AND total_tokens BETWEEN 0 AND 9007199254740991)),
    uncached_input_cost_micro_usd INTEGER CHECK (uncached_input_cost_micro_usd IS NULL OR (typeof(uncached_input_cost_micro_usd) = 'integer' AND uncached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    cached_input_cost_micro_usd INTEGER CHECK (cached_input_cost_micro_usd IS NULL OR (typeof(cached_input_cost_micro_usd) = 'integer' AND cached_input_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    output_cost_micro_usd INTEGER CHECK (output_cost_micro_usd IS NULL OR (typeof(output_cost_micro_usd) = 'integer' AND output_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    total_cost_micro_usd INTEGER CHECK (total_cost_micro_usd IS NULL OR (typeof(total_cost_micro_usd) = 'integer' AND total_cost_micro_usd BETWEEN 0 AND 9007199254740991)),
    price_provenance_digest TEXT CHECK (price_provenance_digest IS NULL OR (length(price_provenance_digest) = 64 AND price_provenance_digest NOT GLOB '*[^0-9a-f]*')),
    aggregate_only INTEGER NOT NULL DEFAULT 1 CHECK (aggregate_only IN (0, 1)),
    UNIQUE (usage_generation_id, period_kind, period_key, model, ownership_class),
    CHECK (covered_invocations <= expected_invocations),
    CHECK ((coverage = 'complete' AND covered_invocations = expected_invocations)
        OR coverage IN ('partial', 'unavailable')),
    CHECK ((coverage = 'unavailable' AND known_token_subtotal IS NULL AND known_cost_subtotal_micro_usd IS NULL)
        OR coverage <> 'unavailable'),
    CHECK ((period_kind = 'lifetime' AND period_key = 'lifetime')
        OR (period_kind = 'daily' AND period_key GLOB '20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]')),
    CHECK (ownership_class = 'steward-overhead' OR aggregate_only = 1),
    FOREIGN KEY (usage_generation_id)
        REFERENCES usage_generations (usage_generation_id)
);

CREATE TABLE usage_global_heads (
    period_kind TEXT NOT NULL CHECK (period_kind IN ('lifetime', 'daily')),
    period_key TEXT NOT NULL,
    model TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 256),
    ownership_class TEXT NOT NULL CHECK (ownership_class IN ('task-owned', 'steward-overhead')),
    usage_generation_id TEXT NOT NULL,
    global_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('visible', 'hidden')),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (period_kind, period_key, model, ownership_class),
    UNIQUE (usage_generation_id, global_id),
    FOREIGN KEY (usage_generation_id)
        REFERENCES usage_generations (usage_generation_id),
    FOREIGN KEY (global_id)
        REFERENCES usage_globals (global_id)
);

-- A global head may not relabel a generation or cross the ownership boundary.
-- The detached overhead owner is the only class allowed to have null task and
-- publication identities.
CREATE TRIGGER usage_global_head_ownership_guard
BEFORE INSERT ON usage_global_heads
WHEN NOT EXISTS (
    SELECT 1
      FROM usage_globals AS g
      JOIN usage_generations AS ug
        ON ug.usage_generation_id = g.usage_generation_id
     WHERE g.global_id = NEW.global_id
       AND g.usage_generation_id = NEW.usage_generation_id
       AND g.period_kind = NEW.period_kind
       AND g.period_key = NEW.period_key
       AND g.model = NEW.model
       AND g.ownership_class = NEW.ownership_class
       AND ug.ownership_class = NEW.ownership_class
       AND (ug.ownership_class = 'steward-overhead'
            AND ug.publication_id IS NULL AND ug.task_id IS NULL
            OR ug.ownership_class = 'task-owned'
            AND ug.publication_id IS NOT NULL AND ug.task_id IS NOT NULL)
)
BEGIN SELECT RAISE(ABORT, 'global head ownership mismatch'); END;

CREATE TRIGGER usage_global_head_ownership_update_guard
BEFORE UPDATE ON usage_global_heads
WHEN NOT EXISTS (
    SELECT 1
      FROM usage_globals AS g
      JOIN usage_generations AS ug
        ON ug.usage_generation_id = g.usage_generation_id
     WHERE g.global_id = NEW.global_id
       AND g.usage_generation_id = NEW.usage_generation_id
       AND g.period_kind = NEW.period_kind
       AND g.period_key = NEW.period_key
       AND g.model = NEW.model
       AND g.ownership_class = NEW.ownership_class
       AND ug.ownership_class = NEW.ownership_class
       AND (ug.ownership_class = 'steward-overhead'
            AND ug.publication_id IS NULL AND ug.task_id IS NULL
            OR ug.ownership_class = 'task-owned'
            AND ug.publication_id IS NOT NULL AND ug.task_id IS NOT NULL)
)
BEGIN SELECT RAISE(ABORT, 'global head ownership mismatch'); END;

CREATE UNIQUE INDEX one_visible_generation_per_task
    ON publication_generations (task_id) WHERE state = 'visible';
CREATE UNIQUE INDEX one_visible_usage_generation_per_task
    ON usage_generations (task_id) WHERE state = 'visible';
CREATE INDEX publication_task_state_order
    ON publication_generations (task_id, state, created_at);
CREATE INDEX usage_task_state_order
    ON usage_generations (task_id, state, created_at);
CREATE INDEX task_head_visibility_order
    ON task_heads (state, updated_at, task_id);
CREATE INDEX usage_head_visibility_order
    ON usage_heads (state, updated_at, task_id);
CREATE INDEX global_head_visibility_order
    ON usage_global_heads (state, updated_at, period_kind, period_key, model, ownership_class);
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
CREATE INDEX usage_summary_scope_order
    ON usage_summaries (task_id, scope, usage_generation_id, run_id, summary_id);
CREATE INDEX usage_invocation_run_retry_order
    ON usage_invocations (task_id, run_id, retry_ordinal, invocation_id);
CREATE INDEX usage_invocation_generation_order
    ON usage_invocations (usage_generation_id, retry_ordinal, invocation_id);
CREATE INDEX usage_turn_cursor_order
    ON usage_turns (invocation_id, ordinal, turn_id);
CREATE INDEX usage_turn_generation_order
    ON usage_turns (usage_generation_id, task_id, run_id, invocation_id, ordinal);
CREATE INDEX usage_price_model_time_order
    ON usage_prices (model, effective_at, price_entry_digest);
CREATE INDEX usage_global_summary_order
    ON usage_globals (period_kind, period_key, model, ownership_class, global_id);

-- Public child rows are immutable after a generation is exposed.
CREATE TRIGGER usage_invocations_immutable
BEFORE UPDATE ON usage_invocations
WHEN EXISTS (SELECT 1 FROM usage_generations AS g WHERE g.usage_generation_id = OLD.usage_generation_id AND g.state = 'visible')
BEGIN SELECT RAISE(ABORT, 'visible usage is immutable'); END;
CREATE TRIGGER usage_turns_immutable
BEFORE UPDATE ON usage_turns
WHEN EXISTS (SELECT 1 FROM usage_generations AS g WHERE g.usage_generation_id = OLD.usage_generation_id AND g.state = 'visible')
BEGIN SELECT RAISE(ABORT, 'visible usage is immutable'); END;
CREATE TRIGGER usage_summaries_immutable
BEFORE UPDATE ON usage_summaries
WHEN EXISTS (SELECT 1 FROM usage_generations AS g WHERE g.usage_generation_id = OLD.usage_generation_id AND g.state = 'visible')
BEGIN SELECT RAISE(ABORT, 'visible usage is immutable'); END;
CREATE TRIGGER usage_globals_immutable
BEFORE UPDATE ON usage_globals
WHEN EXISTS (SELECT 1 FROM usage_generations AS g WHERE g.usage_generation_id = OLD.usage_generation_id AND g.state = 'visible')
BEGIN SELECT RAISE(ABORT, 'visible usage is immutable'); END;
