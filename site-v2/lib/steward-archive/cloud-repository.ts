import "server-only";

import type { CloudReaderConfig } from "./cloud-config";
import { getCloudReaderConfig } from "./cloud-config";
import {
  createCloudflareD1Client,
  type D1ClientOptions,
  type D1QueryResponse,
  type D1Scalar,
} from "./cloudflare";
import {
  decodePublicationCursor,
  decodeUsageInvocationCursor,
  decodeUsageCursor,
  encodePublicationCursor,
  encodeUsageInvocationCursor,
  encodeUsageCursor,
  PublicationCursorError,
  resolvePublicObjectUrl,
  validatePublicArtifact,
  validatePublicEvent,
  validatePublicGeneration,
  validatePublicHead,
  validatePublicPipeline,
  validatePublicPublication,
  validatePublicRun,
  validatePublicTask,
  type PublicArtifact,
  type PublicEvent,
  type PublicPipeline,
  type PublicRun,
  type PublicationCursor,
} from "./publication";
import {
  validateCloudStatusData,
  validateCloudTaskDetailData,
  validateCloudTaskSummary,
  validateCloudTrajectoryDescriptorData,
  validateCloudUsageData,
  validateCloudUsageGlobal,
  validateCloudUsageGlobalGroup,
  validateCloudUsageInvocation,
  validateCloudUsageInvocationPageData,
  validateCloudUsageSummary,
  validateCloudUsageTurn,
  validateCloudUsageTurnPageData,
  validateCloudUsageUnavailable,
  type CloudArtifact,
  type CloudStatus,
  type CloudTaskDetail,
  type CloudTaskSummary,
  type CloudTrajectoryDescriptor,
  type CloudUsage,
  type CloudUsageGlobal,
  type CloudUsageGlobalGroup,
  type CloudUsageInvocation,
  type CloudUsageInvocationPage,
  type CloudUsageReadResult,
  type CloudUsageSummary,
  type CloudUsageTurn,
  type CloudUsageTurnPage,
  type CloudUsageUnavailable,
} from "./cloud-schema";

export type CloudTaskScope = "active" | "history";

export interface CloudD1QueryClient {
  query(statement: string, params?: readonly D1Scalar[]): Promise<D1QueryResponse>;
}

export interface CloudTaskPage {
  readonly tasks: readonly CloudTaskSummary[];
  readonly nextCursor: string | null;
  readonly previousCursor: string | null;
  readonly total: number;
}

export interface CloudTaskListOptions {
  readonly scope: CloudTaskScope;
  readonly cursor?: string | null;
  readonly limit?: number;
}

export interface CloudRepositoryOptions {
  readonly client?: CloudD1QueryClient;
  readonly config?: CloudReaderConfig;
  readonly d1Options?: D1ClientOptions;
}

export type CloudArtifactDescriptor = CloudArtifact & { readonly publicUrl: string };

export class CloudRepositoryDataError extends Error {
  readonly code = "INVALID_PUBLIC_DATA";

  constructor() {
    super("invalid visible Steward cloud data");
    this.name = "CloudRepositoryDataError";
  }
}

const MAX_PAGE_SIZE = 50;
const MAX_COUNT = 1_000_000;
const STATUS_VALIDATION_PAGE_SIZE = 128;
const MAX_DETAIL_PIPELINES = 1_000;
const MAX_DETAIL_RUNS = 10_000;
const MAX_DETAIL_EVENTS = 100_000;
const MAX_DETAIL_ARTIFACTS = 10_000;
const MAX_USAGE_SUMMARIES = 4_096;
const MAX_USAGE_INVOCATIONS = 128;
const MAX_USAGE_INVOCATION_PAGE_SIZE = 128;
const MAX_USAGE_GLOBALS = 4_096;
const MAX_USAGE_TURNS = 4_096;
const MAX_USAGE_TURN_PAGE_SIZE = 200;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$/;

const STATUS_COLUMNS = `
  h.updated_at AS head_updated_at,
  h.state AS head_state,
  p.publication_id AS publication_id,
  p.task_id AS generation_task_id,
  p.run_id AS generation_run_id,
  p.metadata_digest AS generation_metadata_digest,
  p.idempotency_key AS generation_idempotency_key,
  p.state AS generation_state,
  p.expected_task_count AS generation_expected_task_count,
  p.expected_pipeline_count AS generation_expected_pipeline_count,
  p.expected_run_count AS generation_expected_run_count,
  p.expected_event_count AS generation_expected_event_count,
  p.expected_artifact_count AS generation_expected_artifact_count,
  p.created_at AS generation_created_at,
  p.exposed_at AS generation_exposed_at,
  t.task_id AS task_id
`;

const STATUS_FROM = `
  FROM task_heads AS h
  JOIN publication_generations AS p
    ON p.publication_id = h.publication_id
   AND p.task_id = h.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  JOIN tasks AS t
    ON t.publication_id = p.publication_id
   AND t.task_id = h.task_id
 WHERE h.state = 'visible'
`;

/** The latest visible generation is the publication snapshot used by cursors. */
export const STATUS_STATEMENT = `
SELECT
  COUNT(*) AS task_count,
  MAX(p.exposed_at) AS latest_publication_at,
  (
    SELECT p2.publication_id
      FROM task_heads AS h2
      JOIN publication_generations AS p2
        ON p2.publication_id = h2.publication_id
       AND p2.task_id = h2.task_id
       AND p2.state = 'visible'
       AND p2.exposed_at IS NOT NULL
      JOIN tasks AS t2
        ON t2.publication_id = p2.publication_id
       AND t2.task_id = h2.task_id
     WHERE h2.state = 'visible'
     ORDER BY p2.exposed_at DESC, p2.publication_id DESC, p2.task_id DESC
     LIMIT 1
  ) AS latest_publication_id
${STATUS_FROM}
`;

export const STATUS_VALIDATION_STATEMENT = `
SELECT${STATUS_COLUMNS}${STATUS_FROM}
 ORDER BY p.exposed_at DESC, p.publication_id DESC, p.task_id DESC
 LIMIT ?
`;

export const STATUS_VALIDATION_NEXT_STATEMENT = `
SELECT${STATUS_COLUMNS}${STATUS_FROM}
  AND (
    p.exposed_at < ?
    OR (p.exposed_at = ? AND p.publication_id < ?)
    OR (p.exposed_at = ? AND p.publication_id = ? AND p.task_id < ?)
  )
 ORDER BY p.exposed_at DESC, p.publication_id DESC, p.task_id DESC
 LIMIT ?
`;

const TASK_COLUMNS = `
  h.updated_at AS head_updated_at,
  h.state AS head_state,
  p.publication_id AS publication_id,
  p.task_id AS generation_task_id,
  p.run_id AS generation_run_id,
  p.metadata_digest AS generation_metadata_digest,
  p.idempotency_key AS generation_idempotency_key,
  p.state AS generation_state,
  p.expected_task_count AS generation_expected_task_count,
  p.expected_pipeline_count AS generation_expected_pipeline_count,
  p.expected_run_count AS generation_expected_run_count,
  p.expected_event_count AS generation_expected_event_count,
  p.expected_artifact_count AS generation_expected_artifact_count,
  p.created_at AS generation_created_at,
  p.exposed_at AS generation_exposed_at,
  t.task_id AS task_id,
  t.title AS title,
  t.lifecycle_state AS lifecycle_state,
  t.created_at AS created_at,
  t.completed_at AS completed_at,
  p.expected_event_count AS expected_event_count,
  p.expected_artifact_count AS expected_artifact_count,
  COUNT(DISTINCT e.sequence) AS event_count,
  COUNT(DISTINCT a.artifact_id) AS artifact_count,
  r.pipeline_id AS pipeline_id,
  r.run_id AS run_id,
  r.run_state AS run_state,
  MIN(a.redaction_applied) AS redaction_applied_min,
  MAX(a.redaction_applied) AS redaction_applied_max,
  MIN(a.original_retained) AS original_retained_min,
  MAX(a.original_retained) AS original_retained_max
`;

const TASK_FROM = `
  FROM task_heads AS h
  JOIN publication_generations AS p
    ON p.publication_id = h.publication_id
   AND p.task_id = h.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  JOIN tasks AS t
    ON t.publication_id = p.publication_id
   AND t.task_id = h.task_id
  JOIN runs AS r
    ON r.publication_id = p.publication_id
   AND r.task_id = h.task_id
   AND r.run_id = p.run_id
  JOIN pipelines AS pl
    ON pl.publication_id = p.publication_id
   AND pl.task_id = t.task_id
   AND pl.pipeline_id = r.pipeline_id
  LEFT JOIN task_events AS e
    ON e.publication_id = p.publication_id
   AND e.task_id = t.task_id
  LEFT JOIN artifacts AS a
    ON a.publication_id = p.publication_id
   AND a.task_id = t.task_id
   AND a.run_id = r.run_id
 WHERE h.state = 'visible'
`;

const TASK_GROUP = `
 GROUP BY h.updated_at, h.state, p.publication_id, p.task_id, p.run_id,
          p.metadata_digest, p.idempotency_key, p.state,
          p.expected_task_count, p.expected_pipeline_count,
          p.expected_run_count, p.expected_event_count,
          p.expected_artifact_count, p.created_at, p.exposed_at,
          t.task_id, t.title,
          t.lifecycle_state, t.created_at, t.completed_at,
          p.expected_event_count, p.expected_artifact_count,
          r.pipeline_id, r.run_id, r.run_state
`;

export const ACTIVE_PAGE_FIRST_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state = 'active'
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const ACTIVE_PAGE_NEXT_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state = 'active'
  AND (h.updated_at < ? OR (h.updated_at = ? AND t.task_id < ?))
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const ACTIVE_PAGE_PREVIOUS_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state = 'active'
  AND (h.updated_at > ? OR (h.updated_at = ? AND t.task_id > ?))
${TASK_GROUP}
 ORDER BY h.updated_at ASC, t.task_id ASC
 LIMIT ?
`;

export const HISTORY_PAGE_FIRST_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const HISTORY_PAGE_NEXT_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
  AND (h.updated_at < ? OR (h.updated_at = ? AND t.task_id < ?))
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const HISTORY_PAGE_PREVIOUS_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
  AND (h.updated_at > ? OR (h.updated_at = ? AND t.task_id > ?))
${TASK_GROUP}
 ORDER BY h.updated_at ASC, t.task_id ASC
 LIMIT ?
`;

export const ACTIVE_COUNT_STATEMENT = `
SELECT COUNT(DISTINCT t.task_id) AS task_count
${TASK_FROM}
  AND t.lifecycle_state = 'active'
`;

export const HISTORY_COUNT_STATEMENT = `
SELECT COUNT(DISTINCT t.task_id) AS task_count
${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
`;

export const ACTIVE_CURSOR_STATEMENT = `
SELECT
  h.updated_at AS head_updated_at,
  h.state AS head_state,
  p.publication_id AS publication_id,
  p.task_id AS generation_task_id,
  p.run_id AS generation_run_id,
  p.metadata_digest AS generation_metadata_digest,
  p.idempotency_key AS generation_idempotency_key,
  p.state AS generation_state,
  p.expected_task_count AS generation_expected_task_count,
  p.expected_pipeline_count AS generation_expected_pipeline_count,
  p.expected_run_count AS generation_expected_run_count,
  p.expected_event_count AS generation_expected_event_count,
  p.expected_artifact_count AS generation_expected_artifact_count,
  p.created_at AS generation_created_at,
  p.exposed_at AS generation_exposed_at,
  t.task_id AS task_id
${TASK_FROM}
  AND t.lifecycle_state = 'active'
  AND h.updated_at = ?
  AND t.task_id = ?
 LIMIT 1
`;

export const HISTORY_CURSOR_STATEMENT = `
SELECT
  h.updated_at AS head_updated_at,
  h.state AS head_state,
  p.publication_id AS publication_id,
  p.task_id AS generation_task_id,
  p.run_id AS generation_run_id,
  p.metadata_digest AS generation_metadata_digest,
  p.idempotency_key AS generation_idempotency_key,
  p.state AS generation_state,
  p.expected_task_count AS generation_expected_task_count,
  p.expected_pipeline_count AS generation_expected_pipeline_count,
  p.expected_run_count AS generation_expected_run_count,
  p.expected_event_count AS generation_expected_event_count,
  p.expected_artifact_count AS generation_expected_artifact_count,
  p.created_at AS generation_created_at,
  p.exposed_at AS generation_exposed_at,
  t.task_id AS task_id
${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
  AND h.updated_at = ?
  AND t.task_id = ?
 LIMIT 1
`;

const DETAIL_VISIBLE_FROM = `
  FROM task_heads AS h
  JOIN publication_generations AS p
    ON p.publication_id = h.publication_id
   AND p.task_id = h.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  JOIN tasks AS t
    ON t.publication_id = p.publication_id
   AND t.task_id = p.task_id
`;

const DETAIL_TASK_VISIBLE_FROM = `
  FROM task_heads AS h
  JOIN publication_generations AS p
    ON p.publication_id = h.publication_id
   AND p.task_id = h.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  LEFT JOIN tasks AS t
    ON t.publication_id = p.publication_id
   AND t.task_id = p.task_id
`;

export const TASK_DETAIL_STATEMENT = `
SELECT
  h.updated_at AS head_updated_at,
  h.state AS head_state,
  p.publication_id AS publication_id,
  p.task_id AS generation_task_id,
  p.run_id AS generation_run_id,
  p.metadata_digest AS generation_metadata_digest,
  p.idempotency_key AS generation_idempotency_key,
  p.state AS generation_state,
  p.expected_task_count AS generation_expected_task_count,
  p.expected_pipeline_count AS generation_expected_pipeline_count,
  p.expected_run_count AS generation_expected_run_count,
  p.expected_event_count AS generation_expected_event_count,
  p.expected_artifact_count AS generation_expected_artifact_count,
  p.created_at AS generation_created_at,
  p.exposed_at AS generation_exposed_at,
  t.task_id AS task_id,
  t.title AS title,
  t.lifecycle_state AS lifecycle_state,
  t.created_at AS created_at,
  t.completed_at AS completed_at
${DETAIL_TASK_VISIBLE_FROM}
 WHERE h.state = 'visible'
   AND p.task_id = ?
 LIMIT 1
`;

export const TASK_DETAIL_PIPELINES_STATEMENT = `
SELECT
  pl.publication_id AS publication_id,
  pl.pipeline_id AS pipeline_id,
  pl.task_id AS task_id,
  pl.name AS name,
  pl.created_at AS created_at
${DETAIL_VISIBLE_FROM}
  JOIN pipelines AS pl
    ON pl.publication_id = p.publication_id
   AND pl.task_id = p.task_id
 WHERE h.state = 'visible'
   AND p.publication_id = ?
   AND p.task_id = ?
 ORDER BY pl.created_at ASC, pl.pipeline_id ASC
 LIMIT ?
`;

export const TASK_DETAIL_RUNS_STATEMENT = `
SELECT
  r.publication_id AS publication_id,
  r.run_id AS run_id,
  r.task_id AS task_id,
  r.pipeline_id AS pipeline_id,
  r.role AS role,
  r.run_state AS run_state,
  r.started_at AS started_at,
  r.completed_at AS completed_at,
  r.duration_ms AS duration_ms,
  r.atif_digest AS atif_digest
${DETAIL_VISIBLE_FROM}
  JOIN runs AS r
    ON r.publication_id = p.publication_id
   AND r.task_id = p.task_id
 WHERE h.state = 'visible'
   AND p.publication_id = ?
   AND p.task_id = ?
 ORDER BY r.started_at ASC, r.run_id ASC
 LIMIT ?
`;

export const TASK_DETAIL_EVENTS_STATEMENT = `
SELECT
  e.publication_id AS publication_id,
  e.task_id AS task_id,
  e.sequence AS sequence,
  e.event_type AS event_type,
  e.occurred_at AS occurred_at,
  e.summary AS summary
${DETAIL_VISIBLE_FROM}
  JOIN task_events AS e
    ON e.publication_id = p.publication_id
   AND e.task_id = p.task_id
 WHERE h.state = 'visible'
   AND p.publication_id = ?
   AND p.task_id = ?
 ORDER BY e.sequence ASC
 LIMIT ?
`;

export const TASK_DETAIL_ARTIFACTS_STATEMENT = `
SELECT
  a.publication_id AS publication_id,
  a.artifact_id AS artifact_id,
  a.task_id AS task_id,
  a.run_id AS run_id,
  a.logical_path AS logical_path,
  a.public_key AS public_key,
  a.media_type AS media_type,
  a.byte_size AS byte_size,
  a.sha256 AS sha256,
  a.availability AS availability,
  a.redaction_applied AS redaction_applied,
  a.original_retained AS original_retained
${DETAIL_VISIBLE_FROM}
  JOIN artifacts AS a
    ON a.publication_id = p.publication_id
   AND a.task_id = p.task_id
  JOIN runs AS r
    ON r.publication_id = p.publication_id
   AND r.task_id = p.task_id
   AND r.run_id = a.run_id
   AND r.run_id = p.run_id
  JOIN pipelines AS pl
    ON pl.publication_id = r.publication_id
   AND pl.task_id = r.task_id
   AND pl.pipeline_id = r.pipeline_id
 WHERE h.state = 'visible'
   AND p.publication_id = ?
   AND p.task_id = ?
 ORDER BY a.logical_path ASC, a.artifact_id ASC
 LIMIT ?
`;

export const ARTIFACT_DESCRIPTOR_STATEMENT = `
SELECT
  a.publication_id AS publication_id,
  a.artifact_id AS artifact_id,
  a.task_id AS task_id,
  a.run_id AS run_id,
  a.logical_path AS logical_path,
  a.public_key AS public_key,
  a.media_type AS media_type,
  a.byte_size AS byte_size,
  a.sha256 AS sha256,
  a.availability AS availability,
  a.redaction_applied AS redaction_applied,
  a.original_retained AS original_retained
${DETAIL_VISIBLE_FROM}
  JOIN artifacts AS a
    ON a.publication_id = p.publication_id
   AND a.task_id = p.task_id
  JOIN runs AS r
    ON r.publication_id = p.publication_id
   AND r.task_id = p.task_id
   AND r.run_id = a.run_id
   AND r.run_id = p.run_id
  JOIN pipelines AS pl
    ON pl.publication_id = r.publication_id
   AND pl.task_id = r.task_id
   AND pl.pipeline_id = r.pipeline_id
 WHERE h.state = 'visible'
   AND t.task_id = ?
   AND a.logical_path = ?
 LIMIT 2
`;

const USAGE_CONTEXT_FROM = `
  FROM task_heads AS th
  JOIN publication_generations AS p
    ON p.publication_id = th.publication_id
   AND p.task_id = th.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  JOIN tasks AS t
    ON t.publication_id = p.publication_id
   AND t.task_id = p.task_id
  LEFT JOIN usage_heads AS uh
    ON uh.task_id = th.task_id
  LEFT JOIN usage_generations AS ug
    ON ug.usage_generation_id = uh.usage_generation_id
   AND ug.publication_id = p.publication_id
   AND ug.task_id = p.task_id
   AND ug.state = 'visible'
   AND ug.exposed_at IS NOT NULL
 WHERE th.state = 'visible'
   AND th.task_id = ?
`;

const USAGE_CONTEXT_COLUMNS = `
  th.task_id AS task_id,
  th.publication_id AS publication_id,
  th.state AS task_head_state,
  th.updated_at AS task_head_updated_at,
  th.usage_generation_id AS task_head_usage_generation_id,
  p.publication_id AS generation_publication_id,
  p.state AS generation_state,
  p.exposed_at AS generation_exposed_at,
  uh.usage_generation_id AS usage_head_generation_id,
  uh.state AS usage_head_state,
  uh.updated_at AS usage_head_updated_at,
  ug.usage_generation_id AS usage_generation_id,
  ug.publication_id AS usage_publication_id,
  ug.task_id AS usage_task_id,
  ug.schema_version AS usage_schema_version,
  ug.metadata_digest AS usage_metadata_digest,
  ug.state AS usage_generation_state,
  ug.exposed_at AS usage_generation_exposed_at
`;

/** Visible task and usage heads are the only usage ownership boundary. */
export const USAGE_CONTEXT_STATEMENT = `
SELECT${USAGE_CONTEXT_COLUMNS}
${USAGE_CONTEXT_FROM}
 LIMIT 1
`;

const USAGE_VISIBLE_FROM = `
  FROM usage_summaries AS s INDEXED BY usage_summary_scope_order
  CROSS JOIN usage_generations AS ug
    ON ug.usage_generation_id = s.usage_generation_id
   AND ug.publication_id = s.publication_id
   AND ug.task_id = s.task_id
   AND ug.state = 'visible'
   AND ug.exposed_at IS NOT NULL
  CROSS JOIN usage_heads AS uh
    ON uh.task_id = ug.task_id
   AND uh.usage_generation_id = ug.usage_generation_id
   AND uh.state = 'visible'
  CROSS JOIN task_heads AS th
    ON th.task_id = ug.task_id
   AND th.usage_generation_id = ug.usage_generation_id
   AND th.state = 'visible'
  CROSS JOIN publication_generations AS p
    ON p.publication_id = ug.publication_id
   AND p.task_id = ug.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
 WHERE s.task_id = ?
`;

const USAGE_SUMMARY_COLUMNS = `
  s.summary_id AS summary_id,
  s.usage_generation_id AS usage_generation_id,
  s.publication_id AS publication_id,
  s.task_id AS task_id,
  CASE WHEN s.scope = 'task' THEN NULL
       WHEN EXISTS (
         SELECT 1
           FROM runs AS r
           JOIN pipelines AS pl
             ON pl.publication_id = r.publication_id
            AND pl.task_id = r.task_id
            AND pl.pipeline_id = r.pipeline_id
          WHERE r.publication_id = s.publication_id
            AND r.task_id = s.task_id
            AND r.run_id = s.run_id
       ) THEN s.run_id
       ELSE NULL END AS run_id,
  s.scope AS scope,
  s.coverage AS coverage,
  s.covered_invocations AS covered_invocations,
  s.expected_invocations AS expected_invocations,
  s.known_token_subtotal AS known_token_subtotal,
  s.known_cost_subtotal_micro_usd AS known_cost_subtotal_micro_usd,
  s.prompt_tokens AS prompt_tokens,
  s.cached_tokens AS cached_tokens,
  s.uncached_tokens AS uncached_tokens,
  s.completion_tokens AS completion_tokens,
  s.reasoning_tokens AS reasoning_tokens,
  s.total_tokens AS total_tokens,
  s.uncached_input_cost_micro_usd AS uncached_input_cost_micro_usd,
  s.cached_input_cost_micro_usd AS cached_input_cost_micro_usd,
  s.output_cost_micro_usd AS output_cost_micro_usd,
  s.total_cost_micro_usd AS total_cost_micro_usd,
  s.price_provenance_digest AS price_provenance_digest
`;

export const USAGE_SUMMARY_STATEMENT = `
SELECT${USAGE_SUMMARY_COLUMNS}
${USAGE_VISIBLE_FROM}
 ORDER BY s.scope ASC, s.usage_generation_id ASC, s.run_id ASC, s.summary_id ASC
 LIMIT ?
`;

const USAGE_INVOCATION_COLUMNS = `
  i.invocation_id AS invocation_id,
  i.usage_generation_id AS usage_generation_id,
  i.publication_id AS publication_id,
  i.task_id AS task_id,
  CASE WHEN r.run_id IS NOT NULL AND pl.pipeline_id IS NOT NULL THEN i.pipeline_id ELSE NULL END AS pipeline_id,
  CASE WHEN r.run_id IS NOT NULL AND pl.pipeline_id IS NOT NULL THEN i.run_id ELSE NULL END AS run_id,
  i.ownership_class AS ownership_class,
  i.retry_ordinal AS retry_ordinal,
  i.started_at AS started_at,
  i.completed_at AS completed_at,
  i.model AS model,
  i.billing_mode AS billing_mode,
  i.process_outcome AS process_outcome,
  i.coverage AS coverage,
  i.issue_count AS issue_count,
  i.covered_turns AS covered_turns,
  i.expected_turns AS expected_turns,
  i.prompt_tokens AS prompt_tokens,
  i.cached_tokens AS cached_tokens,
  i.uncached_tokens AS uncached_tokens,
  i.completion_tokens AS completion_tokens,
  i.reasoning_tokens AS reasoning_tokens,
  i.total_tokens AS total_tokens,
  i.uncached_input_cost_micro_usd AS uncached_input_cost_micro_usd,
  i.cached_input_cost_micro_usd AS cached_input_cost_micro_usd,
  i.output_cost_micro_usd AS output_cost_micro_usd,
  i.total_cost_micro_usd AS total_cost_micro_usd,
  i.price_entry_digest AS price_entry_digest
`;

const USAGE_INVOCATION_FROM = `
  FROM usage_invocations AS i
  JOIN usage_generations AS ug
    ON ug.usage_generation_id = i.usage_generation_id
   AND ug.publication_id = i.publication_id
   AND ug.task_id = i.task_id
   AND ug.state = 'visible'
   AND ug.exposed_at IS NOT NULL
  JOIN usage_heads AS uh
    ON uh.task_id = ug.task_id
   AND uh.usage_generation_id = ug.usage_generation_id
   AND uh.state = 'visible'
  JOIN task_heads AS th
    ON th.task_id = ug.task_id
   AND th.usage_generation_id = ug.usage_generation_id
   AND th.state = 'visible'
  JOIN publication_generations AS p
    ON p.publication_id = ug.publication_id
   AND p.task_id = ug.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  LEFT JOIN runs AS r
    ON r.publication_id = i.publication_id
   AND r.task_id = i.task_id
   AND r.run_id = i.run_id
   AND r.pipeline_id = i.pipeline_id
  LEFT JOIN pipelines AS pl
    ON pl.publication_id = r.publication_id
   AND pl.task_id = r.task_id
   AND pl.pipeline_id = r.pipeline_id
 WHERE i.task_id = ?
   AND i.ownership_class = 'task-owned'
`;

export const USAGE_INVOCATION_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
 ORDER BY i.run_id ASC, i.retry_ordinal ASC, i.invocation_id ASC
 LIMIT ?
`;

export const USAGE_INVOCATION_CONTEXT_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
  AND i.invocation_id = ?
 LIMIT 1
`;

export const USAGE_INVOCATION_RUN_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
  AND i.run_id = ?
 ORDER BY i.retry_ordinal ASC, i.invocation_id ASC
 LIMIT ?
`;

export const USAGE_INVOCATION_FIRST_STATEMENT = USAGE_INVOCATION_STATEMENT;
export const USAGE_INVOCATION_NEXT_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
  AND (
    i.run_id > ?
    OR (i.run_id = ? AND (i.retry_ordinal > ? OR (i.retry_ordinal = ? AND i.invocation_id > ?)))
  )
 ORDER BY i.run_id ASC, i.retry_ordinal ASC, i.invocation_id ASC
 LIMIT ?
`;
export const USAGE_INVOCATION_PREVIOUS_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
  AND (
    i.run_id < ?
    OR (i.run_id = ? AND (i.retry_ordinal < ? OR (i.retry_ordinal = ? AND i.invocation_id < ?)))
  )
 ORDER BY i.run_id DESC, i.retry_ordinal DESC, i.invocation_id DESC
 LIMIT ?
`;
export const USAGE_INVOCATION_RUN_FIRST_STATEMENT = USAGE_INVOCATION_RUN_STATEMENT;
export const USAGE_INVOCATION_RUN_NEXT_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
  AND i.run_id = ?
  AND (i.retry_ordinal > ? OR (i.retry_ordinal = ? AND i.invocation_id > ?))
 ORDER BY i.retry_ordinal ASC, i.invocation_id ASC
 LIMIT ?
`;
export const USAGE_INVOCATION_RUN_PREVIOUS_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
  AND i.run_id = ?
  AND (i.retry_ordinal < ? OR (i.retry_ordinal = ? AND i.invocation_id < ?))
 ORDER BY i.retry_ordinal DESC, i.invocation_id DESC
 LIMIT ?
`;
export const USAGE_INVOCATION_BOUNDARY_STATEMENT = `
SELECT${USAGE_INVOCATION_COLUMNS}
${USAGE_INVOCATION_FROM}
  AND i.run_id = ?
  AND i.retry_ordinal = ?
  AND i.invocation_id = ?
 LIMIT 1
`;
/**
 * Invocation totals are cached on the task/run summary rows.  Keep the
 * lookup bounded to one visible summary rather than scanning child rows at
 * request time.  The legacy COUNT names remain aliases for callers that
 * already dispatch on the exported statement identity.
 */
export const USAGE_INVOCATION_TOTAL_STATEMENT = `
SELECT s.expected_invocations AS invocation_count
${USAGE_VISIBLE_FROM}
  AND s.scope = 'task'
  AND s.run_id IS NULL
 LIMIT 1
`;
export const USAGE_INVOCATION_RUN_TOTAL_STATEMENT = `
SELECT s.expected_invocations AS invocation_count
${USAGE_VISIBLE_FROM}
  AND s.scope = 'run'
  AND s.run_id = ?
 LIMIT 1
`;
export const USAGE_INVOCATION_COUNT_STATEMENT = USAGE_INVOCATION_TOTAL_STATEMENT;
export const USAGE_INVOCATION_RUN_COUNT_STATEMENT = USAGE_INVOCATION_RUN_TOTAL_STATEMENT;

const USAGE_GLOBAL_VISIBLE_FROM = `
  FROM usage_global_heads AS gh
  JOIN usage_globals AS g
    ON g.global_id = gh.global_id
   AND g.usage_generation_id = gh.usage_generation_id
   AND g.period_kind = gh.period_kind
   AND g.period_key = gh.period_key
   AND g.model = gh.model
   AND g.ownership_class = gh.ownership_class
  JOIN usage_generations AS ug
    ON ug.usage_generation_id = gh.usage_generation_id
   AND ug.state = 'visible'
   AND ug.exposed_at IS NOT NULL
  JOIN usage_heads AS uh
    ON uh.task_id = ug.task_id
   AND uh.usage_generation_id = ug.usage_generation_id
   AND uh.state = 'visible'
  JOIN task_heads AS th
    ON th.task_id = ug.task_id
   AND th.usage_generation_id = ug.usage_generation_id
   AND th.state = 'visible'
  JOIN publication_generations AS p
    ON p.publication_id = ug.publication_id
   AND p.task_id = ug.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
 WHERE gh.state = 'visible'
`;

const USAGE_GLOBAL_COLUMNS = `
  g.global_id AS global_id,
  g.usage_generation_id AS usage_generation_id,
  g.period_kind AS period_kind,
  g.period_key AS period_key,
  g.model AS model,
  g.ownership_class AS ownership_class,
  g.coverage AS coverage,
  g.covered_invocations AS covered_invocations,
  g.expected_invocations AS expected_invocations,
  g.known_token_subtotal AS known_token_subtotal,
  g.known_cost_subtotal_micro_usd AS known_cost_subtotal_micro_usd,
  g.prompt_tokens AS prompt_tokens,
  g.cached_tokens AS cached_tokens,
  g.uncached_tokens AS uncached_tokens,
  g.completion_tokens AS completion_tokens,
  g.reasoning_tokens AS reasoning_tokens,
  g.total_tokens AS total_tokens,
  g.uncached_input_cost_micro_usd AS uncached_input_cost_micro_usd,
  g.cached_input_cost_micro_usd AS cached_input_cost_micro_usd,
  g.output_cost_micro_usd AS output_cost_micro_usd,
  g.total_cost_micro_usd AS total_cost_micro_usd,
  g.price_provenance_digest AS price_provenance_digest,
  g.aggregate_only AS aggregate_only
`;

export const USAGE_GLOBAL_STATEMENT = `
SELECT${USAGE_GLOBAL_COLUMNS}
${USAGE_GLOBAL_VISIBLE_FROM}
 ORDER BY gh.updated_at ASC, gh.period_kind ASC, gh.period_key ASC, gh.model ASC, gh.ownership_class ASC
 LIMIT ?
`;
export const USAGE_GLOBALS_STATEMENT = USAGE_GLOBAL_STATEMENT;

const USAGE_TURN_COLUMNS = `
  u.turn_id AS turn_id,
  u.usage_generation_id AS usage_generation_id,
  u.invocation_id AS invocation_id,
  u.publication_id AS publication_id,
  u.task_id AS task_id,
  u.run_id AS run_id,
  u.ordinal AS ordinal,
  u.prompt_tokens AS prompt_tokens,
  u.cached_tokens AS cached_tokens,
  u.uncached_tokens AS uncached_tokens,
  u.completion_tokens AS completion_tokens,
  u.reasoning_tokens AS reasoning_tokens,
  u.total_tokens AS total_tokens,
  u.uncached_input_cost_micro_usd AS uncached_input_cost_micro_usd,
  u.cached_input_cost_micro_usd AS cached_input_cost_micro_usd,
  u.output_cost_micro_usd AS output_cost_micro_usd,
  u.total_cost_micro_usd AS total_cost_micro_usd,
  u.price_entry_digest AS price_entry_digest
`;

const USAGE_TURN_FROM = `
  FROM usage_turns AS u
  JOIN usage_invocations AS i
    ON i.invocation_id = u.invocation_id
   AND i.usage_generation_id = u.usage_generation_id
   AND i.ownership_class = 'task-owned'
   AND i.task_id = u.task_id
   AND i.run_id = u.run_id
  JOIN runs AS r
    ON r.publication_id = i.publication_id
   AND r.task_id = i.task_id
   AND r.run_id = i.run_id
   AND r.pipeline_id = i.pipeline_id
  JOIN pipelines AS pl
    ON pl.publication_id = r.publication_id
   AND pl.task_id = r.task_id
   AND pl.pipeline_id = r.pipeline_id
  JOIN usage_generations AS ug
    ON ug.usage_generation_id = u.usage_generation_id
   AND ug.publication_id = u.publication_id
   AND ug.task_id = u.task_id
   AND ug.state = 'visible'
   AND ug.exposed_at IS NOT NULL
  JOIN usage_heads AS uh
    ON uh.task_id = u.task_id
   AND uh.usage_generation_id = u.usage_generation_id
   AND uh.state = 'visible'
  JOIN task_heads AS th
    ON th.task_id = u.task_id
   AND th.usage_generation_id = u.usage_generation_id
   AND th.state = 'visible'
  JOIN publication_generations AS p
    ON p.publication_id = u.publication_id
   AND p.task_id = u.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
 WHERE u.task_id = ?
   AND u.invocation_id = ?
`;

export const USAGE_TURN_FIRST_STATEMENT = `
SELECT${USAGE_TURN_COLUMNS}
${USAGE_TURN_FROM}
 ORDER BY u.ordinal ASC, u.turn_id ASC
 LIMIT ?
`;
export const USAGE_TURN_NEXT_STATEMENT = `
SELECT${USAGE_TURN_COLUMNS}
${USAGE_TURN_FROM}
  AND (u.ordinal > ? OR (u.ordinal = ? AND u.turn_id > ?))
 ORDER BY u.ordinal ASC, u.turn_id ASC
 LIMIT ?
`;
export const USAGE_TURN_PREVIOUS_STATEMENT = `
SELECT${USAGE_TURN_COLUMNS}
${USAGE_TURN_FROM}
  AND (u.ordinal < ? OR (u.ordinal = ? AND u.turn_id < ?))
 ORDER BY u.ordinal DESC, u.turn_id DESC
 LIMIT ?
`;
export const USAGE_TURN_BOUNDARY_STATEMENT = `
SELECT${USAGE_TURN_COLUMNS}
${USAGE_TURN_FROM}
  AND u.ordinal = ?
  AND u.turn_id = ?
 LIMIT 1
`;
export const USAGE_TURN_COUNT_STATEMENT = `
SELECT COUNT(*) AS turn_count
${USAGE_TURN_FROM}
`;
export const USAGE_TURNS_FIRST_STATEMENT = USAGE_TURN_FIRST_STATEMENT;
export const USAGE_TURNS_NEXT_STATEMENT = USAGE_TURN_NEXT_STATEMENT;
export const USAGE_TURNS_PREVIOUS_STATEMENT = USAGE_TURN_PREVIOUS_STATEMENT;

const SCOPE_QUERY: Record<CloudTaskScope, string> = {
  active: "tasks-active",
  history: "tasks-history",
};

const PAGE_STATEMENTS: Record<CloudTaskScope, Record<"first" | "next" | "previous", string>> = {
  active: { first: ACTIVE_PAGE_FIRST_STATEMENT, next: ACTIVE_PAGE_NEXT_STATEMENT, previous: ACTIVE_PAGE_PREVIOUS_STATEMENT },
  history: { first: HISTORY_PAGE_FIRST_STATEMENT, next: HISTORY_PAGE_NEXT_STATEMENT, previous: HISTORY_PAGE_PREVIOUS_STATEMENT },
};

const COUNT_STATEMENTS: Record<CloudTaskScope, string> = { active: ACTIVE_COUNT_STATEMENT, history: HISTORY_COUNT_STATEMENT };
const CURSOR_STATEMENTS: Record<CloudTaskScope, string> = { active: ACTIVE_CURSOR_STATEMENT, history: HISTORY_CURSOR_STATEMENT };

type CursorDirection = "next" | "previous";
type DecodedTaskCursor = { direction: CursorDirection; updatedAt: string; taskId: string };

const STATUS_SUMMARY_KEYS = ["task_count", "latest_publication_at", "latest_publication_id"] as const;
const STATUS_VALIDATION_KEYS = [
  "head_updated_at", "head_state", "publication_id",
  "generation_task_id", "generation_run_id", "generation_metadata_digest", "generation_idempotency_key", "generation_state",
  "generation_expected_task_count", "generation_expected_pipeline_count", "generation_expected_run_count",
  "generation_expected_event_count", "generation_expected_artifact_count", "generation_created_at", "generation_exposed_at", "task_id",
] as const;
const TASK_KEYS = [
  "head_updated_at", "head_state", "publication_id", "generation_task_id", "generation_run_id", "generation_metadata_digest",
  "generation_idempotency_key", "generation_state", "generation_expected_task_count", "generation_expected_pipeline_count",
  "generation_expected_run_count", "generation_expected_event_count", "generation_expected_artifact_count", "generation_created_at",
  "generation_exposed_at", "task_id", "title", "lifecycle_state", "created_at", "completed_at",
  "expected_event_count", "expected_artifact_count", "event_count", "artifact_count", "pipeline_id", "run_id", "run_state",
  "redaction_applied_min", "redaction_applied_max", "original_retained_min", "original_retained_max",
] as const;
const COUNT_KEYS = ["task_count"] as const;
const CURSOR_KEYS = [
  "head_updated_at", "head_state", "publication_id", "generation_task_id", "generation_run_id", "generation_metadata_digest",
  "generation_idempotency_key", "generation_state", "generation_expected_task_count", "generation_expected_pipeline_count",
  "generation_expected_run_count", "generation_expected_event_count", "generation_expected_artifact_count", "generation_created_at",
  "generation_exposed_at", "task_id",
] as const;
const DETAIL_TASK_KEYS = [
  "head_updated_at", "head_state", "publication_id", "generation_task_id", "generation_run_id", "generation_metadata_digest",
  "generation_idempotency_key", "generation_state", "generation_expected_task_count", "generation_expected_pipeline_count",
  "generation_expected_run_count", "generation_expected_event_count", "generation_expected_artifact_count", "generation_created_at",
  "generation_exposed_at", "task_id", "title", "lifecycle_state", "created_at", "completed_at",
] as const;
const PIPELINE_KEYS = ["publication_id", "pipeline_id", "task_id", "name", "created_at"] as const;
const RUN_KEYS = ["publication_id", "run_id", "task_id", "pipeline_id", "role", "run_state", "started_at", "completed_at", "duration_ms", "atif_digest"] as const;
const EVENT_KEYS = ["publication_id", "task_id", "sequence", "event_type", "occurred_at", "summary"] as const;
const ARTIFACT_KEYS = [
  "publication_id", "artifact_id", "task_id", "run_id", "logical_path", "public_key", "media_type", "byte_size", "sha256", "availability",
  "redaction_applied", "original_retained",
] as const;
const USAGE_CONTEXT_KEYS = [
  "task_id", "publication_id", "task_head_state", "task_head_updated_at", "task_head_usage_generation_id",
  "generation_publication_id", "generation_state", "generation_exposed_at", "usage_head_generation_id", "usage_head_state",
  "usage_head_updated_at", "usage_generation_id", "usage_publication_id", "usage_task_id", "usage_schema_version",
  "usage_metadata_digest", "usage_generation_state", "usage_generation_exposed_at",
] as const;
const USAGE_SUMMARY_ROW_KEYS = [
  "summary_id", "usage_generation_id", "publication_id", "task_id", "run_id", "scope", "coverage", "covered_invocations",
  "expected_invocations", "known_token_subtotal", "known_cost_subtotal_micro_usd", "prompt_tokens", "cached_tokens", "uncached_tokens",
  "completion_tokens", "reasoning_tokens", "total_tokens", "uncached_input_cost_micro_usd", "cached_input_cost_micro_usd",
  "output_cost_micro_usd", "total_cost_micro_usd", "price_provenance_digest"] as const;
const USAGE_INVOCATION_ROW_KEYS = [
  "invocation_id", "usage_generation_id", "publication_id", "task_id", "pipeline_id", "run_id", "ownership_class", "retry_ordinal",
  "started_at", "completed_at", "model", "billing_mode", "process_outcome", "coverage", "issue_count", "covered_turns", "expected_turns",
  "prompt_tokens", "cached_tokens", "uncached_tokens", "completion_tokens", "reasoning_tokens", "total_tokens",
  "uncached_input_cost_micro_usd", "cached_input_cost_micro_usd", "output_cost_micro_usd", "total_cost_micro_usd", "price_entry_digest"] as const;
const USAGE_GLOBAL_ROW_KEYS = [
  "global_id", "usage_generation_id", "period_kind", "period_key", "model", "ownership_class", "coverage", "covered_invocations",
  "expected_invocations", "known_token_subtotal", "known_cost_subtotal_micro_usd", "prompt_tokens", "cached_tokens", "uncached_tokens",
  "completion_tokens", "reasoning_tokens", "total_tokens", "uncached_input_cost_micro_usd", "cached_input_cost_micro_usd",
  "output_cost_micro_usd", "total_cost_micro_usd", "price_provenance_digest", "aggregate_only"] as const;
const USAGE_TURN_ROW_KEYS = [
  "turn_id", "usage_generation_id", "invocation_id", "publication_id", "task_id", "run_id", "ordinal", "prompt_tokens", "cached_tokens",
  "uncached_tokens", "completion_tokens", "reasoning_tokens", "total_tokens", "uncached_input_cost_micro_usd",
  "cached_input_cost_micro_usd", "output_cost_micro_usd", "total_cost_micro_usd", "price_entry_digest"] as const;

function invalidData(): never {
  throw new CloudRepositoryDataError();
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalidData();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalidData();
  return value as Record<string, unknown>;
}

function isClient(value: unknown): value is CloudD1QueryClient {
  return Boolean(value) && typeof value === "object" && typeof (value as { query?: unknown }).query === "function";
}

function isConfig(value: unknown): value is CloudReaderConfig {
  return Boolean(value)
    && typeof value === "object"
    && typeof (value as { accountId?: unknown }).accountId === "string"
    && typeof (value as { databaseId?: unknown }).databaseId === "string"
    && typeof (value as { d1ReadToken?: unknown }).d1ReadToken === "string"
    && typeof (value as { publicR2BaseUrl?: unknown }).publicR2BaseUrl === "string";
}

function exactRow(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const row = record(value);
  const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) invalidData();
  return row;
}

function rowsFromResponse(response: unknown): readonly Record<string, unknown>[] {
  const envelope = record(response);
  if (Object.keys(envelope).length !== 1 || !Array.isArray(envelope.result) || envelope.result.length !== 1) invalidData();
  const resultSet = record(envelope.result[0]);
  if (Object.keys(resultSet).length !== 2 || !Array.isArray(resultSet.results) || !record(resultSet.meta)) invalidData();
  return resultSet.results.map((row) => record(row));
}

function boundedInteger(value: unknown, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) invalidData();
  return value;
}

function id(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value)) invalidData();
  return value;
}

function timestamp(value: unknown): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) invalidData();
  try {
    validateCloudStatusData({ state: "empty", taskCount: 0, latestPublicationAt: value });
  } catch {
    invalidData();
  }
  return value;
}

function validatePublicContract(row: Record<string, unknown>, expectedRunId?: string) {
  try {
    const generation = validatePublicGeneration({
      publication_id: row.publication_id,
      task_id: row.generation_task_id,
      run_id: row.generation_run_id,
      metadata_digest: row.generation_metadata_digest,
      idempotency_key: row.generation_idempotency_key,
      state: row.generation_state,
      expected_task_count: row.generation_expected_task_count,
      expected_pipeline_count: row.generation_expected_pipeline_count,
      expected_run_count: row.generation_expected_run_count,
      expected_event_count: row.generation_expected_event_count,
      expected_artifact_count: row.generation_expected_artifact_count,
      created_at: row.generation_created_at,
      exposed_at: row.generation_exposed_at,
    });
    const head = validatePublicHead({
      task_id: row.task_id,
      publication_id: row.publication_id,
      state: row.head_state,
      updated_at: row.head_updated_at,
    });
    if (generation.task_id !== row.task_id || generation.publication_id !== row.publication_id) invalidData();
    if (head.task_id !== row.task_id || head.publication_id !== row.publication_id) invalidData();
    if (expectedRunId !== undefined && generation.run_id !== expectedRunId) invalidData();
    return { generation, head };
  } catch {
    invalidData();
  }
}

function disclosure(value: unknown): boolean {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  invalidData();
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

function validLogicalPath(value: unknown): value is string {
  return typeof value === "string"
    && value.length >= 1
    && value.length <= 1024
    && !value.startsWith("/")
    && !value.includes("\\")
    && !value.includes("..")
    && !value.includes("://")
    && ![...value].some((character) => character.charCodeAt(0) < 0x20);
}

function safeValidate<T>(validate: () => T): T {
  try {
    return validate();
  } catch {
    invalidData();
  }
}

function isUsageUnavailable(value: unknown): value is CloudUsageUnavailable {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && (value as { kind?: unknown }).kind === "unavailable";
}

type UsageRowsResult = readonly Record<string, unknown>[] | CloudUsageUnavailable;

async function queryUsageRows(
  client: CloudD1QueryClient,
  statement: string,
  params: readonly D1Scalar[],
): Promise<UsageRowsResult> {
  let response: D1QueryResponse;
  try {
    response = await client.query(statement, params);
  } catch {
    return usageUnavailable("unavailable");
  }
  try {
    return rowsFromResponse(response);
  } catch {
    return usageUnavailable("invalid");
  }
}

type UsageContext = {
  readonly taskId: string;
  readonly publicationId: string;
  readonly usageGenerationId: string | null;
  readonly generationExposedAt: string;
};

function usageUnavailable(reason: "missing" | "invalid" | "unavailable"): CloudUsageUnavailable {
  return validateCloudUsageUnavailable({ kind: "unavailable", reason });
}

function exactUsageRow(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const row = record(value);
  const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) invalidData();
  return row;
}

function usageId(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !ID.test(value)) invalidData();
  return value;
}

function usageTimestamp(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !TIMESTAMP.test(value)) invalidData();
  try {
    validateCloudStatusData({ state: "empty", taskCount: 0, latestPublicationAt: value });
  } catch {
    invalidData();
  }
  return value;
}

function parseUsageContext(value: unknown): UsageContext {
  const row = exactUsageRow(value, USAGE_CONTEXT_KEYS);
  const taskId = usageId(row.task_id)!;
  const publicationId = usageId(row.publication_id)!;
  if (row.task_head_state !== "visible" || row.generation_publication_id !== publicationId || row.generation_state !== "visible") invalidData();
  const generationExposedAt = usageTimestamp(row.generation_exposed_at)!;
  usageTimestamp(row.task_head_updated_at);
  const taskHeadGenerationId = usageId(row.task_head_usage_generation_id)!;
  const usageHeadGenerationId = usageId(row.usage_head_generation_id, true);
  const usageGenerationId = usageId(row.usage_generation_id, true);
  const usageHeadState = row.usage_head_state;
  const hasUsage = usageGenerationId !== null;
  if (!hasUsage) {
    if (usageHeadGenerationId !== null || usageHeadState !== null || row.usage_head_updated_at !== null || row.usage_publication_id !== null || row.usage_task_id !== null || row.usage_schema_version !== null || row.usage_metadata_digest !== null || row.usage_generation_state !== null || row.usage_generation_exposed_at !== null) {
      invalidData();
    }
    return { taskId, publicationId, usageGenerationId: null, generationExposedAt };
  }
  if (usageHeadGenerationId !== usageGenerationId || usageHeadState !== "visible" || row.usage_publication_id !== publicationId || row.usage_task_id !== taskId || row.usage_schema_version !== "1.0" || row.usage_generation_state !== "visible" || usageTimestamp(row.usage_generation_exposed_at) === null || usageTimestamp(row.usage_head_updated_at) === null || taskHeadGenerationId !== usageGenerationId) invalidData();
  if (typeof row.usage_metadata_digest !== "string" || !/^[0-9a-f]{64}$/.test(row.usage_metadata_digest)) invalidData();
  return { taskId, publicationId, usageGenerationId, generationExposedAt };
}

function parseUsageSummaryRow(value: unknown): CloudUsageSummary {
  const row = exactUsageRow(value, USAGE_SUMMARY_ROW_KEYS);
  return safeValidate(() => validateCloudUsageSummary({
    summaryId: row.summary_id,
    usageGenerationId: row.usage_generation_id,
    publicationId: row.publication_id,
    taskId: row.task_id,
    runId: row.run_id,
    scope: row.scope,
    coverage: row.coverage,
    coveredInvocations: row.covered_invocations,
    expectedInvocations: row.expected_invocations,
    knownTokenSubtotal: row.known_token_subtotal,
    knownCostSubtotalMicroUsd: row.known_cost_subtotal_micro_usd,
    promptTokens: row.prompt_tokens,
    cachedTokens: row.cached_tokens,
    uncachedTokens: row.uncached_tokens,
    completionTokens: row.completion_tokens,
    reasoningTokens: row.reasoning_tokens,
    totalTokens: row.total_tokens,
    uncachedInputCostMicroUsd: row.uncached_input_cost_micro_usd,
    cachedInputCostMicroUsd: row.cached_input_cost_micro_usd,
    outputCostMicroUsd: row.output_cost_micro_usd,
    totalCostMicroUsd: row.total_cost_micro_usd,
    priceProvenanceDigest: row.price_provenance_digest,
  }));
}

function parseUsageInvocationRow(value: unknown): CloudUsageInvocation {
  const row = exactUsageRow(value, USAGE_INVOCATION_ROW_KEYS);
  return safeValidate(() => validateCloudUsageInvocation({
    invocationId: row.invocation_id,
    usageGenerationId: row.usage_generation_id,
    publicationId: row.publication_id,
    taskId: row.task_id,
    pipelineId: row.pipeline_id,
    runId: row.run_id,
    ownershipClass: row.ownership_class,
    retryOrdinal: row.retry_ordinal,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    model: row.model,
    billingMode: row.billing_mode,
    processOutcome: row.process_outcome,
    coverage: row.coverage,
    issueCount: row.issue_count,
    coveredTurns: row.covered_turns,
    expectedTurns: row.expected_turns,
    promptTokens: row.prompt_tokens,
    cachedTokens: row.cached_tokens,
    uncachedTokens: row.uncached_tokens,
    completionTokens: row.completion_tokens,
    reasoningTokens: row.reasoning_tokens,
    totalTokens: row.total_tokens,
    uncachedInputCostMicroUsd: row.uncached_input_cost_micro_usd,
    cachedInputCostMicroUsd: row.cached_input_cost_micro_usd,
    outputCostMicroUsd: row.output_cost_micro_usd,
    totalCostMicroUsd: row.total_cost_micro_usd,
    priceEntryDigest: row.price_entry_digest,
  }));
}

function parseUsageGlobalRow(value: unknown): CloudUsageGlobal {
  const row = exactUsageRow(value, USAGE_GLOBAL_ROW_KEYS);
  return safeValidate(() => validateCloudUsageGlobal({
    globalId: row.global_id,
    usageGenerationId: row.usage_generation_id,
    periodKind: row.period_kind,
    periodKey: row.period_key,
    model: row.model,
    ownershipClass: row.ownership_class,
    coverage: row.coverage,
    coveredInvocations: row.covered_invocations,
    expectedInvocations: row.expected_invocations,
    knownTokenSubtotal: row.known_token_subtotal,
    knownCostSubtotalMicroUsd: row.known_cost_subtotal_micro_usd,
    promptTokens: row.prompt_tokens,
    cachedTokens: row.cached_tokens,
    uncachedTokens: row.uncached_tokens,
    completionTokens: row.completion_tokens,
    reasoningTokens: row.reasoning_tokens,
    totalTokens: row.total_tokens,
    uncachedInputCostMicroUsd: row.uncached_input_cost_micro_usd,
    cachedInputCostMicroUsd: row.cached_input_cost_micro_usd,
    outputCostMicroUsd: row.output_cost_micro_usd,
    totalCostMicroUsd: row.total_cost_micro_usd,
    priceProvenanceDigest: row.price_provenance_digest,
    aggregateOnly: row.aggregate_only,
  }));
}

function parseUsageTurnRow(value: unknown): CloudUsageTurn {
  const row = exactUsageRow(value, USAGE_TURN_ROW_KEYS);
  return safeValidate(() => validateCloudUsageTurn({
    turnId: row.turn_id,
    usageGenerationId: row.usage_generation_id,
    invocationId: row.invocation_id,
    publicationId: row.publication_id,
    taskId: row.task_id,
    runId: row.run_id,
    ordinal: row.ordinal,
    promptTokens: row.prompt_tokens,
    cachedTokens: row.cached_tokens,
    uncachedTokens: row.uncached_tokens,
    completionTokens: row.completion_tokens,
    reasoningTokens: row.reasoning_tokens,
    totalTokens: row.total_tokens,
    uncachedInputCostMicroUsd: row.uncached_input_cost_micro_usd,
    cachedInputCostMicroUsd: row.cached_input_cost_micro_usd,
    outputCostMicroUsd: row.output_cost_micro_usd,
    totalCostMicroUsd: row.total_cost_micro_usd,
    priceEntryDigest: row.price_entry_digest,
  }));
}

function groupUsageGlobals(rows: readonly CloudUsageGlobal[]): CloudUsageGlobalGroup[] {
  const groups = new Map<string, { model: string; ownershipClass: CloudUsageGlobal["ownershipClass"]; lifetime: CloudUsageGlobal | null; daily: CloudUsageGlobal[] }>();
  for (const row of rows) {
    const key = `${row.model}\u0000${row.ownershipClass}`;
    const group = groups.get(key) ?? { model: row.model, ownershipClass: row.ownershipClass, lifetime: null, daily: [] };
    if (row.periodKind === "lifetime") {
      if (group.lifetime !== null) invalidData();
      group.lifetime = row;
    } else {
      if (group.daily.some((item) => item.periodKey === row.periodKey)) invalidData();
      group.daily.push(row);
    }
    groups.set(key, group);
  }
  return [...groups.values()].map((group) => safeValidate(() => validateCloudUsageGlobalGroup(group)));
}

function usageLimit(value: unknown, maximum: number, fallback = maximum): number {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value)) return value === Infinity ? maximum : 1;
  if (!Number.isSafeInteger(value)) return value > 0 ? maximum : 1;
  return Math.min(maximum, Math.max(1, value));
}

function usageCount(value: unknown): number {
  const row = exactUsageRow(value, ["turn_count"]);
  if (typeof row.turn_count !== "number" || !Number.isSafeInteger(row.turn_count) || row.turn_count < 0 || row.turn_count > MAX_USAGE_TURNS) invalidData();
  return row.turn_count;
}

function usageInvocationCount(value: unknown): number {
  const row = exactUsageRow(value, ["invocation_count"]);
  if (typeof row.invocation_count !== "number" || !Number.isSafeInteger(row.invocation_count) || row.invocation_count < 0 || row.invocation_count > MAX_COUNT) invalidData();
  return row.invocation_count;
}

function usageTurnSort(left: CloudUsageTurn, right: CloudUsageTurn): number {
  if (left.invocationId !== right.invocationId) return left.invocationId < right.invocationId ? -1 : 1;
  if (left.ordinal !== right.ordinal) return left.ordinal < right.ordinal ? -1 : 1;
  if (left.turnId !== right.turnId) return left.turnId < right.turnId ? -1 : 1;
  return 0;
}

type DecodedUsageTurnCursor = {
  readonly direction: "next" | "previous";
  readonly invocationId: string;
  readonly ordinal: number;
  readonly turnId: string;
};

type DecodedUsageInvocationCursor = {
  readonly direction: "next" | "previous";
  readonly runId: string;
  readonly retryOrdinal: number;
  readonly invocationId: string;
};

function decodeTurnPageCursor(value: unknown, context: UsageContext, invocationId: string, runId: string): DecodedUsageTurnCursor {
  if (!context.usageGenerationId) throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
  const cursor = decodeUsageCursor(value, {
    query: "usage-turns",
    publicationId: context.publicationId,
    usageGenerationId: context.usageGenerationId,
    taskId: context.taskId,
    runId,
    invocationId,
  });
  if (cursor.sort[0] !== invocationId) throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
  return { direction: cursor.direction, invocationId: cursor.invocationId, ordinal: cursor.sort[1], turnId: cursor.sort[2] };
}

function decodeInvocationPageCursor(value: unknown, context: UsageContext, runId: string | null): DecodedUsageInvocationCursor {
  if (!context.usageGenerationId) throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
  const cursor = decodeUsageInvocationCursor(value, {
    publicationId: context.publicationId,
    usageGenerationId: context.usageGenerationId,
    taskId: context.taskId,
    runId,
  });
  return { direction: cursor.direction, runId: cursor.sort[0], retryOrdinal: cursor.sort[1], invocationId: cursor.sort[2] };
}

function validateUsageInvocationOwner(
  invocation: CloudUsageInvocation,
  context: UsageContext,
  expectedRunId?: string,
): void {
  if (invocation.usageGenerationId !== context.usageGenerationId
    || invocation.publicationId !== context.publicationId
    || invocation.taskId !== context.taskId
    || invocation.ownershipClass !== "task-owned"
    || invocation.pipelineId === null
    || invocation.runId === null
    || invocation.invocationId === null) invalidData();
  if (expectedRunId !== undefined && invocation.runId !== expectedRunId) invalidData();
}

function detailLimit(expected: unknown, maximum: number): number {
  const count = boundedInteger(expected, MAX_COUNT);
  if (count > maximum) invalidData();
  return count + 1;
}

function exactDetailCount<T>(rows: readonly T[], expected: unknown, maximum: number): void {
  const count = boundedInteger(expected, MAX_COUNT);
  if (count > maximum || rows.length !== count || rows.length > maximum) invalidData();
}

function assertStrictOrder<T>(rows: readonly T[], key: (row: T) => string): void {
  for (let index = 1; index < rows.length; index += 1) {
    if (key(rows[index - 1]!) >= key(rows[index]!)) invalidData();
  }
}

type DetailTaskBase = {
  readonly generation: ReturnType<typeof validatePublicGeneration>;
  readonly head: ReturnType<typeof validatePublicHead>;
  readonly task: ReturnType<typeof validatePublicTask>;
};

function parseDetailTask(rowValue: unknown): DetailTaskBase {
  const row = exactRow(rowValue, DETAIL_TASK_KEYS);
  const { generation, head } = validatePublicContract(row);
  const task = safeValidate(() => validatePublicTask({
    publication_id: row.publication_id,
    task_id: row.task_id,
    title: row.title,
    lifecycle_state: row.lifecycle_state,
    created_at: row.created_at,
    completed_at: row.completed_at,
  }));
  if (task.task_id !== generation.task_id || task.publication_id !== generation.publication_id) invalidData();
  boundedInteger(generation.expected_pipeline_count, MAX_COUNT);
  boundedInteger(generation.expected_run_count, MAX_COUNT);
  boundedInteger(generation.expected_event_count, MAX_COUNT);
  boundedInteger(generation.expected_artifact_count, MAX_COUNT);
  return { generation, head, task };
}

function parseDetailPipeline(rowValue: unknown): PublicPipeline {
  return safeValidate(() => validatePublicPipeline(exactRow(rowValue, PIPELINE_KEYS)));
}

function parseDetailRun(rowValue: unknown): PublicRun {
  return safeValidate(() => validatePublicRun(exactRow(rowValue, RUN_KEYS)));
}

function parseDetailEvent(rowValue: unknown): PublicEvent {
  return safeValidate(() => validatePublicEvent(exactRow(rowValue, EVENT_KEYS)));
}

function parseDetailArtifact(rowValue: unknown): PublicArtifact {
  return safeValidate(() => validatePublicArtifact(exactRow(rowValue, ARTIFACT_KEYS)));
}

function publicDisclosure(artifacts: readonly PublicArtifact[]): { redactionApplied: boolean; originalRetained: boolean } {
  if (artifacts.length === 0) return { redactionApplied: false, originalRetained: false };
  const first = {
    redactionApplied: disclosure(artifacts[0]!.redaction_applied),
    originalRetained: disclosure(artifacts[0]!.original_retained),
  };
  for (const artifact of artifacts) {
    if (disclosure(artifact.redaction_applied) !== first.redactionApplied || disclosure(artifact.original_retained) !== first.originalRetained) {
      invalidData();
    }
  }
  return first;
}

type StatusSnapshot = {
  status: CloudStatus;
  publicationId: string | null;
  latestPublicationAt: string | null;
};

function parseStatusSummary(rowsValue: readonly Record<string, unknown>[]): StatusSnapshot {
  if (rowsValue.length === 0) {
    return {
      status: validateCloudStatusData({ state: "empty", taskCount: 0, latestPublicationAt: null }),
      publicationId: null,
      latestPublicationAt: null,
    };
  }
  if (rowsValue.length !== 1) invalidData();
  const row = exactRow(rowsValue[0], STATUS_SUMMARY_KEYS);
  const taskCount = boundedInteger(row.task_count, MAX_COUNT);
  const latestPublicationAt = row.latest_publication_at === null ? null : timestamp(row.latest_publication_at);
  const publicationId = row.latest_publication_id === null ? null : id(row.latest_publication_id);
  if (taskCount === 0 && (latestPublicationAt !== null || publicationId !== null)) invalidData();
  if (taskCount > 0 && (latestPublicationAt === null || publicationId === null)) invalidData();
  const status = validateCloudStatusData({
    state: taskCount === 0 ? "empty" : "available",
    taskCount,
    latestPublicationAt,
  });
  return { status, publicationId, latestPublicationAt };
}

type StatusValidationRow = {
  exposedAt: string;
  publicationId: string;
  taskId: string;
};

function parseStatusValidation(rowValue: unknown): StatusValidationRow {
  const row = exactRow(rowValue, STATUS_VALIDATION_KEYS);
  const exposedAt = timestamp(row.generation_exposed_at);
  const publicationId = id(row.publication_id);
  const taskId = id(row.task_id);
  validatePublicContract(row);
  return { exposedAt, publicationId, taskId };
}

function compareStatusKey(left: StatusValidationRow, right: StatusValidationRow): number {
  if (left.exposedAt !== right.exposedAt) return left.exposedAt < right.exposedAt ? -1 : 1;
  if (left.publicationId !== right.publicationId) return left.publicationId < right.publicationId ? -1 : 1;
  if (left.taskId !== right.taskId) return left.taskId < right.taskId ? -1 : 1;
  return 0;
}

function parseTask(rowValue: unknown): { task: CloudTaskSummary; updatedAt: string } {
  const row = exactRow(rowValue, TASK_KEYS);
  const updatedAt = timestamp(row.head_updated_at);
  const publicationId = id(row.publication_id);
  const taskId = id(row.task_id);
  const pipelineId = id(row.pipeline_id);
  const runId = id(row.run_id);
  const { generation } = validatePublicContract(row, runId);
  if (generation.task_id !== taskId || generation.publication_id !== publicationId) invalidData();
  const runState = row.run_state;
  if (runState !== "completed" && runState !== "failed" && runState !== "cancelled") invalidData();
  const completedRunId = runState === "completed" ? runId : null;
  const expectedEventCount = boundedInteger(row.expected_event_count, MAX_COUNT);
  const expectedArtifactCount = boundedInteger(row.expected_artifact_count, MAX_COUNT);
  const eventCount = boundedInteger(row.event_count, MAX_COUNT);
  const artifactCount = boundedInteger(row.artifact_count, MAX_COUNT);
  if (generation.expected_event_count !== expectedEventCount || generation.expected_artifact_count !== expectedArtifactCount) invalidData();
  if (expectedEventCount !== eventCount || expectedArtifactCount !== artifactCount || expectedArtifactCount === 0) invalidData();
  const redactionMin = disclosure(row.redaction_applied_min);
  const redactionMax = disclosure(row.redaction_applied_max);
  const originalMin = disclosure(row.original_retained_min);
  const originalMax = disclosure(row.original_retained_max);
  if (redactionMin !== redactionMax || originalMin !== originalMax) invalidData();
  const task = validateCloudTaskSummary({
    taskId,
    title: row.title,
    lifecycleState: row.lifecycle_state,
    createdAt: row.created_at,
    completedAt: row.completed_at,
    completeness: "complete",
    pipelineId,
    completedRunId,
    eventCount,
    artifactCount,
    disclosure: { redactionApplied: redactionMin, originalRetained: originalMin },
  });
  if (publicationId.length === 0) invalidData();
  return { task, updatedAt };
}

function parseCount(rowValue: unknown): number {
  const row = exactRow(rowValue, COUNT_KEYS);
  return boundedInteger(row.task_count, MAX_COUNT);
}

function parseCursorBoundary(rowValue: unknown, expected: DecodedTaskCursor): void {
  const row = exactRow(rowValue, CURSOR_KEYS);
  validatePublicContract(row);
  if (timestamp(row.head_updated_at) !== expected.updatedAt || id(row.task_id) !== expected.taskId) invalidData();
}

function cursorError(code: "INVALID_CURSOR" | "STALE_CURSOR"): never {
  throw new PublicationCursorError(code, code === "STALE_CURSOR" ? "cursor is stale" : "invalid cursor");
}

function decodeTaskCursor(value: unknown, scope: CloudTaskScope, publicationId: string): DecodedTaskCursor {
  let cursor: PublicationCursor;
  try {
    cursor = decodePublicationCursor(value, { query: SCOPE_QUERY[scope], publicationId });
  } catch (error) {
    if (error instanceof PublicationCursorError) throw error;
    cursorError("INVALID_CURSOR");
  }
  if (cursor.sort.length !== 3 || typeof cursor.sort[0] !== "string" || typeof cursor.sort[1] !== "string" || typeof cursor.sort[2] !== "string") cursorError("INVALID_CURSOR");
  const updatedAt = cursor.sort[0];
  const taskId = cursor.sort[1];
  const direction = cursor.sort[2];
  if (!TIMESTAMP.test(updatedAt) || !ID.test(taskId) || (direction !== "next" && direction !== "previous")) cursorError("INVALID_CURSOR");
  return { direction, updatedAt, taskId };
}

function boundedLimit(value: unknown): number {
  if (value === undefined) return MAX_PAGE_SIZE;
  if (typeof value !== "number" || Number.isNaN(value)) return MAX_PAGE_SIZE;
  if (!Number.isFinite(value)) return value > 0 ? MAX_PAGE_SIZE : 1;
  return Math.min(MAX_PAGE_SIZE, Math.max(1, Math.trunc(value)));
}

function parseListArguments(
  scopeOrOptions: CloudTaskScope | CloudTaskListOptions,
  optionsOrCursor?: CloudTaskListOptions | string | null,
  limit?: number,
): { scope: CloudTaskScope; cursor: string | null; limit: number } {
  if (typeof scopeOrOptions === "object") {
    if (scopeOrOptions.scope !== "active" && scopeOrOptions.scope !== "history") invalidData();
    return { scope: scopeOrOptions.scope, cursor: scopeOrOptions.cursor ?? null, limit: boundedLimit(scopeOrOptions.limit) };
  }
  if (scopeOrOptions !== "active" && scopeOrOptions !== "history") invalidData();
  if (typeof optionsOrCursor === "object" && optionsOrCursor !== null) {
    return { scope: scopeOrOptions, cursor: optionsOrCursor.cursor ?? null, limit: boundedLimit(optionsOrCursor.limit) };
  }
  return { scope: scopeOrOptions, cursor: optionsOrCursor ?? null, limit: boundedLimit(limit) };
}

function toCloudDisclosure(artifact: PublicArtifact): { redactionApplied: boolean; originalRetained: boolean } {
  return {
    redactionApplied: disclosure(artifact.redaction_applied),
    originalRetained: disclosure(artifact.original_retained),
  };
}

function toCloudArtifact(artifact: PublicArtifact): CloudArtifact {
  return {
    artifactId: artifact.artifact_id,
    taskId: artifact.task_id,
    runId: artifact.run_id,
    logicalPath: artifact.logical_path,
    publicKey: artifact.public_key,
    mediaType: artifact.media_type,
    byteSize: artifact.byte_size,
    sha256: artifact.sha256,
    availability: artifact.availability,
    disclosure: toCloudDisclosure(artifact),
  };
}

function buildTaskDetail(
  base: DetailTaskBase,
  pipelines: readonly PublicPipeline[],
  runs: readonly PublicRun[],
  events: readonly PublicEvent[],
  artifacts: readonly PublicArtifact[],
): CloudTaskDetail {
  const publication = safeValidate(() => validatePublicPublication({
    generation: base.generation,
    head: base.head,
    task: base.task,
    pipelines: [...pipelines],
    runs: [...runs],
    events: [...events],
    artifacts: [...artifacts],
  }));
  if (publication.generation.publication_id !== base.generation.publication_id || publication.task.task_id !== base.task.task_id) invalidData();
  assertStrictOrder(pipelines, (row) => `${row.created_at}\u0000${row.pipeline_id}`);
  assertStrictOrder(runs, (row) => `${row.started_at}\u0000${row.run_id}`);
  for (let index = 0; index < events.length; index += 1) if (events[index]!.sequence !== index + 1) invalidData();
  assertStrictOrder(artifacts, (row) => `${row.logical_path}\u0000${row.artifact_id}`);

  const canonicalRuns = runs.filter((run) => run.run_id === publication.generation.run_id);
  if (canonicalRuns.length !== 1) invalidData();
  const canonicalRun = canonicalRuns[0]!;
  const canonicalPipeline = pipelines.find((pipeline) => pipeline.pipeline_id === canonicalRun.pipeline_id);
  if (!canonicalPipeline) invalidData();
  const disclosureState = publicDisclosure(artifacts);
  const task = safeValidate(() => validateCloudTaskSummary({
    taskId: publication.task.task_id,
    title: publication.task.title,
    lifecycleState: publication.task.lifecycle_state,
    createdAt: publication.task.created_at,
    completedAt: publication.task.completed_at,
    completeness: "complete",
    pipelineId: canonicalPipeline.pipeline_id,
    completedRunId: canonicalRun.run_state === "completed" ? canonicalRun.run_id : null,
    eventCount: events.length,
    artifactCount: artifacts.length,
    disclosure: disclosureState,
  }));

  const cloudRuns = runs.map((run) => {
    const atifMatches = artifacts.filter((artifact) => artifact.run_id === run.run_id && artifact.sha256 === run.atif_digest && artifact.media_type === "application/json");
    return {
      runId: run.run_id,
      taskId: run.task_id,
      pipelineId: run.pipeline_id,
      role: run.role,
      runState: run.run_state,
      startedAt: run.started_at,
      completedAt: run.completed_at,
      durationMs: run.duration_ms,
      atifDigest: run.atif_digest,
      atifArtifactId: atifMatches.length === 1 ? atifMatches[0]!.artifact_id : null,
    };
  });
  const cloudPipelines = pipelines.map((pipeline) => ({
    pipelineId: pipeline.pipeline_id,
    taskId: pipeline.task_id,
    name: pipeline.name,
    createdAt: pipeline.created_at,
  }));
  const cloudEvents = events.map((event) => ({
    taskId: event.task_id,
    sequence: event.sequence,
    eventType: event.event_type,
    occurredAt: event.occurred_at,
    summary: event.summary,
  }));
  const cloudArtifacts = artifacts.map(toCloudArtifact);
  const availableAtif = artifacts.filter((artifact) => artifact.run_id === canonicalRun.run_id
    && artifact.sha256 === canonicalRun.atif_digest
    && artifact.media_type === "application/json"
    && artifact.availability === "available");
  let trajectory: CloudTrajectoryDescriptor | null = null;
  if (canonicalRun.run_state === "completed" && availableAtif.length > 0) {
    const artifact = availableAtif[0]!;
    trajectory = safeValidate(() => validateCloudTrajectoryDescriptorData({
      taskId: canonicalRun.task_id,
      pipelineId: canonicalRun.pipeline_id,
      runId: canonicalRun.run_id,
      role: canonicalRun.role,
      runState: canonicalRun.run_state,
      startedAt: canonicalRun.started_at,
      completedAt: canonicalRun.completed_at,
      durationMs: canonicalRun.duration_ms,
      artifactId: availableAtif.length === 1 && artifacts.filter((item) => item.run_id === canonicalRun.run_id && item.sha256 === canonicalRun.atif_digest && item.media_type === "application/json").length === 1
        ? artifact.artifact_id
        : null,
      publicKey: artifact.public_key,
      mediaType: "application/json",
      byteSize: artifact.byte_size,
      sha256: artifact.sha256,
      availability: "available",
      disclosure: toCloudDisclosure(artifact),
    }));
  }

  return safeValidate(() => validateCloudTaskDetailData({
    task: task,
    pipelines: cloudPipelines,
    runs: cloudRuns,
    events: cloudEvents,
    artifacts: cloudArtifacts,
    trajectory,
  }));
}

export class CloudRepository {
  private readonly configuredClient: CloudD1QueryClient | undefined;
  private readonly configuredConfig: CloudReaderConfig | undefined;
  private readonly d1Options: D1ClientOptions;
  private runtimeClient: CloudD1QueryClient | undefined;

  constructor(options?: CloudRepositoryOptions | CloudD1QueryClient | CloudReaderConfig, config?: CloudReaderConfig) {
    if (isClient(options)) {
      this.configuredClient = options as CloudD1QueryClient;
      this.configuredConfig = config;
      this.d1Options = {};
    } else if (isConfig(options)) {
      this.configuredClient = undefined;
      this.configuredConfig = options;
      this.d1Options = {};
    } else {
      const resolved = (options ?? {}) as CloudRepositoryOptions;
      this.configuredClient = resolved.client;
      this.configuredConfig = resolved.config;
      this.d1Options = resolved.d1Options ?? {};
    }
  }

  private client(): CloudD1QueryClient {
    if (this.configuredClient) return this.configuredClient;
    if (!this.runtimeClient) this.runtimeClient = createCloudflareD1Client(this.configuredConfig ?? getCloudReaderConfig(), this.d1Options);
    return this.runtimeClient;
  }

  private statusValidationLimit(): number {
    const configuredRows = this.d1Options.maxRows;
    if (configuredRows === undefined) return STATUS_VALIDATION_PAGE_SIZE;
    if (!Number.isSafeInteger(configuredRows) || configuredRows < 0) return 0;
    return Math.min(STATUS_VALIDATION_PAGE_SIZE, configuredRows);
  }

  private async readStatus(): Promise<StatusSnapshot> {
    const summaryResponse = await this.client().query(STATUS_STATEMENT, []);
    const summary = parseStatusSummary(rowsFromResponse(summaryResponse));
    if (summary.status.taskCount === 0) return summary;

    const validationLimit = this.statusValidationLimit();
    let response = await this.client().query(STATUS_VALIDATION_STATEMENT, [validationLimit]);
    let previous: StatusValidationRow | null = null;
    let validatedCount = 0;

    while (validatedCount < summary.status.taskCount) {
      const rows = rowsFromResponse(response);
      if (rows.length === 0 || rows.length > validationLimit) invalidData();
      const parsedRows = rows.map(parseStatusValidation);
      for (const row of parsedRows) {
        if (previous && compareStatusKey(row, previous) >= 0) invalidData();
        if (!previous && (row.exposedAt !== summary.latestPublicationAt || row.publicationId !== summary.publicationId)) invalidData();
        previous = row;
      }
      validatedCount += parsedRows.length;
      if (validatedCount > summary.status.taskCount) invalidData();
      if (validatedCount === summary.status.taskCount) break;
      if (!previous) invalidData();
      response = await this.client().query(STATUS_VALIDATION_NEXT_STATEMENT, [
        previous.exposedAt,
        previous.exposedAt,
        previous.publicationId,
        previous.exposedAt,
        previous.publicationId,
        previous.taskId,
        validationLimit,
      ]);
    }
    if (validatedCount !== summary.status.taskCount) invalidData();
    return summary;
  }

  private async readUsageContext(taskId: string): Promise<UsageContext | null | CloudUsageUnavailable> {
    try {
      const response = await this.client().query(USAGE_CONTEXT_STATEMENT, [taskId]);
      const rows = rowsFromResponse(response);
      if (rows.length === 0) return null;
      if (rows.length !== 1) return usageUnavailable("invalid");
      try {
        return parseUsageContext(rows[0]);
      } catch {
        return usageUnavailable("invalid");
      }
    } catch {
      return usageUnavailable("unavailable");
    }
  }

  /** Read precomputed global groups only; no task or request-time rollup is performed. */
  async getGlobalUsage(): Promise<CloudUsageGlobalGroup[] | CloudUsageUnavailable> {
    const rows = await queryUsageRows(this.client(), USAGE_GLOBAL_STATEMENT, [MAX_USAGE_GLOBALS + 1]);
    if (isUsageUnavailable(rows)) return rows;
    if (rows.length > MAX_USAGE_GLOBALS) return usageUnavailable("invalid");
    try {
      return groupUsageGlobals(rows.map(parseUsageGlobalRow));
    } catch {
      return usageUnavailable("invalid");
    }
  }

  async readGlobalUsage(): Promise<CloudUsageGlobalGroup[] | CloudUsageUnavailable> {
    return this.getGlobalUsage();
  }

  async getTaskUsage(taskId: string): Promise<CloudUsage | null | CloudUsageUnavailable> {
    if (!validIdentifier(taskId)) return null;
    const context = await this.readUsageContext(taskId);
    if (context === null || isUsageUnavailable(context)) return context;
    if (!context.usageGenerationId) return usageUnavailable("missing");
    const summaryRows = await queryUsageRows(this.client(), USAGE_SUMMARY_STATEMENT, [taskId, MAX_USAGE_SUMMARIES + 1]);
    if (isUsageUnavailable(summaryRows)) return summaryRows;
    if (summaryRows.length === 0 || summaryRows.length > MAX_USAGE_SUMMARIES) return usageUnavailable("invalid");
    let summaries: CloudUsageSummary[];
    try {
      summaries = summaryRows.map(parseUsageSummaryRow);
    } catch {
      return usageUnavailable("invalid");
    }
    if (!summaries.some((summary) => summary.scope === "task" && summary.runId === null)) return usageUnavailable("invalid");

    const invocationRows = await queryUsageRows(this.client(), USAGE_INVOCATION_STATEMENT, [taskId, MAX_USAGE_INVOCATIONS + 1]);
    if (isUsageUnavailable(invocationRows)) return invocationRows;
    if (invocationRows.length > MAX_USAGE_INVOCATIONS) return usageUnavailable("invalid");
    let invocations: CloudUsageInvocation[];
    try {
      invocations = invocationRows.map(parseUsageInvocationRow);
      invocations.forEach((invocation) => validateUsageInvocationOwner(invocation, context));
    } catch {
      return usageUnavailable("invalid");
    }
    const globals = await this.getGlobalUsage();
    if (isUsageUnavailable(globals)) return globals;
    try {
      return safeValidate(() => validateCloudUsageData({
        schemaVersion: "1.0",
        usageGenerationId: context.usageGenerationId,
        publicationId: context.publicationId,
        taskId: context.taskId,
        summaries,
        invocations,
        globals,
      }));
    } catch {
      return usageUnavailable("invalid");
    }
  }

  async readTaskUsage(taskId: string): Promise<CloudUsage | null | CloudUsageUnavailable> {
    return this.getTaskUsage(taskId);
  }

  async getUsage(taskId: string): Promise<CloudUsage | null | CloudUsageUnavailable> {
    return this.getTaskUsage(taskId);
  }

  async getTaskUsageSummary(taskId: string, runId?: string): Promise<CloudUsageSummary | null | CloudUsageUnavailable> {
    if (!validIdentifier(taskId) || (runId !== undefined && !validIdentifier(runId))) return null;
    const context = await this.readUsageContext(taskId);
    if (context === null || isUsageUnavailable(context)) return context;
    if (!context.usageGenerationId) return usageUnavailable("missing");
    const rows = await queryUsageRows(this.client(), USAGE_SUMMARY_STATEMENT, [taskId, MAX_USAGE_SUMMARIES + 1]);
    if (isUsageUnavailable(rows)) return rows;
    if (rows.length === 0 || rows.length > MAX_USAGE_SUMMARIES) return usageUnavailable("invalid");
    try {
      const summaries = rows.map(parseUsageSummaryRow);
      if (summaries.some((summary) => summary.usageGenerationId !== context.usageGenerationId || summary.publicationId !== context.publicationId || summary.taskId !== context.taskId)) return usageUnavailable("invalid");
      if (!summaries.some((summary) => summary.scope === "task" && summary.runId === null)) return usageUnavailable("invalid");
      const selected = summaries.filter((summary) => runId === undefined ? summary.scope === "task" : summary.scope === "run" && summary.runId === runId);
      if (selected.length > 1) return usageUnavailable("invalid");
      return selected[0] ?? null;
    } catch {
      return usageUnavailable("invalid");
    }
  }

  async readTaskUsageSummary(taskId: string, runId?: string): Promise<CloudUsageSummary | null | CloudUsageUnavailable> {
    return this.getTaskUsageSummary(taskId, runId);
  }

  private async readUsageInvocationPage(
    taskId: string,
    runId: string | null,
    options: { readonly cursor?: string | null; readonly limit?: number },
  ): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable> {
    const context = await this.readUsageContext(taskId);
    if (context === null || isUsageUnavailable(context)) return context;
    if (!context.usageGenerationId) return usageUnavailable("missing");
    const limit = usageLimit(options.limit, MAX_USAGE_INVOCATION_PAGE_SIZE, 50);
    let decoded: DecodedUsageInvocationCursor | null;
    try {
      decoded = options.cursor == null ? null : decodeInvocationPageCursor(options.cursor, context, runId);
    } catch (error) {
      if (error instanceof PublicationCursorError) throw error;
      return usageUnavailable("invalid");
    }

    if (decoded) {
      const boundaryRows = await queryUsageRows(this.client(), USAGE_INVOCATION_BOUNDARY_STATEMENT, [taskId, decoded.runId, decoded.retryOrdinal, decoded.invocationId]);
      if (isUsageUnavailable(boundaryRows)) return boundaryRows;
      if (boundaryRows.length !== 1) throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
      try {
        const boundary = parseUsageInvocationRow(boundaryRows[0]);
        validateUsageInvocationOwner(boundary, context, runId ?? undefined);
        if (boundary.runId !== decoded.runId || boundary.retryOrdinal !== decoded.retryOrdinal || boundary.invocationId !== decoded.invocationId) throw new Error();
      } catch {
        throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
      }
    }

    const runScoped = runId !== null;
    const statement = runScoped
      ? decoded?.direction === "next" ? USAGE_INVOCATION_RUN_NEXT_STATEMENT
        : decoded?.direction === "previous" ? USAGE_INVOCATION_RUN_PREVIOUS_STATEMENT : USAGE_INVOCATION_RUN_FIRST_STATEMENT
      : decoded?.direction === "next" ? USAGE_INVOCATION_NEXT_STATEMENT
        : decoded?.direction === "previous" ? USAGE_INVOCATION_PREVIOUS_STATEMENT : USAGE_INVOCATION_FIRST_STATEMENT;
    const params: D1Scalar[] = runScoped
      ? decoded?.direction === "next" || decoded?.direction === "previous"
        ? [taskId, runId!, decoded.retryOrdinal, decoded.retryOrdinal, decoded.invocationId, limit + 1]
        : [taskId, runId!, limit + 1]
      : decoded?.direction === "next" || decoded?.direction === "previous"
        ? [taskId, decoded.runId, decoded.runId, decoded.retryOrdinal, decoded.retryOrdinal, decoded.invocationId, limit + 1]
        : [taskId, limit + 1];
    const pageRows = await queryUsageRows(this.client(), statement, params);
    if (isUsageUnavailable(pageRows)) return pageRows;
    if (pageRows.length > limit + 1) return usageUnavailable("invalid");
    let parsed: CloudUsageInvocation[];
    try {
      parsed = pageRows.map(parseUsageInvocationRow);
      parsed.forEach((invocation) => validateUsageInvocationOwner(invocation, context, runId ?? undefined));
    } catch {
      return usageUnavailable("invalid");
    }

    const countStatement = runScoped ? USAGE_INVOCATION_RUN_COUNT_STATEMENT : USAGE_INVOCATION_COUNT_STATEMENT;
    const countParams: D1Scalar[] = runScoped ? [taskId, runId!] : [taskId];
    const countRows = await queryUsageRows(this.client(), countStatement, countParams);
    if (isUsageUnavailable(countRows)) return countRows;
    if (countRows.length !== 1) return usageUnavailable("invalid");
    let total: number;
    try {
      total = usageInvocationCount(countRows[0]);
    } catch {
      return usageUnavailable("invalid");
    }

    const hasExtra = parsed.length > limit;
    const output = decoded?.direction === "previous" ? parsed.slice(0, limit).reverse() : parsed.slice(0, limit);
    const first = output[0];
    const last = output.at(-1);
    const cursorFor = (invocation: CloudUsageInvocation, direction: "next" | "previous") => encodeUsageInvocationCursor({
      publicationId: context.publicationId,
      usageGenerationId: context.usageGenerationId!,
      taskId,
      runId,
      sort: [invocation.runId!, invocation.retryOrdinal, invocation.invocationId!],
      direction,
    });
    let nextCursor: string | null = null;
    let previousCursor: string | null = null;
    if (first && ((decoded?.direction === "previous" && hasExtra) || decoded?.direction === "next")) previousCursor = cursorFor(first, "previous");
    if (last && (((decoded?.direction === "next" || decoded === null) && hasExtra) || decoded?.direction === "previous")) nextCursor = cursorFor(last, "next");
    try {
      return safeValidate(() => validateCloudUsageInvocationPageData({ invocations: output, nextCursor, previousCursor, total }));
    } catch {
      return usageUnavailable("invalid");
    }
  }

  async getUsageInvocationPage(taskId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async getUsageInvocationPage(taskId: string, runId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async getUsageInvocationPage(
    taskId: string,
    runIdOrOptions?: string | { readonly cursor?: string | null; readonly limit?: number },
    maybeOptions: { readonly cursor?: string | null; readonly limit?: number } = {},
  ): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable> {
    const runId = typeof runIdOrOptions === "string" ? runIdOrOptions : null;
    const options = typeof runIdOrOptions === "string" ? maybeOptions : runIdOrOptions ?? {};
    if (!validIdentifier(taskId) || (runId !== null && !validIdentifier(runId))) return null;
    return this.readUsageInvocationPage(taskId, runId, options);
  }

  async listUsageInvocationPage(taskId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async listUsageInvocationPage(taskId: string, runId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async listUsageInvocationPage(taskId: string, runIdOrOptions?: string | { readonly cursor?: string | null; readonly limit?: number }, maybeOptions: { readonly cursor?: string | null; readonly limit?: number } = {}): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable> {
    return typeof runIdOrOptions === "string"
      ? this.getUsageInvocationPage(taskId, runIdOrOptions, maybeOptions)
      : this.getUsageInvocationPage(taskId, runIdOrOptions);
  }

  async getUsageInvocations(taskId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async getUsageInvocations(taskId: string, runId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async getUsageInvocations(taskId: string, runIdOrOptions?: string | { readonly cursor?: string | null; readonly limit?: number }, maybeOptions: { readonly cursor?: string | null; readonly limit?: number } = {}): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable> {
    return typeof runIdOrOptions === "string"
      ? this.getUsageInvocationPage(taskId, runIdOrOptions, maybeOptions)
      : this.getUsageInvocationPage(taskId, runIdOrOptions);
  }

  async listUsageInvocations(taskId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async listUsageInvocations(taskId: string, runId: string, options?: { readonly cursor?: string | null; readonly limit?: number }): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable>;
  async listUsageInvocations(taskId: string, runIdOrOptions?: string | { readonly cursor?: string | null; readonly limit?: number }, maybeOptions: { readonly cursor?: string | null; readonly limit?: number } = {}): Promise<CloudUsageInvocationPage | null | CloudUsageUnavailable> {
    return typeof runIdOrOptions === "string"
      ? this.getUsageInvocationPage(taskId, runIdOrOptions, maybeOptions)
      : this.getUsageInvocationPage(taskId, runIdOrOptions);
  }

  async getUsageTurnPage(taskId: string, invocationId: string, options: { readonly cursor?: string | null; readonly limit?: number } = {}): Promise<CloudUsageTurnPage | null | CloudUsageUnavailable> {
    if (!validIdentifier(taskId) || !validIdentifier(invocationId)) return null;
    const context = await this.readUsageContext(taskId);
    if (context === null || (context && "kind" in context)) return context;
    if (!context.usageGenerationId) return usageUnavailable("missing");
    const limit = usageLimit(options.limit, MAX_USAGE_TURN_PAGE_SIZE, 50);
    const invocationRows = await queryUsageRows(this.client(), USAGE_INVOCATION_CONTEXT_STATEMENT, [taskId, invocationId]);
    if (isUsageUnavailable(invocationRows)) return invocationRows;
    if (invocationRows.length === 0) return null;
    if (invocationRows.length !== 1) return usageUnavailable("invalid");
    let invocation: CloudUsageInvocation;
    try {
      invocation = parseUsageInvocationRow(invocationRows[0]);
    } catch {
      return usageUnavailable("invalid");
    }
    try {
      validateUsageInvocationOwner(invocation, context);
    } catch {
      return usageUnavailable("invalid");
    }

    const countRows = await queryUsageRows(this.client(), USAGE_TURN_COUNT_STATEMENT, [taskId, invocationId]);
    if (isUsageUnavailable(countRows)) return countRows;
    if (countRows.length !== 1) return usageUnavailable("invalid");
    let total: number;
    try {
      total = usageCount(countRows[0]);
    } catch {
      return usageUnavailable("invalid");
    }
    let decoded: DecodedUsageTurnCursor | null;
    try {
      decoded = options.cursor == null ? null : decodeTurnPageCursor(options.cursor, context, invocationId, invocation.runId!);
    } catch (error) {
      if (error instanceof PublicationCursorError) throw error;
      return usageUnavailable("invalid");
    }
    if (decoded) {
      const boundaryRows = await queryUsageRows(this.client(), USAGE_TURN_BOUNDARY_STATEMENT, [taskId, invocationId, decoded.ordinal, decoded.turnId]);
      if (isUsageUnavailable(boundaryRows)) return boundaryRows;
      if (boundaryRows.length !== 1) throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
      let boundary: CloudUsageTurn;
      try {
        boundary = parseUsageTurnRow(boundaryRows[0]);
      } catch {
        throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
      }
      if (boundary.usageGenerationId !== context.usageGenerationId || boundary.publicationId !== context.publicationId || boundary.taskId !== taskId || boundary.runId !== invocation.runId || boundary.invocationId !== invocationId || boundary.ordinal !== decoded.ordinal || boundary.turnId !== decoded.turnId) throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
    }

    const statement = decoded?.direction === "next"
      ? USAGE_TURN_NEXT_STATEMENT
      : decoded?.direction === "previous" ? USAGE_TURN_PREVIOUS_STATEMENT : USAGE_TURN_FIRST_STATEMENT;
    const params: D1Scalar[] = decoded?.direction === "next" || decoded?.direction === "previous"
      ? [taskId, invocationId, decoded.ordinal, decoded.ordinal, decoded.turnId, limit + 1]
      : [taskId, invocationId, limit + 1];
    const pageRows = await queryUsageRows(this.client(), statement, params);
    if (isUsageUnavailable(pageRows)) return pageRows;
    if (pageRows.length > limit + 1) return usageUnavailable("invalid");
    let parsed: CloudUsageTurn[];
    try {
      parsed = pageRows.map(parseUsageTurnRow);
    } catch {
      return usageUnavailable("invalid");
    }
    for (const turn of parsed) {
      if (turn.usageGenerationId !== context.usageGenerationId || turn.publicationId !== context.publicationId || turn.taskId !== taskId || turn.runId !== invocation.runId || turn.invocationId !== invocationId) return usageUnavailable("invalid");
    }
    const hasExtra = parsed.length > limit;
    const output = decoded?.direction === "previous" ? parsed.slice(0, limit).reverse() : parsed.slice(0, limit);
    const first = output[0];
    const last = output.at(-1);
    let nextCursor: string | null = null;
    let previousCursor: string | null = null;
    const cursorFor = (turn: CloudUsageTurn, direction: "next" | "previous") => encodeUsageCursor({
      query: "usage-turns", publicationId: context.publicationId, usageGenerationId: context.usageGenerationId!, taskId,
      runId: invocation.runId!, invocationId, sort: [invocationId, turn.ordinal, turn.turnId], direction,
    });
    if (first && (decoded?.direction === "previous" ? hasExtra : decoded?.direction === "next")) previousCursor = cursorFor(first, "previous");
    if (last && (decoded?.direction === "next" || !decoded ? hasExtra : false)) nextCursor = cursorFor(last, "next");
    if (last && decoded?.direction === "previous") nextCursor = cursorFor(last, "next");
    try {
      return safeValidate(() => validateCloudUsageTurnPageData({ turns: output, nextCursor, previousCursor, total }));
    } catch {
      return usageUnavailable("invalid");
    }
  }

  async listUsageTurns(taskId: string, invocationId: string, options: { readonly cursor?: string | null; readonly limit?: number } = {}): Promise<CloudUsageTurnPage | null | CloudUsageUnavailable> {
    return this.getUsageTurnPage(taskId, invocationId, options);
  }

  async getTurnPage(taskId: string, invocationId: string, options: { readonly cursor?: string | null; readonly limit?: number } = {}): Promise<CloudUsageTurnPage | null | CloudUsageUnavailable> {
    return this.getUsageTurnPage(taskId, invocationId, options);
  }

  async getStatus(): Promise<CloudStatus> {
    return (await this.readStatus()).status;
  }

  async listTasks(scope: CloudTaskScope, options?: Omit<CloudTaskListOptions, "scope">): Promise<CloudTaskPage>;
  async listTasks(options: CloudTaskListOptions): Promise<CloudTaskPage>;
  async listTasks(scope: CloudTaskScope, cursor?: string | null, limit?: number): Promise<CloudTaskPage>;
  async listTasks(
    scopeOrOptions: CloudTaskScope | CloudTaskListOptions,
    optionsOrCursor?: Omit<CloudTaskListOptions, "scope"> | string | null,
    limit?: number,
  ): Promise<CloudTaskPage> {
    const args = parseListArguments(scopeOrOptions, optionsOrCursor as CloudTaskListOptions | string | null | undefined, limit);
    const snapshot = await this.readStatus();
    if (snapshot.status.taskCount === 0) return { tasks: [], nextCursor: null, previousCursor: null, total: 0 };
    if (!snapshot.publicationId) invalidData();

    const cursor = args.cursor === null ? null : decodeTaskCursor(args.cursor, args.scope, snapshot.publicationId);
    if (cursor) {
      const boundaryResponse = await this.client().query(CURSOR_STATEMENTS[args.scope], [cursor.updatedAt, cursor.taskId]);
      const boundaryRows = rowsFromResponse(boundaryResponse);
      if (boundaryRows.length !== 1) cursorError("STALE_CURSOR");
      parseCursorBoundary(boundaryRows[0], cursor);
    }

    const statement = cursor ? PAGE_STATEMENTS[args.scope][cursor.direction] : PAGE_STATEMENTS[args.scope].first;
    const queryParams: D1Scalar[] = cursor ? [cursor.updatedAt, cursor.updatedAt, cursor.taskId, args.limit + 1] : [args.limit + 1];
    const pageResponse = await this.client().query(statement, queryParams);
    const pageRows = rowsFromResponse(pageResponse);
    if (pageRows.length > args.limit + 1) invalidData();
    const parsedRows = pageRows.map(parseTask);
    const hasExtra = parsedRows.length > args.limit;
    const pageRowsForOutput = cursor?.direction === "previous"
      ? parsedRows.slice(0, args.limit).reverse()
      : parsedRows.slice(0, args.limit);
    const countResponse = await this.client().query(COUNT_STATEMENTS[args.scope], []);
    const countRows = rowsFromResponse(countResponse);
    if (countRows.length !== 1) invalidData();
    const total = parseCount(countRows[0]);
    if (total < pageRowsForOutput.length) invalidData();
    const seen = new Set<string>();
    for (const item of pageRowsForOutput) {
      if (seen.has(item.task.taskId)) invalidData();
      seen.add(item.task.taskId);
    }

    const first = pageRowsForOutput[0];
    const last = pageRowsForOutput.at(-1);
    let nextCursor: string | null = null;
    let previousCursor: string | null = null;
    if (first && (cursor?.direction === "previous" ? hasExtra : false)) {
      previousCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [first.updatedAt, first.task.taskId, "previous"] });
    } else if (first && cursor?.direction === "next") {
      previousCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [first.updatedAt, first.task.taskId, "previous"] });
    }
    if (last && (cursor?.direction === "next" || !cursor) && hasExtra) {
      nextCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [last.updatedAt, last.task.taskId, "next"] });
    } else if (last && cursor?.direction === "previous") {
      nextCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [last.updatedAt, last.task.taskId, "next"] });
    }
    return { tasks: pageRowsForOutput.map((item) => item.task), nextCursor, previousCursor, total };
  }

  async listActiveTasks(options?: Omit<CloudTaskListOptions, "scope">): Promise<CloudTaskPage> {
    return this.listTasks("active", options);
  }

  async listHistoryTasks(options?: Omit<CloudTaskListOptions, "scope">): Promise<CloudTaskPage> {
    return this.listTasks("history", options);
  }

  async getTaskDetail(taskId: string): Promise<CloudTaskDetail | null> {
    if (!validIdentifier(taskId)) return null;
    const taskResponse = await this.client().query(TASK_DETAIL_STATEMENT, [taskId]);
    const taskRows = rowsFromResponse(taskResponse);
    if (taskRows.length === 0) return null;
    if (taskRows.length !== 1) invalidData();
    const base = parseDetailTask(taskRows[0]);
    const pipelinesResponse = await this.client().query(TASK_DETAIL_PIPELINES_STATEMENT, [base.generation.publication_id, base.task.task_id, detailLimit(base.generation.expected_pipeline_count, MAX_DETAIL_PIPELINES)]);
    const pipelineRows = rowsFromResponse(pipelinesResponse);
    exactDetailCount(pipelineRows, base.generation.expected_pipeline_count, MAX_DETAIL_PIPELINES);
    const pipelines = pipelineRows.map(parseDetailPipeline);

    const runsResponse = await this.client().query(TASK_DETAIL_RUNS_STATEMENT, [base.generation.publication_id, base.task.task_id, detailLimit(base.generation.expected_run_count, MAX_DETAIL_RUNS)]);
    const runRows = rowsFromResponse(runsResponse);
    exactDetailCount(runRows, base.generation.expected_run_count, MAX_DETAIL_RUNS);
    const runs = runRows.map(parseDetailRun);

    const eventsResponse = await this.client().query(TASK_DETAIL_EVENTS_STATEMENT, [base.generation.publication_id, base.task.task_id, detailLimit(base.generation.expected_event_count, MAX_DETAIL_EVENTS)]);
    const eventRows = rowsFromResponse(eventsResponse);
    exactDetailCount(eventRows, base.generation.expected_event_count, MAX_DETAIL_EVENTS);
    const events = eventRows.map(parseDetailEvent);

    const artifactsResponse = await this.client().query(TASK_DETAIL_ARTIFACTS_STATEMENT, [base.generation.publication_id, base.task.task_id, detailLimit(base.generation.expected_artifact_count, MAX_DETAIL_ARTIFACTS)]);
    const artifactRows = rowsFromResponse(artifactsResponse);
    exactDetailCount(artifactRows, base.generation.expected_artifact_count, MAX_DETAIL_ARTIFACTS);
    const artifacts = artifactRows.map(parseDetailArtifact);
    return buildTaskDetail(base, pipelines, runs, events, artifacts);
  }

  async loadTaskDetail(taskId: string): Promise<CloudTaskDetail | null> {
    return this.getTaskDetail(taskId);
  }

  async getArtifactDescriptor(taskId: string, logicalPath: string): Promise<CloudArtifactDescriptor | null> {
    if (!validIdentifier(taskId) || !validLogicalPath(logicalPath)) return null;
    const response = await this.client().query(ARTIFACT_DESCRIPTOR_STATEMENT, [taskId, logicalPath]);
    const rows = rowsFromResponse(response);
    if (rows.length === 0) return null;
    if (rows.length !== 1) invalidData();
    const artifact = parseDetailArtifact(rows[0]);
    if (artifact.task_id !== taskId) invalidData();
    const config = this.configuredConfig ?? getCloudReaderConfig();
    const publicUrl = safeValidate(() => resolvePublicObjectUrl(config.publicR2BaseUrl, artifact.public_key));
    return { ...toCloudArtifact(artifact), publicUrl };
  }

  async getArtifact(taskId: string, logicalPath: string): Promise<CloudArtifactDescriptor | null> {
    return this.getArtifactDescriptor(taskId, logicalPath);
  }

  async resolveArtifactUrl(taskId: string, logicalPath: string): Promise<string | null> {
    const artifact = await this.getArtifactDescriptor(taskId, logicalPath);
    return artifact?.publicUrl ?? null;
  }

  async getTrajectoryDescriptor(taskId: string, runId?: string): Promise<CloudTrajectoryDescriptor | null> {
    if (runId !== undefined && !validIdentifier(runId)) return null;
    const detail = await this.getTaskDetail(taskId);
    if (!detail) return null;
    if (runId === undefined) return detail.trajectory;
    const run = detail.runs.find((candidate) => candidate.runId === runId);
    if (!run || run.runState !== "completed") return null;
    const matches = detail.artifacts.filter((artifact) => artifact.runId === run.runId && artifact.sha256 === run.atifDigest && artifact.mediaType === "application/json");
    const available = matches.filter((artifact) => artifact.availability === "available");
    if (available.length === 0) return null;
    const artifact = available[0]!;
    return safeValidate(() => validateCloudTrajectoryDescriptorData({
      taskId: run.taskId,
      pipelineId: run.pipelineId,
      runId: run.runId,
      role: run.role,
      runState: run.runState,
      startedAt: run.startedAt,
      completedAt: run.completedAt,
      durationMs: run.durationMs,
      artifactId: matches.length === 1 ? artifact.artifactId : null,
      publicKey: artifact.publicKey,
      mediaType: "application/json",
      byteSize: artifact.byteSize,
      sha256: artifact.sha256,
      availability: "available",
      disclosure: artifact.disclosure,
    }));
  }

  async getTrajectory(taskId: string, runId?: string): Promise<CloudTrajectoryDescriptor | null> {
    return this.getTrajectoryDescriptor(taskId, runId);
  }
}

let repository: CloudRepository | null = null;

export function createCloudRepository(options?: CloudRepositoryOptions | CloudD1QueryClient | CloudReaderConfig, config?: CloudReaderConfig): CloudRepository {
  return new CloudRepository(options, config);
}

export function getCloudRepository(config?: CloudReaderConfig | CloudRepositoryOptions | CloudD1QueryClient, d1Options: D1ClientOptions = {}): CloudRepository {
  if (!repository) {
    if (isClient(config) || isConfig(config)) repository = new CloudRepository(config);
    else repository = new CloudRepository({ ...(config ?? {}), d1Options });
  }
  return repository;
}

export function resetCloudRepository(): void {
  repository = null;
}

export {
  CloudRepository as CloudStewardArchiveRepository,
  CloudRepository as StewardCloudRepository,
  createCloudRepository as createCloudStewardArchiveRepository,
  getCloudRepository as getCloudStewardArchiveRepository,
  decodePublicationCursor,
  decodeUsageInvocationCursor,
  decodeUsageCursor,
  encodePublicationCursor,
  encodeUsageInvocationCursor,
  encodeUsageCursor,
  PublicationCursorError,
};
