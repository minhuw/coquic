# Storage compatibility alias inventory

## Purpose and limitations

This report inventories the compatibility names seeded by Plan 007 without changing
Storage implementation, tests, exports, schemas, migrations, or packaging. The
inventory combines tracked-repository source and string searches with definition
inspection and `git log --all --oneline -S` history searches. The repository scan
can characterize repository callers, persistence identity, exports, comments, and
historical introduction, but it cannot observe downstream imports, private forks,
installed copies, generated consumers, or other external ownership. Therefore an
absence in this report is not evidence that a name is unused outside this
repository.

The drift check against `e85d64ac` was clean for the assigned Storage and Storage
test paths. The source inventory was run with the exact seed expression from the
plan. Dotted-string searching found Storage imports and module references but no
dynamic lookup constructing a seeded Storage compatibility name. Generic
`getattr` matches were recorded as false positives rather than compatibility
evidence. Publication-domain and core-model names sharing a seed spelling were
separated from the schema aliases by module path.

## Classification criteria

- `canonical-public-facade` means the name is the intentional package facade or
  primary public entry point, with active repository callers and a distinct role
  from a removable alias.
- `internal-cleanup-candidate` requires all of the following: no package
  re-export, no current, historical, or dotted-path caller, no persistence or
  mapper identity role, no compatibility comment, and a documented canonical
  replacement. In this report it applies only to `TaskPage.tasks`, whose
  canonical replacement is `items`; this remains a separately approvable
  recommendation, not deletion authority.
- `external-ownership-unresolved` is used when repository evidence cannot
  establish ownership or a safe canonical replacement. In this report it
  applies to `OutboxGenerationRow`, which names a persisted row identity even
  though no repository caller was found. Missing repository callers do not
  disprove downstream use.

## Compatibility matrix

| Definition | Canonical target | Export surface | Repository evidence | History | Classification | Recommendation |
|---|---|---|---|---|---|---|
| Normalized SQL row alias — `TaskExecution` | `TaskExecutionRow` mapped to `task_executions` | Re-exported by `coquic_steward.storage` and included in `__all__`; schema-local definition at `schema.py:1462` | `git grep` finds definition, Storage mapper use, and imports from `storage`; row has execution ownership and unique task identity | `062920e9 fix(steward): enforce task ledger ownership`; also `b68dfda8`, `dec0feeb`, `cddb25b5` | `explicit-compatibility` | Preserve while the normalized execution row and package spelling remain part of the inspected surface; any narrowing needs direct import and mapper characterization. |
| Normalized SQL row alias — `TaskPipeline` | `TaskPipelineRow` mapped to `task_pipelines` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1463` | `git grep` finds definition, pipeline persistence and mapper use, and package imports; row carries durable attempt and parent identity | `062920e9 fix(steward): enforce task ledger ownership`; also `b68dfda8`, `dec0feeb`, `b6b9210d` | `explicit-compatibility` | Preserve as a persistence-facing compatibility spelling; evaluate only in a separately approved cohort with row-identity and import evidence. |
| Normalized SQL row alias — `CodexSession` | `CodexSessionRow` mapped to `codex_sessions` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1464` | `git grep` finds schema definition and package imports; Storage also has a distinct core-model `CodexSession`, so module-qualified identity matters | `062920e9 fix(steward): enforce task ledger ownership`; also `c4b63135 refactor(steward): delete legacy path compatibility`, `394d5b2d refactor(steward): remove execution type aliases`, `a5cd979f` | `explicit-compatibility` | Preserve and document the `storage.schema` versus core-model namespace distinction; do not narrow by spelling search alone. |
| Normalized SQL row alias — `TaskRun` | `TaskRunRow` mapped to `task_runs` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1465` | `git grep` finds definition, extensive run persistence and test use, and package imports; row owns durable role and recovery identity | `062920e9 fix(steward): enforce task ledger ownership`; also `59685774`, `a5cd979f`, `1f31d91a` | `explicit-compatibility` | Preserve as a persistence and compatibility boundary; any future transition must characterize direct imports and all predecessor identity links. |
| Worktree checkpoint row alias — `WorktreeCheckpoint` | `TaskWorktreeCheckpointRow` mapped to `task_worktree_checkpoints` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1466` | `git grep` finds definition, worktree mapper use, and task-ledger tests; row has one-checkpoint-per-execution identity | `2c94ffc3 fix(steward): preserve pipeline and completion ownership`; also `b6b9210d`, `21c39bc1` | `explicit-compatibility` | Preserve until worktree checkpoint ownership and direct imports are separately characterized; no deletion recommendation is authorized by this inventory. |
| Daemon singleton row alias — `DaemonState` | `DaemonStateRow` mapped to `daemon_state` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1467` | `git grep` finds definition, daemon persistence access, and package imports; literal `daemon` singleton key is a persistence identity | `a5cd979f feat(steward): add durable container task lifecycle` | `explicit-compatibility` | Preserve the alias with its singleton persistence role; reassess only with database identity and package-import evidence. |
| Verified image release row alias — `StewardImageRelease` | `StewardImageReleaseRow` mapped to `steward_image_releases` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1468` | `git grep` finds definition and release persistence paths; row stores selected and rollback release identity | `c128de38 refactor(steward): remove unreachable schema migrator`; also `f94be7b0` | `explicit-compatibility` | Preserve because the alias names a persisted release identity; consider no cleanup without a dedicated schema/import transition. |
| Container reference row alias — `StewardContainerReference` | `StewardContainerReferenceRow` mapped to `steward_container_references` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1469` | `git grep` finds definition, cleanup and retention persistence, and package imports; container and epoch coordinates are durable ownership facts | `f94be7b0 feat(steward): operate daemon with Docker Compose` | `explicit-compatibility` | Preserve as a persisted ownership spelling; future narrowing must prove no external import and retain the table identity. |
| Validation cleanup row alias — `StewardValidationCleanup` | `StewardValidationCleanupRow` mapped to `steward_validation_cleanups` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1470` | `git grep` finds definition, validation recovery persistence, and package imports; run ID is the cleanup authority key | `0d79cf10 fix(steward): harden validation operation recovery` | `explicit-compatibility` | Preserve while validation cleanup recovery depends on the persisted authority; review only through an approved compatibility cohort. |
| Resource-pressure row alias — `StewardResourcePressure` | `StewardResourcePressureRow` mapped to `steward_resource_pressure` | Re-exported by `coquic_steward.storage` and included in `__all__`; `schema.py:1471` | `git grep` finds definition, daemon resource-pressure persistence, tests, and package imports; bounded facts are durable | `f94be7b0 feat(steward): operate daemon with Docker Compose` | `explicit-compatibility` | Preserve as a public package alias over the durable resource-pressure row; do not infer removability from limited caller hits. |
| Publication generation row alias — `PublicationGeneration` | `PublicationGenerationRow` mapped to `publication_generations` | Schema-local in `storage.schema`; not package-re-exported; distinct publication-domain names occur in `storage.sqlite` and `publication` modules | `git grep` finds alias and publication persistence; SQL constraints bind publication ID and generation boundary; non-storage hits are recorded as domain false positives | `25398194 refactor(steward): require concrete publication generations`; also `4e44a31e`, `85c89799`, `5c579196` | `explicit-compatibility` | Preserve the schema-qualified alias and namespace distinction; any transition needs publication-row identity and direct import characterization. |
| Publication receipt row alias — `PublicationReceipt` | `PublicationReceiptRow` mapped to `publication_receipts` | Schema-local in `storage.schema`; not package-re-exported; publication domain models share the spelling elsewhere | `git grep` finds alias, receipt persistence and foreign-key use; publication publisher and tests are scan false positives unless module-qualified | `33392352 fix(steward): align credential-aware publication identity`; also `06d08f85`, `a9d25c24`, `ee788470` | `explicit-compatibility` | Preserve as a schema-local persistence alias and keep it distinct from publication-domain receipts; no deletion recommendation. |
| Publication health row alias — `PublicationHealth` | `PublicationHealthRow` mapped to `publication_health` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds alias and singleton health persistence; publication-domain health references are separately qualified | `5c579196 refactor(steward): type cli lifecycle and signals`; also `d28b1484`, `f672a40a`, `c2b6da44` | `explicit-compatibility` | Preserve with the singleton row identity; consider future characterization only alongside publication outbox storage. |
| Publication cleanup intent row alias — `PublicationCleanupIntent` | `PublicationCleanupIntentRow` mapped to `publication_cleanup_intents` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds alias and exact-path cleanup persistence with publication foreign keys | `d28b1484 fix(steward): harden publication progress`; also `f672a40a`, `c2b6da44` | `explicit-compatibility` | Preserve as an exact-path cleanup authority spelling; any narrowing must include persisted identity and cleanup recovery evidence. |
| Publication hide-fence row alias — `PublicationHideFence` | `PublicationHideFenceRow` mapped to `publication_hide_fences` | Schema-local in `storage.schema`; not package-re-exported; domain hide-fence names elsewhere are distinct | `git grep` finds alias and task-scoped fence persistence; publisher and daemon hits are qualified domain uses, not proof of row alias callers | `51492ea5 refactor(steward): use typed daemon publication APIs`; also `dab33240`, `c937d1ab` | `explicit-compatibility` | Preserve the task-scoped fence alias and its state machine; review with publication hide recovery, not generic spelling searches. |
| Historical outbox generation alias — `OutboxGenerationRow` | `PublicationGenerationRow` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds direct alias assignment at `schema.py:1477`; no current repository caller or dotted-path lookup was found, while the target retains publication-generation persistence identity | `c2b6da44 feat(steward): model durable publication outbox state` | `external-ownership-unresolved` | Preserve pending direct-import and downstream-ownership evidence; do not delete or rename because the alias targets a persisted publication identity. |
| Historical outbox receipt alias — `OutboxReceiptRow` | `PublicationReceiptRow` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds direct alias assignment at `schema.py:1478`; target retains receipt table and foreign-key identity | `c2b6da44 feat(steward): model durable publication outbox state` | `explicit-compatibility` | Preserve with the receipt identity; any follow-up must be separately approved and must not alter SQLite identity. |
| Publication outbox generation alias — `PublicationOutboxGenerationRow` | `PublicationGenerationRow` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds direct alias assignment at `schema.py:1479`; publication outbox code and tests provide qualified persistence evidence | `c2b6da44 feat(steward): model durable publication outbox state` | `explicit-compatibility` | Preserve as an outbox compatibility spelling and assess only with the other outbox aliases as one evidence cohort. |
| Publication outbox receipt alias — `PublicationOutboxReceiptRow` | `PublicationReceiptRow` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds direct alias assignment at `schema.py:1480`; target is the durable receipt row | `c2b6da44 feat(steward): model durable publication outbox state` | `explicit-compatibility` | Preserve until outbox import ownership and receipt identity are characterized; do not rename or delete from this spike. |
| Publication outbox health alias — `PublicationOutboxHealthRow` | `PublicationHealthRow` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds direct alias assignment at `schema.py:1481`; target is the singleton publication health row | `c2b6da44 feat(steward): model durable publication outbox state` | `explicit-compatibility` | Preserve with the health singleton and evaluate only in a separately approved outbox cohort. |
| Publication outbox cleanup alias — `PublicationOutboxCleanupIntentRow` | `PublicationCleanupIntentRow` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds direct alias assignment at `schema.py:1482`; target retains exact-path cleanup persistence | `c2b6da44 feat(steward): model durable publication outbox state` | `explicit-compatibility` | Preserve because cleanup intent is a recovery authority; require direct import and persistence evidence before any transition. |
| Publication outbox hide-fence alias — `PublicationOutboxHideFenceRow` | `PublicationHideFenceRow` | Schema-local in `storage.schema`; not package-re-exported | `git grep` finds direct alias assignment at `schema.py:1483`; target retains task-scoped hide-fence identity | `c937d1ab feat(steward): persist publication hide fences` | `explicit-compatibility` | Preserve with hide-fence persistence and assess only through an approved outbox compatibility cohort. |
| SQLite schema-version alias — `CURRENT_SCHEMA_VERSION` | `SQLITE_USER_VERSION` with current value `2` | Re-exported by `coquic_steward.storage` and included in `__all__`; `sqlite.py:243` | `git grep` finds definition, create/open validation, and current-schema tests; it controls PRAGMA user version | `7a4ba686 refactor(steward): add exact sqlite store factories` | `explicit-compatibility` | Preserve the version alias and its validation contract; changing it requires an explicit schema plan, not alias cleanup. |
| SQLite catalog-digest alias — `SCHEMA_CATALOG_DIGEST` | `CURRENT_SCHEMA_CATALOG_DIGEST` | Defined in `storage.sqlite` at `sqlite.py:244-245`; not package-re-exported | `git grep` finds alias and catalog validation; the canonical digest is checked against the complete SQLite catalog | `7a4ba686 refactor(steward): add exact sqlite store factories` | `explicit-compatibility` | Preserve as a module-local compatibility spelling while documenting the distinction from the package-exported digest constant. |
| Store lifecycle exception alias — `StoreCreationError` | `SQLiteStoreLifecycleError` | Re-exported by `coquic_steward.storage` and included in `__all__`; public aliases comment at `sqlite.py:285-288` | `git grep` finds alias, factory errors, and tests around create lifecycle; no separate exception hierarchy is created | `7a4ba686 refactor(steward): add exact sqlite store factories` | `explicit-compatibility` | Preserve the named create failure boundary; any consolidation must characterize direct exception imports and catch clauses. |
| Store lifecycle exception alias — `StoreOpenError` | `SQLiteStoreLifecycleError` | Re-exported by `coquic_steward.storage` and included in `__all__`; public aliases comment at `sqlite.py:285-288` | `git grep` finds alias and open validation boundary; it shares the lifecycle exception identity intentionally | `7a4ba686 refactor(steward): add exact sqlite store factories` | `explicit-compatibility` | Preserve the named open failure boundary; defer any narrowing to a separately approved exception compatibility change. |
| Store lifecycle exception alias — `StoreValidationError` | `SQLiteStoreLifecycleError` | Re-exported by `coquic_steward.storage` and included in `__all__`; public aliases comment at `sqlite.py:285-288` | `git grep` finds alias and store validation paths; it is a public named failure boundary despite shared class identity | `7a4ba686 refactor(steward): add exact sqlite store factories` | `explicit-compatibility` | Preserve the named validation failure boundary and characterize downstream catches before considering consolidation. |
| Detached page accessor returning `items` — `TaskPage.tasks` | `TaskPage.items` | SQLite-local property on `TaskPage` at `sqlite.py:291-299`; `TaskPage` itself is not package-exported | `git grep` finds property definition and page construction; no current repository caller, dotted-path lookup, persistence/mapper role, or history pickaxe result was found | none found | `internal-cleanup-candidate` | Consider a separately approved cleanup after confirming the canonical `items` spelling and preserving any externally owned page consumers; this spike does not authorize removal. |
| Detached page accessor returning `next_cursor` — `TaskPage.cursor` | `TaskPage.next_cursor` | SQLite-local property on `TaskPage` at `sqlite.py:291-304`; `TaskPage` itself is not package-exported | `git grep` finds property definition and cursor use; no separate history pickaxe result and no dotted-path dynamic lookup were found | none found | `explicit-compatibility` | Preserve as an additive accessor while page consumers remain externally unobservable; reassess only with direct import and API evidence. |
| Public storage facade alias — `TaskStore` | `SQLiteTaskStore` | Package export and `__all__` entry at `storage/__init__.py:51,200`; extensive source and test callers | `git grep` finds broad `TaskStore.create` and `TaskStore.open` use; facade owns task, execution, publication, cleanup, and lifecycle persistence | `6d3f26b7 refactor(steward): remove legacy executor lifecycle`; also `8246344e`, `87aca008`, `9416eacf` | `canonical-public-facade` | Preserve as the stable public facade; any future API narrowing requires a separately selected plan and direct downstream-compatibility evidence. |

### Approved planner Store narrowing

The operator approved direct deletion of `claim_control_loop_planner_run` and
`complete_control_loop_planner_run`. Repository-wide source, test, documentation,
dotted-string, plugin-registration, and dynamic-lookup searches found no caller
or supported promise for either method. The `TaskStore` facade and all other
Store methods remain supported; direct ledger claims and atomic
`commit_planner_decision` remain unchanged. No alias, warning, fallback, or
compatibility shim is provided.

Classification counts: canonical-public-facade=1 internal-cleanup-candidate=1 explicit-compatibility=27 external-ownership-unresolved=1

## Scan false positives and namespace notes

The repository-wide seed search also finds canonical core-model classes with the
same names as several schema aliases, especially `TaskExecution`, `TaskPipeline`,
`CodexSession`, `TaskRun`, and `WorktreeCheckpoint`. It finds publication-domain
models and publisher/test references for `PublicationGeneration`,
`PublicationReceipt`, `PublicationHealth`, and `PublicationHideFence`. Those hits
are evidence of active domain contracts, but are not interchangeable with the
`storage.schema` row aliases. Generic `getattr(...)` results throughout the
repository are unrelated dynamic attribute access and do not identify downstream
Storage imports. `CURRENT_SCHEMA_CATALOG_DIGEST` is the canonical constant and is
distinct from the seeded `SCHEMA_CATALOG_DIGEST` spelling.

The dotted-string scan found qualified Storage imports and module references, and
found no dynamic `import_module` or constructed dotted lookup for a seeded alias.
This is a repository observation only. It cannot disprove external imports or
runtime strings outside tracked files.

## Follow-up cohorts

These are recommendations for separately approvable work, not implementation
authority for this report:

1. **Operational schema aliases:** the ten exported normalized, daemon, image,
   container, validation, and resource row aliases. Characterize direct imports,
   mapper identity, and persistence contracts before considering any transition.
2. **Publication and outbox aliases:** the five publication row aliases and seven
   outbox spellings. Characterize schema-qualified imports, publication recovery,
   and table identity as one evidence cohort. `OutboxGenerationRow` remains
   externally owned/unresolved until that evidence exists; do not prescribe
   deletion for an alias solely because it is schema-local.
3. **SQLite boundary names:** the version, digest, three lifecycle-error aliases,
   and two `TaskPage` accessors. `TaskPage.tasks` is the sole bounded internal
   cleanup candidate, while its companion cursor accessor remains explicit
   compatibility; characterize direct imports, exception catches, validation
   behavior, and page consumers independently.
4. **Facade preservation:** `TaskStore` should remain the canonical public facade.
   Any change to it requires a distinct API plan rather than an alias cleanup.

No compatibility transition is authorized by this evidence-producing spike.
Repository evidence cannot observe downstream imports, so no row is recommended
for deletion or deprecation solely on the basis of a missing repository caller.
The `TaskPage.tasks` row is only a bounded follow-up candidate under the explicit
criteria above; it is not an authorization to remove the accessor.

## Verification record

- Drift check: clean for all six assigned Storage implementation and test path groups.
- Source and dotted-string inventory: completed with exact seed expression; false positives and namespace collisions recorded above.
- History inventory: one pickaxe result recorded for every seed symbol; `TaskPage.tasks` and `TaskPage.cursor` explicitly record `none found`.
- Implementation scope: no Python, tests, schemas, exports, migrations, packaging, warnings, or deprecations changed.
- Working-tree sole-path gate: a clean committed checkout cannot satisfy the required pre-commit assertion; running the exact command at `HEAD` therefore exits 1 and is not claimed as evidence. The required state is independently reproducible from this commit without using a diff as the gate:

  ```bash
  report_commit="$(git rev-parse HEAD)"
  parent_commit="$(git rev-parse HEAD^)"
  tmp="$(mktemp -d)"
  trap 'git worktree remove --force "$tmp"; rmdir "$tmp" 2>/dev/null || true' EXIT
  git worktree add --detach "$tmp" "$parent_commit"
  git -C "$tmp" restore --source="$report_commit" --worktree -- steward/STORAGE_COMPATIBILITY.md
  (
    cd "$tmp"
    test "$(git status --porcelain=v1 --untracked-files=all | cut -c4- | sort -u)" = "steward/STORAGE_COMPATIBILITY.md"
  )
  ```

  This reconstructs the parent-index working tree with this report as its sole
  uncommitted change; the inner exact status command exits 0. It is the required
  pre-commit-state check, not a base-to-HEAD or clean post-commit substitute.
- Committed scope gate: after committing, `git diff --name-only d56e71d5..HEAD | sort -u` contained only `steward/STORAGE_COMPATIBILITY.md`; the clean post-commit status is separately expected and does not substitute for the required pre-commit status gate.
- No-implementation gate: `git diff --exit-code -- steward/src/coquic_steward/storage steward/tests steward/pyproject.toml` passed.
- Hygiene gate: `git diff --check` passed.
