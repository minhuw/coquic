# Cloudflare publication operations

This stack is the provider boundary for Steward cloud publication and Site V2.
It retains the protected legacy D1 database and creates a second protected,
clean usage D1 for the cutover. It also creates one public R2 bucket for
immutable sanitized objects and one private R2 bucket for optional originals.
The private bucket has no public endpoint or development URL and expires
objects after 2,592,000 seconds (30 days).

D1 rows and public objects contain only the validated public contract. Local
SQLite, task archives, and the optional original remain Steward's private
operational evidence. Cloudflare account-token policies are account-scoped, so
the D1 database must never receive private-shaped rows.

## Inputs and authority

Run the rollout from the operator's local reproducible shell. It is not a
GitHub Actions step, a Site deploy step, or a Steward lifecycle hook.

Before the rollout, the operator must have:

- `nix develop`, Pulumi, Wrangler, and the repository checkout available;
- a logged-in Pulumi CLI and the selected `production` stack;
- a bootstrap `CLOUDFLARE_API_TOKEN` in the process environment only;
- an absolute credential directory that is either absent or owned by the
  invoking user and mode `0700`; and
- the protected SSH key and known-hosts entry required by
  `site/deploy/install-cloud-config.sh`.

The process-local bootstrap `CLOUDFLARE_API_TOKEN` authorizes both Pulumi
provider operations and the Wrangler remote D1 inspection/bootstrap performed
by this rollout; Wrangler inherits it for its `d1 execute --remote` calls. It
is never persisted or logged: do not put it in Pulumi configuration, a command
argument, `.env`, a credential file, or any captured output. It is not a
Steward or Site runtime credential. Keep Pulumi state and any stack
configuration containing secrets outside source control.

Initialize or select the stack and set only the non-secret topology values:

```sh
nix develop
nix develop -c uv sync --project infra/cloudflare --locked
cd infra/cloudflare
pulumi login
pulumi stack select production
pulumi config set account_id <account-id>
pulumi config set zone_id <zone-id>
pulumi config set database_name coquic-publication
pulumi config set usage_database_name coquic-publication-usage
pulumi config set public_bucket_name coquic-public-artifacts
pulumi config set private_bucket_name coquic-private-originals
pulumi config set public_hostname artifacts.coquic.minhuw.dev
pulumi config set private_retention_seconds 2592000
```

Use `pulumi config set --secret` for any later sensitive stack input. Token
creation and the protected handoff are owned by this rollout; token rotation
requires a separate review because the Steward R2 secret is derived from the
Steward token.

## Preview and apply

Return to the repository root after setting the Pulumi configuration; the
rollout command below is written relative to that root.

`infra/cloudflare/scripts/deploy-production.sh` is the only rollout command.
It requires an absolute credentials directory, an explicit gate, and permits
only the `production` stack. Preview is read-only; prepare is the only mode
that may apply the create-only candidate plan:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /srv/coquic-steward/private/credentials \
  --mode prepare
```

The default is a read-only structured Pulumi preview. Provider output is
captured below a mode-`0700` temporary directory and reduced to operation counts;
the temporary plan is mode `0400` and is removed on exit. Review the preview
before continuing. Stop when the preview is malformed, contains a delete or
replacement, proposes a broader permission, or exposes a secret. The command
never applies a plan in its default mode.

After reviewing the preview, rerun the same command with `--apply`:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /srv/coquic-steward/private/credentials \
  --mode prepare \
  --apply
```

The prepare invocation creates and rechecks a fresh structured preview, then
applies that exact saved plan with Pulumi. The preview must contain creates and
no updates, deletes, or replacements. It bootstraps the candidate schema and
installs the three Steward files, but never invokes Site. It never destroys
resources, rotates tokens, or starts Steward.

After Steward has produced one real task in the candidate D1, rerun the same
command in activation mode. Activation never applies Pulumi or bootstraps a
blank database. It rechecks the exact schema and a joined task/usage sample
covering runs, invocations, turns, globals, ownership, coverage, Token fields,
and numeric or N.A. cost state before passing the candidate ID to Site:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /srv/coquic-steward/private/credentials \
  --mode activate \
  --apply
```

## D1 and credential handoff

After a successful provider apply (or a read-only activation preview), the
command validates the exact Pulumi `steward_config` and `site_config` objects
from a private `--show-secrets` capture. Both objects carry the candidate
`d1_database_id` and the old `rollback_d1_database_id`; mismatched IDs,
malformed IDs, unexpected fields, or invalid URLs stop the run without printing
the values. The old database is never queried or handed to either producer or
reader during this rollout.

It then queries D1 with a fixed read-only `sqlite_master` statement:

- a blank database is bootstrapped from `contracts/steward-cloud/d1.sql` and
  queried again;
- an exact schema is a no-op; and
- malformed output or any schema drift stops before host credentials are
  written.

Schema changes require a separately reviewed forward migration. Do not edit
the schema in place or use a rollback to hide drift.

The `--credentials-dir` target must be a real mode-`0700` directory owned by
the invoking user. The command atomically installs exactly these three regular
files, each mode `0600`:

| Path | Pulumi value | Compose target |
| --- | --- | --- |
| `d1-read-token` | `steward_config.d1_token` | `/run/secrets/d1-read-token` |
| `r2-access-key-id` | `steward_config.s3_access_key_id` | `/run/secrets/r2-access-key-id` |
| `r2-secret-access-key` | `steward_config.s3_secret_access_key` | `/run/secrets/r2-secret-access-key` |

The path names are the host contract; the D1 token has the provider permission
needed by the trusted publisher. Symlinks, non-regular files, unowned targets,
unsafe directory modes, and unsafe replacement states are refused. Existing
regular files are staged and restored if any part of the three-file install
fails. Values never appear in stdout, stderr, arguments, Compose environment,
or public publication data.

Activation creates a mode-`0600` temporary input containing exactly these four
Site fields and invokes the protected SSH handoff. Prepare deliberately does
not create this file or invoke Site:

```text
CLOUDFLARE_ACCOUNT_ID
COQUIC_STEWARD_D1_DATABASE_ID
COQUIC_STEWARD_D1_READ_TOKEN
COQUIC_STEWARD_PUBLIC_R2_BASE_URL
```

`site/deploy/install-cloud-config.sh` owns remote validation, atomic app-env
replacement, service configuration, and its rollback transaction. The rollout
invokes that child with `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_API_KEY`, and
`PULUMI_ACCESS_TOKEN` explicitly unset, so Site receives only the four fields
listed above. It installs Site's cloud values but does not deploy a Site
release or launch Steward.

## Failure and rerun boundaries

The stages are intentionally not one fictional transaction. Use this table to
decide what is safe to inspect and rerun:

| Failure | State that may remain | Recovery |
| --- | --- | --- |
| Pulumi auth/preview/parse | No provider or host mutation | Correct local inputs and rerun preview. |
| Pulumi apply during prepare | Cloud state may be partial; D1 and host were not attempted | Inspect Pulumi state, review the next create-only preview, then rerun prepare. |
| Outputs or candidate schema verification | Cloud apply may be complete; no host files were installed | Resolve the provider/schema issue under review, then rerun prepare or activation. |
| Three-file credential install | Prior regular files are restored, or no new set exists | Fix ownership/mode/path issues and rerun prepare. |
| Candidate sample | Steward remains on the candidate; Site is unchanged | Repair the producer/task evidence and rerun activation. |
| Site SSH handoff | Candidate D1 and Steward files remain; old D1 is untouched | Repair the protected SSH boundary and rerun activation; no automatic cloud rollback runs. |

Every rerun repeats the destructive-plan and schema checks. An exact D1 schema
is a no-op, and existing credential files are replaced atomically. Never use a
manual delete, broad glob, or ad hoc secret copy to recover a partial run.

Rollback before activation restores Steward's prior configuration and keeps
Site on the old D1. After activation, rollback is a paired Site release/config
restore followed by Steward reconfiguration to the retained
`rollback_d1_database_id`; it does not migrate, scan, dual-write, or delete
either database. Provider changes and token rotation remain explicit operator
reviews. There is no routine provider rollback command.

## Site replica cleanup boundary

The Cloudflare rollout and ordinary Site deploy or rollback never delete local
replicas. For this rollout, the following exact set is the sole cleanup
authority for retired Site-host replica roots after the checker proof and the
chosen rollback window:

```text
/opt/coquic-demo/steward/tasks
/opt/coquic-demo/steward/control-loop
/opt/coquic-demo/steward/cache
```

Remove at most one listed directory at a time with an operator-owned manual
command. No other Site path or document is cleanup authority for this rollout;
do not add or reclassify a target from another document. These are retired Site
replicas, not Steward's private `$COQUIC_HOME/tasks`,
`$COQUIC_HOME/control-loop`, or any source archive; never delete those private
archives or use a recursive glob.

## Local checks

The provider tests use mocks and do not contact Cloudflare, Wrangler, SSH, or a
live endpoint:

```sh
nix develop -c env -u PYTHONPATH uv run --project infra/cloudflare pytest infra/cloudflare/tests -q
nix develop -c env -u PYTHONPATH uv run --project infra/cloudflare pytest infra/cloudflare/tests/test_deploy_production.py -q
nix develop -c env -u PYTHONPATH uv run --project infra/cloudflare python -m compileall -q infra/cloudflare
```

The checked-in example contains names and paths only. Keep generated Pulumi
state, temporary output, and credentials outside source control.

Related operator runbooks:

- [Steward container operations](../../steward/CONTAINER_OPERATIONS.md)
- [Steward cloud publication](../../steward/CLOUD_PUBLICATION.md)
- [Site V2 cutover and checker](../../site-v2/MIGRATION.md)
