# Cloudflare publication operations

This stack is the provider boundary for Steward cloud publication and Site V2.
It creates one protected D1 database for public metadata, one public R2 bucket
for immutable sanitized objects, and one private R2 bucket for optional
originals. The private bucket has no public endpoint or development URL and
expires objects after 2,592,000 seconds (30 days).

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
It requires an absolute credentials directory and permits only the
`production` stack:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /srv/coquic-steward/private/credentials
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
  --apply
```

The apply invocation creates and rechecks a fresh structured preview, then
applies that exact saved plan with Pulumi. It does not accept a separate plan
file or silently approve a destructive change. It never destroys resources,
rotates tokens, deploys the Site application, starts Steward, or starts a
recurring monitor.

## D1 and credential handoff

After a successful provider apply, the command validates the exact Pulumi
`steward_config` and `site_config` objects from a private `--show-secrets`
capture. Unexpected fields, mismatched account/database IDs, malformed IDs, or
invalid URLs stop the run without printing the values.

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

Finally, the command creates a mode-`0600` temporary input containing exactly
these four Site fields and invokes the protected SSH handoff:

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
| Pulumi apply | Cloud state may be partial; D1 and host were not attempted | Inspect Pulumi state, review the next preview, then rerun the same command. |
| Outputs or D1 verification | Cloud apply may be complete; no host files were installed | Resolve the provider/schema issue under review, then rerun. |
| Three-file credential install | Prior regular files are restored, or no new set exists | Fix ownership/mode/path issues and rerun. |
| Site SSH handoff | Cloud, D1, and verified Steward files remain | Repair the protected SSH boundary and rerun; no automatic cloud rollback runs. |

Every rerun repeats the destructive-plan and schema checks. An exact D1 schema
is a no-op, and existing credential files are replaced atomically. Never use a
manual delete, broad glob, or ad hoc secret copy to recover a partial run.

Site application rollback is independent: it preserves the four cloud fields
and does not change Pulumi resources, D1 schema, R2 objects, or Steward files.
Provider changes and token rotation remain explicit operator reviews. There is
no routine provider rollback command.

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
