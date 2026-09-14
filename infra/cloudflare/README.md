# Cloudflare publication operations

This stack is the provider boundary for Steward cloud publication and Site V2.
It creates one protected current D1, one public R2 bucket for immutable
sanitized objects, one private R2 bucket for optional originals, and one Worker
with a named Durable Object for live Steward state. The private bucket has no
public endpoint and expires objects after 2,592,000 seconds (30 days).

D1 rows and public objects contain only the validated public contract. Local
SQLite, task archives, and the optional original remain Steward's private
operational evidence. Cloudflare account-token policies are account-scoped, so
the D1 database must never receive private-shaped rows.

The live gateway exposes public `GET /api/steward/live`, authenticated `POST`
on the same path, and public WebSocket updates at `/api/steward/live/ws` on
`https://live.coquic.minhuw.dev`. Every request is routed to the single Durable
Object selected with `idFromName("global")`. The response contract is
`contracts/steward-live/live-state.schema.json`; no snapshot exists until the
first accepted Steward update, so initial reads return JSON with status 503.

## Inputs and authority

Run the bootstrap from the operator's local reproducible shell. It is not a
GitHub Actions step, a Site deploy step, or a Steward lifecycle hook.
The default Nix shell bundles Pulumi's Python language plugin; reopen
`nix develop` after shell changes. Run Pulumi through `uv run --locked --project
infra/cloudflare` from the repository root so its Python SDK and package-discovery
`pip` come from the locked project environment.

Before the bootstrap, the operator must have:

- `nix develop`, Pulumi, Wrangler, and the repository checkout available;
- a logged-in Pulumi CLI and the selected `coquic-production` stack;
- a bootstrap `CLOUDFLARE_API_TOKEN` in the process environment only;
- an absolute credential directory that is either absent or owned by the
  invoking user and mode `0700`; and
- the protected SSH key and known-hosts entry required by
  `site/deploy/install-cloud-config.sh`.

The process-local bootstrap token authorizes Pulumi provider operations and the
Wrangler remote D1 inspection/bootstrap. It is never persisted or logged: do
not put it in Pulumi configuration, a command argument, `.env`, a credential
file, or captured output. It is not a Steward or Site runtime credential. Keep
Pulumi state and any stack configuration containing secrets outside source
control.

The canonical non-secret inputs are listed in
`Pulumi.coquic-production.yaml.example`.

If an existing `production` stack manages these cloud resources, do not create
a parallel stack. Optional operator-only migration, from `infra/cloudflare`
with Pulumi already logged in:

```sh
pulumi stack select production
pulumi stack rename coquic-production
```

After renaming, rerun and review the bootstrap preview. Existing stacks that
omit `live_hostname` use the fixed `live.coquic.minhuw.dev` default; setting it
explicitly is optional. Do not copy or rename old saved plans or review records.

For a fresh deployment without existing cloud resources, initialize or select
`coquic-production` and set only these canonical non-secret values:

```sh
nix develop
nix develop -c uv sync --project infra/cloudflare --locked
cd infra/cloudflare
pulumi login
pulumi stack select coquic-production --create
pulumi config set account_id <account-id>
pulumi config set zone_id <zone-id>
pulumi config set database_name coquic-publication
pulumi config set public_bucket_name coquic-public-artifacts
pulumi config set private_bucket_name coquic-private-originals
pulumi config set public_hostname artifacts.coquic.minhuw.dev
pulumi config set live_hostname live.coquic.minhuw.dev
pulumi config set private_retention_seconds 2592000
```

Use `pulumi config set --secret` for any later sensitive stack input. Token
creation and the protected handoff are owned by this bootstrap; token rotation
requires a separate review because the Steward R2 secret and the distinct,
domain-separated live write token are derived from the Steward token.

## Preview and bootstrap

Return to the repository root after setting the Pulumi configuration. The only
rollout command is:

```sh
nix develop -c uv run --locked --project infra/cloudflare \
  bash infra/cloudflare/scripts/deploy-production.sh \
  --stack coquic-production \
  --credentials-dir /srv/coquic-steward/private/credentials
```

The default is a read-only structured Pulumi preview. Provider output is
captured below a mode-`0700` temporary directory and reduced to operation
counts. After the safety checks pass, the exact plan and a review record are
retained in a private mode-`0700` plan directory; both files are mode `0400`.
The default directory is `${XDG_STATE_HOME:-$HOME/.local/state}/coquic-cloudflare-bootstrap`;
use `--plan-dir` to select another private absolute directory. Stop when the
preview is malformed, contains a delete or replacement, updates anything except
the live Worker script in place, proposes a broader permission, or exposes a
secret. Unchanged resources are included so
retries can validate the complete graph; Pulumi's exact `[secret]` redaction
marker is accepted, never an exposed credential value. The command never
applies a plan in its default form.

After reviewing the preview, rerun the same command with `--apply`:

```sh
nix develop -c uv run --locked --project infra/cloudflare \
  bash infra/cloudflare/scripts/deploy-production.sh \
  --stack coquic-production \
  --credentials-dir /srv/coquic-steward/private/credentials \
  --apply
```

The bootstrap invocation authenticates, validates the retained review record
and digest, and applies exactly that operator-reviewed plan with Pulumi. It
never creates a replacement preview. Pulumi rejects a saved plan that no
longer matches current provider state or configuration. The command then
validates the one protected D1, checks the exact schema, installs the four
Steward files, and passes exactly five fields through the protected Site
handoff. A blank D1 is initialized; an exact schema is a no-op; incompatible
nonblank state fails without an unreviewed schema change. An empty Site is
valid. Real-task verification stays with the on-demand deployment checker.

## D1 and credential handoff

After a successful provider apply, the command validates the exact Pulumi
`steward_config` and `site_config` objects from a private `--show-secrets`
capture. Both objects carry the same `d1_database_id`; mismatched IDs,
malformed IDs, unexpected fields, or invalid URLs stop the run without printing
values.

It generates a private temporary Wrangler binding pinned to the validated
Pulumi database UUID and explicitly selects the validated account. No manual
Wrangler configuration or database-name discovery is needed. The binding and
Wrangler logs are removed with the private temporary directory on exit.

It then queries D1 with a fixed read-only `sqlite_master` statement:

- a blank database is bootstrapped from `contracts/steward-cloud/d1.sql` and
  queried again;
- an exact schema is a no-op; and
- malformed output or any schema drift stops before host credentials are
  written.

D1's system-owned `_cf_KV` table is excluded from the application comparison;
a database containing only that table is blank. Other `_cf_` objects and all
application tables, indexes, and triggers remain subject to the exact check.

Schema changes require a separately reviewed forward change. Do not edit the
schema in place or use a second database to hide drift.

The `--credentials-dir` target must be a real mode-`0700` directory owned by
the invoking user. The command atomically installs exactly these four regular
files, each mode `0600`:

| Path | Pulumi value | Compose target |
| --- | --- | --- |
| `d1-read-token` | `steward_config.d1_token` | `/run/secrets/d1-read-token` |
| `r2-access-key-id` | `steward_config.s3_access_key_id` | `/run/secrets/r2-access-key-id` |
| `r2-secret-access-key` | `steward_config.s3_secret_access_key` | `/run/secrets/r2-secret-access-key` |
| `live-write-token` | `steward_config.live_write_token` | `/run/secrets/live-write-token` |

Symlinks, non-regular files, unowned targets, unsafe directory modes, and
unsafe replacement states are refused. Existing regular files are staged and
restored if any part of the four-file install fails. Values never appear in
stdout, stderr, arguments, Compose environment, or public publication data.

The bootstrap creates a mode-`0600` temporary input containing exactly these
five Site fields and invokes the protected SSH handoff:

```text
CLOUDFLARE_ACCOUNT_ID
COQUIC_STEWARD_D1_DATABASE_ID
COQUIC_STEWARD_D1_READ_TOKEN
COQUIC_STEWARD_PUBLIC_R2_BASE_URL
COQUIC_STEWARD_LIVE_SNAPSHOT_URL
```

`site/deploy/install-cloud-config.sh` owns remote validation, atomic app-env
replacement, service configuration, and its local transaction. When
`COQUIC_DEMO_REMOTE_SSH_KEY_PATH` is unset or empty, the installer uses normal
OpenSSH authentication (agent or default SSH configuration). A nonempty value
must name an existing key file and is passed to both SSH and SCP. Batch mode
and strict host-key checking remain enabled. The rollout
explicitly unsets provider credentials for that child, so Site receives only
the five fields listed above. It installs Site's cloud values but does not
deploy a Site release or launch Steward.

## Failure and rerun boundaries

The stages are intentionally separate:

| Failure | State that may remain | Recovery |
| --- | --- | --- |
| Pulumi auth/preview/parse | No provider or host mutation; no accepted apply artifact | Correct local inputs and rerun the preview. |
| Pulumi apply | Cloud state may be partial; D1 and host were not attempted | Inspect Pulumi state, review the next safe preview, then rerun the bootstrap. |
| Outputs or schema verification | Cloud apply may be complete; no host files were installed | Resolve the provider or schema issue under review, then rerun. |
| Four-file credential install | Prior regular files are restored, or no new set exists | Fix ownership, mode, or path issues and rerun. |
| Site SSH handoff | D1 and Steward files remain | Repair the protected SSH boundary and rerun; no automatic provider reversal runs. |

After a post-apply failure (such as D1 inspection), the previous plan has
already been consumed. Rerun without `--apply` and review a fresh preview;
if the cloud apply completed without drift, expect ten unchanged resources.
Then rerun with `--apply` to finish the remaining bootstrap steps. Do not
recreate resources or restore the consumed plan.

Each new preview repeats the destructive-plan and secret checks. An apply
consumes only the retained reviewed plan, and the bootstrap repeats the D1
schema check. An exact D1 schema is a no-op, and existing credential files are
replaced atomically. Never use a manual delete, broad glob, or ad hoc secret
copy to recover a partial run.

Application rollback is a Site release/config concern followed by Steward
reconfiguration to the same persistent D1 and cloud configuration. It does not
migrate, scan private R2, dual-write, or delete provider state. Provider changes
and token rotation remain explicit operator reviews; there is no routine
provider reversal command.

## Local checks

The provider tests use mocks; the toolchain regression runs a real Pulumi
Python preview against an isolated local file backend. Neither contacts
Cloudflare, Wrangler, SSH, or a live endpoint:

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
- [Site V2 delivery and checker](../../site-v2/MIGRATION.md)
