# V2 delivery and rollback

Site V2 is a direct cloud deployment. It does not read historical filesystem
archives, run a compatibility reader, or keep a second publication path beside
cloud publication. Cloud provider state, Steward publication, and the Site Node
application have separate operators and rollback boundaries.

## Stage 1: Validate the contracts

- Validate every schema, example, and Markdown link.
- Run the mocked D1/R2 unit and route suites without live credentials.
- Build the standalone Next.js server without a cloud connection.
- Keep one valid empty fixture and one first-real-task fixture. Empty means no
  visible task; it is not an unavailable, malformed, partial, or numeric-zero
  result.

The executable contract gate is:

```sh
nix develop -c uv run --project site-v2 python site-v2/scripts/validate_contracts.py
```

## Stage 2: Bootstrap Cloudflare locally

Cloudflare bootstrap is an explicit local operator action, never a Site GitHub
workflow step. From the reproducible Nix shell, run the read-only preview:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /absolute/path/to/steward/credentials
```

Review the structured preview and stop for any delete, replacement, update,
unsafe permission, malformed output, or secret. Add `--apply` only after that
review:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /absolute/path/to/steward/credentials \
  --apply
```

The command applies one protected current D1, verifies the exact schema,
initializes a blank database when needed, writes the three mode-0600 Steward
credential files into the mode-0700 operator directory, and passes exactly four
fields to `site/deploy/install-cloud-config.sh`. An exact schema is idempotent;
unsupported nonblank state fails without an automatic schema change. A valid
empty Site is accepted. Real-task checking remains on demand.

## Stage 3: Run Steward and Site independently

Before starting the daemon, confirm the bootstrap has installed:

- `CLOUDFLARE_ACCOUNT_ID`;
- `COQUIC_STEWARD_D1_DATABASE_ID`;
- `COQUIC_STEWARD_D1_READ_TOKEN`; and
- `COQUIC_STEWARD_PUBLIC_R2_BASE_URL`.

The values are stored in mode-0600 regular files on the host. The run wrapper
validates them and passes them only to the Next.js Node process. The ordinary
remote deploy path preserves those exports while installing a new release. It
verifies the service, HTTP/3, page marker, and configured optional checks before
declaring success.

The Site GitHub workflow may build and deploy the application, but it has no
Cloudflare credentials and never calls Pulumi or Wrangler. A Site deploy or
repair is therefore independent of provider and schema state.

## Stage 4: Prove empty and first-real-task states

Run the on-demand checker after the bootstrap. It is read-only and accepts a
valid empty publication with explicit skips for detail, trajectory, artifacts,
and cloud metrics. With a real task it also proves the rendered lifetime/daily
metrics and the task run, invocation/retry, and bounded turn surfaces,
including ownership, coverage, token totals, and numeric or N.A. cost state. It
must not require a canary, schedule, polling loop, or synthetic task.

```sh
nix develop -c uv run --project steward python scripts/check-steward-deployment.py \
  --base-url https://coquic.minhuw.dev \
  --output .remote-ci/steward-deployment.json
```

For an empty deployment, the checker proves valid status and task envelopes and
records explicit skips. Once one real published task exists, it selects the
first task, verifies ownership, loads its complete trajectory, proves the
metrics surfaces, calls the same-origin artifact action, and verifies one `307`
redirect to a safe HTTPS location whose decoded path matches the validated
public key. A failed schema, ownership, integrity, usage, or redirect check
fails closed.

The checker is on-demand only. There is no scheduled live monitor, dedicated
canary, or deployment step that fabricates an empty or real task.

## Stage 5: Current-release rollback

Application rollback is a Site concern. If an ordinary deploy, service restart,
or post-deploy verification fails, `deploy-remote.sh` restores the prior
`current` release, service files, TLS files, and non-cloud configuration. The
Steward service is then pointed at the same persistent D1 and cloud configuration
used by the restored Site release. Both provider resources remain intact; no
schema rewrite, private-object scan, dual write, compatibility reader, or
resource deletion is part of application rollback.

Provider rollback is a separately reviewed operator action. A schema change
requires a forward review; an infrastructure change must pass the same preview
safety checks. No routine Site deploy invokes that action.

## Per-route acceptance checklist

- Correct title, primary heading, canonical URL, alias behavior, and 404
  behavior.
- Complete happy-path functionality and every documented state.
- Keyboard-only and touch completion of the primary workflow.
- No critical or serious automated accessibility findings.
- No document overflow at required viewports or 200% zoom.
- Dark/light, reduced-motion, and forced-colors behavior.
- Payload validation, stale-request cancellation, retry, and partial-data
  handling.
- Direct links/downloads preserve filenames, media types, and content.

## Verification map

Every release candidate runs the credential-free application gates:

```sh
nix develop -c npm --prefix site-v2 run test:unit
nix develop -c npm --prefix site-v2 run test:steward
nix develop -c npm --prefix site-v2 run test:deploy
nix develop -c npm --prefix site-v2 run typecheck
nix develop -c npm --prefix site-v2 run build
```

The focused browser proof remains separate:

```sh
nix develop -c npm --prefix site-v2 run test:visual -- tests/steward.spec.ts --workers=1
```
