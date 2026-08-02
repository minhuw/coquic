# V2 Delivery, Rollback, and Cutover Gates

Site V2 is a clean cloud rollout. It does not migrate historical filesystem
archives, run an archive compatibility reader, or keep rsync beside cloud
publication. Cloud provider state, Steward publication, and the Site Node
application have separate operators and rollback boundaries.

## Stage 1: Validate the contracts

- Validate every schema, example, and Markdown link.
- Run the mocked D1/R2 unit and route suites with no live credential.
- Build the standalone Next.js server without a cloud connection.
- Keep one valid empty fixture and one first-real-task fixture. Empty means no
  visible task; it is not an unavailable, malformed, partial, or numeric-zero
  result.

The executable contract gate is:

```sh
nix develop -c uv run --project site-v2 python site-v2/scripts/validate_contracts.py
```

## Stage 2: Roll out Cloudflare locally

Cloudflare rollout is an explicit local operator action, never a Site GitHub
workflow step. From the reproducible Nix shell, run the only rollout command:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /absolute/path/to/steward/credentials
```

The default is a structured, read-only Pulumi preview. Review the preview and
stop for any delete or replacement, unsafe permission, malformed output, or
secret in output. Add `--apply` only after that review:

```sh
nix develop -c infra/cloudflare/scripts/deploy-production.sh \
  --stack production \
  --credentials-dir /absolute/path/to/steward/credentials \
  --apply
```

Apply uses the accepted saved plan, verifies the exact D1 schema, bootstraps a
blank database when necessary, and refuses schema drift until a separately
reviewed forward migration exists. It writes three mode-0600 Steward credential
files into the operator-selected mode-0700 directory, then passes exactly four
Site fields to `site/deploy/install-cloud-config.sh` over the protected SSH
handoff. It does not deploy Site, start Steward, delete resources, rotate
tokens, or start a recurring monitor.

## Stage 3: Activate Site independently

Before activation, confirm the protected handoff has installed:

- `CLOUDFLARE_ACCOUNT_ID`;
- `COQUIC_STEWARD_D1_DATABASE_ID`;
- `COQUIC_STEWARD_D1_READ_TOKEN`; and
- `COQUIC_STEWARD_PUBLIC_R2_BASE_URL`.

The values are a mode-0600 regular file on the host. `site/deploy/run-demo.sh`
validates them and passes them only to the Next.js Node process. The ordinary
deploy path (`site/deploy/deploy-remote.sh`) preserves those exports while
installing a new release. It verifies the service, HTTP/3, page marker, and
configured optional checks before declaring success.

The Site GitHub workflow may build and deploy the application, but it has no
Cloudflare credentials and never calls Pulumi or Wrangler. A Site deploy or
repair is therefore independent of provider/schema state.

## Stage 4: Prove empty and first-real-task states

Run the on-demand checker after activation. It is read-only and accepts a valid
empty publication. It must not require a canary, schedule, polling loop, or
synthetic task.

```sh
nix develop -c uv run --project steward python scripts/check-steward-deployment.py \
  --base-url https://coquic.minhuw.dev \
  --output .remote-ci/steward-deployment.json
```

For an empty deployment, the checker proves valid status and task envelopes and
records explicit skips for detail, trajectory, and artifacts. Once one real
published task exists, it selects the first task, verifies task ownership,
loads its complete trajectory, calls the same-origin artifact action, and
verifies one `307` redirect to a safe HTTPS location whose decoded path matches
the validated public key. A failed schema, ownership, integrity, or redirect
check fails closed.

The checker is on-demand only. There is no scheduled live monitor or dedicated
canary, and no deployment step fabricates an empty or real task.

## Stage 5: Rollback and cleanup

Application rollback is a Site concern. If an ordinary deploy, service restart,
or post-deploy verification fails, `deploy-remote.sh` restores the prior
`current` release, service files, TLS files, and non-cloud configuration. The
four protected cloud exports are carried forward unchanged. Cloudflare
resources, D1 schema, R2 objects, and Steward credentials are not rolled back
by Site application rollback.

Provider rollback is a separately reviewed operator action. A schema change
requires a forward migration review; an infrastructure change must pass the
same preview safety checks. No routine Site deploy invokes that action.

Retired Site replica roots remain available through the rollback window. The
Steward source archives remain permanently preserved at
`/opt/coquic-demo/steward/tasks` and
`/opt/coquic-demo/steward/control-loop`; ordinary deploy, repair, and rollback
never delete either path. The Site replica cache
`/opt/coquic-demo/steward/cache/site-v2.sqlite` remains available during that
window and is the delayed manual cleanup target. After the cutover has been
verified with the empty or first-real-task checker and the operator's rollback
window has elapsed, an operator may remove that exact cache path manually.
This deletion is explicit and never part of ordinary deploy, repair, or
rollback; those actions delete none of the named paths.

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
