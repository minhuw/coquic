# Cloudflare publication storage

This Pulumi program describes the clean publication topology used by Steward
and Site V2:

- one protected D1 database for public metadata;
- one protected R2 bucket with the public custom domain
  `artifacts.coquic.minhuw.dev` for immutable sanitized objects; and
- one protected R2 bucket for private originals, with an all-object lifecycle
  rule that expires objects after 2,592,000 seconds (30 days).

The private bucket has no public endpoint, custom domain, or development URL.
This stack contains only non-secret account, zone, naming, hostname, and
retention inputs. It does not create credentials, apply the D1 schema, or
contact Cloudflare during tests.

## Operator workflow

Run Pulumi from the reproducible development shell:

```sh
nix develop
nix develop -c uv sync --project infra/cloudflare --locked
cd infra/cloudflare
pulumi login
pulumi stack init production
cp Pulumi.production.yaml.example Pulumi.production.yaml
pulumi config set account_id <account-id>
pulumi config set zone_id <zone-id>
pulumi config set database_name coquic-publication
pulumi config set public_bucket_name coquic-public-artifacts
pulumi config set private_bucket_name coquic-private-originals
pulumi config set public_hostname artifacts.coquic.minhuw.dev
pulumi config set private_retention_seconds 2592000
```

When a later operator workflow needs sensitive stack configuration, set it with
Pulumi's encrypted form (`pulumi config set --secret`). Plans 050 and 057 define
which credentials exist and how they are handed off; this topology plan never
stores or exports those values.

Use the operator's approved bootstrap authentication for the read-only preview:

```sh
pulumi preview --diff
```

Review the graph and any replacement proposal before an operator applies it.
Plan 059 owns the explicit apply and D1 schema rollout. Plans 050 and 057 own
credential creation and the protected secret handoff. Plan 060 owns Site V2
activation and rollback. This plan never runs `pulumi up`.

## Local checks

The tests use Pulumi mocks and need no account access or network:

```sh
nix develop -c uv sync --project infra/cloudflare --locked
nix develop -c uv run --project infra/cloudflare pytest
nix develop -c uv run --project infra/cloudflare python -m compileall -q infra/cloudflare
```

Keep any stack configuration containing operator credentials outside source
control. The checked-in example contains placeholders only.
