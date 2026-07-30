# Cloudflare publication storage

This Pulumi program describes the clean publication topology and least-privilege
credentials used by Steward and Site V2:

- one protected D1 database for public metadata;
- one protected R2 bucket with the public custom domain
  `artifacts.coquic.minhuw.dev` for immutable sanitized objects; and
- one protected R2 bucket for private originals, with an all-object lifecycle
  rule that expires objects after 2,592,000 seconds (30 days).

The private bucket has no public endpoint, custom domain, or development URL.
This stack contains only non-secret account, zone, naming, hostname, and
retention inputs. It creates two protected account tokens only after resolving
the exact Cloudflare permission-group names below; duplicate, missing, or
broader lookup results fail closed.

| Token | Permission groups | Resource scope |
| --- | --- | --- |
| `coquic-steward-publication` | `D1 Read`, `D1 Edit`, `Workers R2 Storage Read`, `Workers R2 Storage Write` | the configured account |
| `coquic-site-reader` | `D1 Read` | the configured account |

Cloudflare account-token policies cannot scope D1 to one database. D1 therefore
contains public-safe rows only. Site receives no R2 permission or credential;
sanitized objects remain anonymously readable at
`https://artifacts.coquic.minhuw.dev`.

The stack exports three non-secret topology values (`d1_database_id`,
`public_bucket_name`, and `public_base_url`) and the following secret values:

- `steward_config`: account ID, D1 database ID, Steward D1 token, both R2
  bucket names, and the S3 access-key pair;
- `site_config`: account ID, D1 database ID, Site D1 Read token, and the public
  R2 base URL;
- standalone Steward/Site token and S3 credential exports for the downstream
  secret-file handoff.

The S3 access-key ID is the Steward token ID. Its secret access key is the
lower-case SHA-256 digest of the one-time Steward token value. Pulumi marks the
provider token value, composite objects, and standalone credential exports as
secret; no output or log should stringify a secret. The bootstrap Cloudflare
token is provider authentication only and is never a stack input or export.

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
stores those values in configuration. Write the secret exports to daemon-only
regular files with private permissions; never mount them into task, planner, or
validation containers. Rotate both account tokens together through an explicit
operator review because the S3 secret derivation changes when the Steward token
changes.

Use the operator's approved bootstrap authentication for the read-only preview:

```sh
pulumi preview --diff
```

Review the graph and any replacement proposal before an operator applies it.
The preview must show exactly five storage resources, two account tokens, and
redacted token values. Stop if Pulumi proposes a delete or replacement outside
an explicit credential rotation review, if a policy contains a broader group,
or if any secret appears in preview output. This plan does not run `pulumi up`.
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
