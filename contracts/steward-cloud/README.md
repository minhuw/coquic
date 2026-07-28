# Harbor ATIF v1.7 schema

This directory contains the byte-stable JSON Schema generated from Harbor's
`Trajectory` model. It pins the immutable upstream base used by Steward and
Site contract work; CoQUIC-specific semantic restrictions are defined by later
contracts.

- Upstream: `https://github.com/laude-institute/harbor.git`
- Commit: `f742842cc914d99a081171c0ced3fe152715ac27`
- Schema version: `ATIF-v1.7`
- Model import: `harbor.models.trajectories.trajectory.Trajectory`
- SHA-256: `a597b620b77ecb4d0cff1b89fa6b74baf15086bea43fdb6c85d8b47df6cf3ec9`

The schema is serialized with `Trajectory.model_json_schema()`, JSON keys
sorted lexicographically, two-space indentation, UTF-8 encoding, and one
trailing newline. Harbor is not a CoQUIC runtime dependency.

## Reproduction

Run the following from the repository root. The `sed` stage removes the
development-shell banner so only the Python JSON output is captured.

```sh
harbor_dir=$(mktemp -d)
git -C "$harbor_dir" init
git -C "$harbor_dir" fetch --depth=1 https://github.com/laude-institute/harbor.git f742842cc914d99a081171c0ced3fe152715ac27
git -C "$harbor_dir" checkout --detach FETCH_HEAD
nix develop -c uv run --project "$harbor_dir" --frozen python -c 'import json; from harbor.models.trajectories.trajectory import Trajectory; print(json.dumps(Trajectory.model_json_schema(), indent=2, sort_keys=True))' | sed -n '/^{/,$p' > contracts/steward-cloud/atif-v1.7.schema.json
```

The resulting file must match the recorded SHA-256 and compare byte-for-byte
with this checked-in schema.
