# coquic

coquic is an experimental project to see how far a feature-complete QUIC implementation can be built using only GPT-5.4 + Codex, documenting the progress, limits, and lessons from that effort.

## Development

Enter the reproducible development shell with:

```bash
nix develop
```

The shell installs the project's pre-commit hooks automatically. You can also run the checks manually:

```bash
pre-commit run clang-format --all-files --show-diff-on-failure
pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
zig build
zig build test
zig build coverage
```

The C++ test suite uses GoogleTest. `zig build coverage` writes:

- `coverage/html/index.html`
- `coverage/lcov.info`

## CI

GitHub Actions runs the same four checks through `nix develop`:

- format check
- lint
- build
- test and coverage artifact export
