# Classification Guide

Use the narrowest issue type that describes the work.

- `bug`: behavior is wrong, broken, or regressed.
- `feature`: new user-visible or protocol-visible behavior.
- `enhancement`: improves existing behavior without changing its basic contract.
- `tech-debt`: cleanup, refactor, simplification, or maintainability.
- `test-gap`: missing or weak test coverage.
- `docs`: documentation, comments, website, examples, or guides.
- `investigation`: unknown cause or unclear design; output should be findings and next issues.
- `compliance`: tracks RFC, Duvet, spec, or standards conformance.
- `ci`: GitHub Actions, automation, release, deploy, or tooling workflow.
- `perf`: performance, benchmarking, profiling, or resource use.
- `interop`: behavior found through peer interoperability or protocol test suites.

Prefer `investigation` when the implementation path is not yet clear. Prefer `feature` over `compliance` when the issue is primarily to add behavior, even if the source is an RFC MAY.
