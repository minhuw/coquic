# Steward Dashboard Shadow Rollout Exit Report

Date: 2026-07-13
Rollback point: `ffb27842` (`test(site): cover steward public monitor`)
Local rollout target: `http://127.0.0.1:3101`
Public target: `https://coquic.minhuw.dev/steward`

## Recommendation

The repository-local shadow gate passes. The daemon, CLI, producer contract,
site decoder, retained read views, and desktop/mobile monitor flows are ready
for the code cutover. The deployed target still needs a site deployment before
the migration can be declared complete in production: `GET /steward/status`
currently returns `404`, while the legacy `GET /steward/status.json` returns
`200`. The cutover work may proceed against the local evidence, but release
completion must re-run the public endpoint checks after deployment.

## Evidence

| Area | Command or observation | Result |
| --- | --- | --- |
| CLI controls | Isolated `COQUIC_HOME=/tmp/coquic-shadow-cli-20260713` smoke: `--help`, `status`, `tick --no-plan --no-dispatch`, `daemon --once --no-plan --no-dispatch`, `publish-public-state --output .../status.json`, `audit-invariants` | All commands exited successfully; tick wakeup was consumed by the one-shot daemon; the generated v3 snapshot validated and contained no seeded private markers |
| Runtime and publication | `steward/.venv/bin/python -m pytest -q steward/tests/test_runtime_heartbeat.py steward/tests/test_publisher_health.py steward/tests/test_public_data_hardening.py steward/tests/test_public_mirror_contract.py` | 24 passed; heartbeat publication was also repeated 10 times after the atomic writer fix |
| Legacy parity baseline | `steward/.venv/bin/python -m pytest -q steward/tests/test_clean_steward.py -k 'web_'` | 38 passed, 218 deselected; the local API still represented the pre-cutover comparison baseline |
| Site unit and route coverage | `npm test -- --reporter=dot` in `site/next` | 45 passed across 5 files |
| Site browser coverage | `npm run test:e2e -- --reporter=line` in `site/next` | 8 passed across desktop and mobile projects |
| Build | `npm run build` in `site/next` | Next.js production build passed; status, task data, artifact, planner, and task detail routes were generated or classified dynamic as expected |
| Privacy | Producer contract fixtures and artifact scans | No `/home/`, `/media/`, `/tmp/`, private-key, bearer-token, prompt, or thread markers in the generated public snapshot/detail evidence |
| Site outage behavior | Site route tests for missing, unreadable, malformed, incompatible, and invalid status files | All failures return an explicit unavailable reason and `Cache-Control: no-store`; daemon work remains local |
| Deployed target | `GET https://coquic.minhuw.dev/steward` -> `200`; `GET /steward/status` -> `404`; `GET /steward/status.json` -> `200` | Deployment follow-up required; the target is still serving the legacy status path |

## Scenario Results

1. Idle daemon: covered by the empty and idle v3 fixtures, isolated CLI one-shot
   cycle, runtime heartbeat tests, and the browser overview flow.
2. Signal fetch and planner task creation: covered by the integration fixture,
   planner history route tests, signal view tests, and the planner browser flow.
3. Fix and feature workflows: retained task detail fixtures cover feature
   planning, worker, validation, review, and integration presentation.
4. Validation failure, review rejection, blocked task, and failed task: covered
   by the blocked and failed v3 fixtures and producer state parametrization.
5. Integration success: covered by the integration fixture, commit projection,
   task detail integration records, and route/browser tests.
6. Publisher outage and recovery: covered by publisher failure categories,
   retry state, digest transitions, and daemon continuation tests.
7. Daemon and site restart, stale data, and unsupported schema: covered by the
   runtime heartbeat, freshness, route-unavailability, and browser fixture
   setup tests.

## Gate Measurements

- Active polling is configured for 10 seconds and the daemon heartbeat interval
  is 30 seconds, leaving a 40-second local visibility bound before transport
  latency and deployment caching.
- Idle polling backs off to 30 seconds; stale and offline mirrors back off to
  45 seconds.
- The local route always uses `no-store`; the remote endpoint must be checked
  again after the new site build is deployed.

## Exit Decision

Local code gate: **GO** for subplan 16 implementation.

Production deployment gate: **FOLLOW-UP REQUIRED**. Deploy the site containing
the v3 monitor route and then verify `/steward/status`, `/steward/data/tasks/`,
redaction, and the 60-second active update bound before removing the rollback
path in production.
