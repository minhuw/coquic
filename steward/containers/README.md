# Steward container boundaries

This directory contains the Compose and management implementation for Steward's
container deployment. The daemon is the trusted control side; task and
validation containers are restricted development and checking closures, and
the planner receives only sealed planning history, a private session, and
bounded output staging.

## Operational authority

The [container operations runbook](../CONTAINER_OPERATIONS.md) is the sole
authoritative contract for container identity, mounts, credentials, launch,
lifecycle, recovery, cleanup, Site handoff, and local proof. This README is a
boundary overview and navigation entry point; it does not duplicate command
matrices or normative procedures.

The runbook specifies the explicit production sequence, safety boundaries, and
operator-only smoke modes. Use it before operating the management wrapper or
changing the Compose deployment. Runtime scripts and configuration remain the
implementation of that documented contract.
