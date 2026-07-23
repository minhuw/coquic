#!/usr/bin/env bash
set -euo pipefail

exec python -m coquic_steward.cli daemon "$@"
