#!/usr/bin/env bash
set -euo pipefail

exec coquic-steward daemon "$@"
