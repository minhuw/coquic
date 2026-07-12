#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/coquic-validation-index.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

export GIT_INDEX_FILE="${tmp_dir}/index"
git read-tree HEAD
git add -A --

"$@"
