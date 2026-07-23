#!/usr/bin/env bash
set -euo pipefail

# The trusted caller sends a four-byte length followed by the revocable key on
# stdin. It is consumed before Codex receives its prompt and never appears in
# argv, Docker config, labels, or the transcript stream.
read_api_key() {
  local header length
  header="$(dd if=/dev/stdin bs=1 count=4 status=none 2>/dev/null | python -c 'import sys; print(int.from_bytes(sys.stdin.buffer.read(), "big"))')"
  length="${header:-0}"
  if [[ ! "$length" =~ ^[0-9]+$ || "$length" -gt 4096 ]]; then
    echo "invalid invocation control header" >&2
    exit 64
  fi
  if (( length > 0 )); then
    IFS= read -r -N "$length" CODEX_API_KEY
  else
    CODEX_API_KEY=""
  fi
  export CODEX_API_KEY
}

case "${1:-run}" in
  run)
    shift
    read_api_key
    if [[ "$#" -eq 0 ]]; then
      echo "missing Codex argv" >&2
      exit 64
    fi
    exec "$@"
    ;;
  signal)
    # Signals are handled by the process supervisor, never by container PID 1.
    shift
    exec /bin/kill -"${COQUIC_STEWARD_SIGNAL:?}" "$@"
    ;;
  prepare)
    shift
    mkdir -p -- "$@"
    ;;
  *)
    echo "unknown task entrypoint operation" >&2
    exit 64
    ;;
esac
