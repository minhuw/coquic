#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "$(id -u)" -ne 0 ]] || { echo 'run the canary as the configured non-root deployment owner' >&2; exit 64; }
docker info >/dev/null
mkdir -p "$root/.zig-cache"
tmp="$(mktemp -d "$root/.zig-cache/steward-production-canary.XXXXXX")"
name="steward-canary-$(basename "$tmp")"
images_to_remove=()
daemon_image=""
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  # Only this canary's unique deployment labels; never prune production objects.
  while IFS= read -r owned; do
    [[ -z "$owned" ]] || docker rm -f "$owned" >/dev/null 2>&1 || true
  done < <(docker ps -aq --filter "label=coquic.steward.deployment=$name")
  if [[ -n "$daemon_image" ]]; then
    # Cleanup only, after the unmodified production provisioning was exercised.
    docker run --rm --network none --entrypoint /bin/chmod \
      --mount "type=bind,src=$tmp,dst=/canary-cleanup" \
      "$daemon_image" -R a+rwX /canary-cleanup >/dev/null 2>&1 || true
  fi
  for image in "${images_to_remove[@]}"; do docker image rm "$image" >/dev/null 2>&1 || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT

for kind in daemon task validation; do
  archive="$(nix build --no-link --print-out-paths "$root#steward-$kind-image")"
  reference="$(tar -xOzf "$archive" manifest.json | python -c 'import json,sys; print(json.load(sys.stdin)[0]["RepoTags"][0])')"
  if ! docker image inspect "$reference" >/dev/null 2>&1; then images_to_remove+=("$reference"); fi
  docker load --input "$archive" >/dev/null
  identity="$(docker image inspect --format '{{.Id}}' "$reference")"
  case "$kind" in
    daemon) daemon_image="$identity" ;;
    task) task_image="$identity" ;;
    validation) validation_image="$identity" ;;
  esac
done
socket="${DOCKER_SOCKET:-/var/run/docker.sock}"
docker_gid="$(stat -c %g "$socket")"
mkdir -m 700 "$tmp/home"
# Same identity/capability/read-only-root boundary as Compose, but no service,
# live credentials, host repository, remote, or publication authority is supplied.
docker run --rm --name "$name" --init --network none --read-only \
  --user "$(id -u):$(id -g)" --group-add "$docker_gid" \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 512 --memory 4g \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777 \
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m \
  --env "COQUIC_HOME=$tmp/home" --env "CANARY_NAME=$name" \
  --env "STEWARD_UID=$(id -u)" --env "STEWARD_DOCKER_GID=$docker_gid" \
  --env "STEWARD_TASK_IMAGE=$task_image" --env "STEWARD_VALIDATION_IMAGE=$validation_image" \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --mount "type=bind,src=$tmp/home,dst=$tmp/home" \
  --mount "type=bind,src=$socket,dst=/var/run/docker.sock" \
  --mount "type=bind,src=$root/steward/containers/production-canary.py,dst=/canary.py,readonly" \
  --workdir "$tmp/home" --entrypoint /bin/bash "$daemon_image" -c '
    set -eu
    for source in /nix/store/*-coquic-steward-source-*/opt/coquic/steward/src; do
      [ -d "$source" ] || continue
      export PYTHONPATH="$source"
      exec /bin/python -B /canary.py
    done
    echo "packaged production source missing" >&2
    exit 1
  '
