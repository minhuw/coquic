#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
cd "${repo_root}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for h3_server_container_smoke_test.sh" >&2
  exit 1
fi

zig build -Dtls_backend=quictls -Dtarget=x86_64-linux-musl -Dspdlog_shared=false >/dev/null

image_tag="coquic-h3-server:smoke"
docker build -t "${image_tag}" -f docker/h3-server/Dockerfile .

entrypoint="$(docker image inspect "${image_tag}" --format '{{json .Config.Entrypoint}}')"
cmd="$(docker image inspect "${image_tag}" --format '{{json .Config.Cmd}}')"
bundled_page="$(
  docker run --rm --entrypoint /bin/sh "${image_tag}" -lc 'cat /app/www/index.html'
)"

if [[ "${entrypoint}" != *"/usr/local/bin/h3-server"* ]]; then
  echo "Entrypoint does not include /usr/local/bin/h3-server: ${entrypoint}" >&2
  exit 1
fi

if [[ "${cmd}" != *"/run/certs/cert.pem"* ]] || [[ "${cmd}" != *"/run/certs/key.pem"* ]]; then
  echo "Cmd does not include /run/certs/cert.pem and /run/certs/key.pem: ${cmd}" >&2
  exit 1
fi

if [[ "${bundled_page}" != *"<body>Hello HTTP/3</body>"* ]]; then
  echo "Bundled page did not contain expected body tag" >&2
  exit 1
fi

echo "h3-server container smoke passed"
