#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

package_attr=""

usage() {
  cat <<'EOF' >&2
Usage:
  musl_package_check.sh --package-attr ATTR
EOF
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --package-attr)
      package_attr="${2:-}"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [ -z "${package_attr}" ]; then
  echo "error: --package-attr is required" >&2
  usage
fi

nix --option eval-cache false build ".#${package_attr}" >/dev/null

binary="$(readlink -f "$(nix path-info ".#${package_attr}")/bin/coquic")"
file_output="$(file "${binary}")"
ldd_output="$(ldd "${binary}" 2>&1 || true)"

printf 'binary: %s\n' "${binary}"
printf 'file: %s\n' "${file_output}"
printf 'ldd: %s\n' "${ldd_output}"

case "${ldd_output}" in
  *"not a dynamic executable"* | *"statically linked"*)
    ;;
  *)
    echo "expected a static musl-linked binary" >&2
    exit 1
    ;;
esac

if ! grep -q "statically linked" <<<"${file_output}"; then
  echo "expected file output to report a statically linked binary" >&2
  exit 1
fi

expected_name="${package_attr#coquic-}"
if [[ "${binary}" != *"${expected_name}"* ]]; then
  echo "expected binary path to include package name fragment ${expected_name}, got: ${binary}" >&2
  exit 1
fi
