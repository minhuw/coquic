#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

readelf_cmd=()
if command -v readelf >/dev/null 2>&1; then
  readelf_cmd=(readelf)
elif command -v nix >/dev/null 2>&1; then
  readelf_cmd=(nix shell --quiet nixpkgs#binutils -c readelf)
else
  echo "error: readelf is not available and nix is not installed" >&2
  exit 1
fi

nix build .#coquic-quictls >/dev/null
binary="$(readlink -f result/bin/coquic)"
if ! readelf_output="$("${readelf_cmd[@]}" -d "${binary}")"; then
  echo "error: failed to inspect ${binary} dynamic dependencies" >&2
  exit 1
fi
needed="$(grep NEEDED <<<"${readelf_output}" || true)"

if grep -Eq 'lib(ssl|crypto|fmt|spdlog)\.so' <<<"${needed}"; then
  echo "expected static TLS/fmt/spdlog linkage, got:" >&2
  echo "${needed}" >&2
  exit 1
fi

if ! nix develop -c bash -lc '
  tmpdir=$(mktemp -d)
  trap "rm -rf \"${tmpdir}\"" EXIT
  cd "${tmpdir}"
  openssl ecparam -name prime256v1 -genkey -out ca.key >/dev/null 2>&1
  openssl req -out cert.csr -new -key ca.key -nodes -subj "/O=coquic static package test/" >/dev/null 2>&1
'; then
  echo "expected nix develop openssl to generate a CSR without missing config files" >&2
  exit 1
fi
