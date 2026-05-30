#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="${repo_root}/scripts/check-perf-implementation-releases.py"
implementations_json="${repo_root}/bench/implementations.json"
workflow="${repo_root}/.github/workflows/perf.yml"
tmpdir="$(mktemp -d)"
output="${tmpdir}/release-check.txt"
json_output="${tmpdir}/release-check.json"
fake_git="${tmpdir}/git"
trap 'rm -rf "${tmpdir}"' EXIT

[ -x "${script}" ] || {
  echo "missing executable perf release checker: ${script}" >&2
  exit 1
}

cat > "${fake_git}" <<'FAKE_GIT'
#!/usr/bin/env bash
set -euo pipefail

if [ "$1" != "ls-remote" ]; then
  echo "unexpected git command: $*" >&2
  exit 1
fi

if [ "${2:-}" = "--tags" ]; then
  repo="${3:-}"
  case "${repo}" in
    https://github.com/quic-go/quic-go.git)
      printf '%s\trefs/tags/v0.59.1\n' 1111111111111111111111111111111111111111
      printf '%s\trefs/tags/v0.99.0\n' 9999999999999999999999999999999999999999
      ;;
    https://github.com/quinn-rs/quinn.git)
      printf '%s\trefs/tags/quinn-0.11.9\n' 2222222222222222222222222222222222222222
      printf '%s\trefs/tags/quinn-proto-0.99.0\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      ;;
    https://github.com/cloudflare/quiche.git)
      printf '%s\trefs/tags/0.29.1\n' 3333333333333333333333333333333333333333
      printf '%s\trefs/tags/tokio-quiche-99.0.0\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      ;;
    https://github.com/alibaba/xquic.git)
      printf '%s\trefs/tags/v1.9.3\n' e5f7fe9555f6dfb87581deddd24e86fb86dfe2de
      printf '%s\trefs/tags/v1.99.0\n' cccccccccccccccccccccccccccccccccccccccc
      ;;
    https://github.com/h2o/quicly.git)
      printf '%s\trefs/tags/not-a-release\n' dddddddddddddddddddddddddddddddddddddddd
      ;;
    *)
      echo "unexpected tag repo: ${repo}" >&2
      exit 1
      ;;
  esac
  exit 0
fi

repo="${2:-}"
ref="${3:-}"
if [ "${repo}" = "https://github.com/h2o/quicly.git" ] && [ "${ref}" = "HEAD" ]; then
  printf '%s\tHEAD\n' eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  exit 0
fi

echo "unexpected ls-remote args: $*" >&2
exit 1
FAKE_GIT
chmod +x "${fake_git}"

python3 "${script}" \
  --manifest "${implementations_json}" \
  --workflow "${workflow}" \
  --git "${fake_git}" \
  --implementation coquic \
  --implementation quic-go \
  --implementation quinn \
  --implementation quiche \
  --implementation xquic \
  --implementation quicly \
  --no-fail-on-outdated \
  --json-out "${json_output}" \
  >"${output}"

grep -F -- 'coquic' "${output}" >/dev/null || {
  echo 'release checker output missing CoQUIC row' >&2
  exit 1
}

grep -F -- 'quic-go' "${output}" | grep -F -- 'outdated' >/dev/null || {
  echo 'release checker did not report quic-go as outdated' >&2
  exit 1
}

grep -F -- 'quinn' "${output}" | grep -F -- 'current' >/dev/null || {
  echo 'release checker did not report quinn as current' >&2
  exit 1
}

grep -F -- 'quiche' "${output}" | grep -F -- 'current' >/dev/null || {
  echo 'release checker did not filter tokio-quiche tags' >&2
  exit 1
}

grep -F -- 'xquic' "${output}" | grep -F -- 'outdated' >/dev/null || {
  echo 'release checker did not match xquic commit pin to release tag' >&2
  exit 1
}

grep -F -- 'quicly' "${output}" | grep -F -- 'head-differs' >/dev/null || {
  echo 'release checker did not compare commit-only source against HEAD' >&2
  exit 1
}

if python3 "${script}" \
  --manifest "${implementations_json}" \
  --workflow "${workflow}" \
  --git "${fake_git}" \
  --implementation quic-go \
  >"${tmpdir}/fail-output.txt" 2>"${tmpdir}/fail-stderr.txt"; then
  echo 'release checker should fail on outdated release pins by default' >&2
  exit 1
fi

python3 - "${json_output}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
rows = {row["label"]: row for row in payload["rows"]}

if payload.get("schema_version") != 1:
    raise SystemExit("release checker JSON schema_version mismatch")
if rows["quic-go"]["latest_release"] != "v0.99.0":
    raise SystemExit("release checker JSON missing latest quic-go release")
if rows["quinn"]["latest_release"] != "quinn-0.11.9":
    raise SystemExit("release checker JSON missing package-specific quinn release")
if rows["quiche"]["latest_release"] != "0.29.1":
    raise SystemExit("release checker JSON did not filter package-specific quiche tags")
if rows["xquic"]["current_release"] != "v1.9.3":
    raise SystemExit("release checker JSON did not record xquic current release")
if rows["quicly"]["latest_ref"] != "HEAD eeeeeee":
    raise SystemExit("release checker JSON missing quicly HEAD comparison")
PY

echo 'perf release checker contract looks correct'
