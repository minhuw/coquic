#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import re
import subprocess
import sys
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class ReleaseSource:
    repo: str | None
    tag_pattern: str | None = None
    current_pattern: str = r"^v?(?P<version>\d+(?:\.\d+)+)$"
    local: bool = False


@dataclasses.dataclass(frozen=True)
class ReleaseTag:
    tag: str
    version: str
    key: tuple[int, ...]
    sha: str


class QueryError(ValueError):
    pass


RELEASE_SOURCES = {
    "coquic": ReleaseSource(repo=None, local=True),
    "quic-go": ReleaseSource(
        repo="https://github.com/quic-go/quic-go.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
    "quinn": ReleaseSource(
        repo="https://github.com/quinn-rs/quinn.git",
        tag_pattern=r"^quinn-(?P<version>\d+\.\d+\.\d+)$",
    ),
    "picoquic": ReleaseSource(repo="https://github.com/private-octopus/picoquic.git"),
    "msquic": ReleaseSource(
        repo="https://github.com/microsoft/msquic.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
    "quiche": ReleaseSource(
        repo="https://github.com/cloudflare/quiche.git",
        tag_pattern=r"^(?P<version>\d+\.\d+\.\d+)$",
    ),
    "quicly": ReleaseSource(repo="https://github.com/h2o/quicly.git"),
    "google-quiche": ReleaseSource(repo="https://github.com/google/quiche.git"),
    "tquic": ReleaseSource(
        repo="https://github.com/Tencent/tquic.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
    "mvfst": ReleaseSource(
        repo="https://github.com/facebook/mvfst.git",
        tag_pattern=r"^v(?P<version>\d{4}\.\d{2}\.\d{2}\.\d{2})$",
        current_pattern=r"^v?(?P<version>\d{4}\.\d{2}\.\d{2}\.\d{2})$",
    ),
    "s2n-quic": ReleaseSource(
        repo="https://github.com/aws/s2n-quic.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
    "xquic": ReleaseSource(
        repo="https://github.com/alibaba/xquic.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
    "aioquic": ReleaseSource(
        repo="https://github.com/aiortc/aioquic.git",
        tag_pattern=r"^v?(?P<version>\d+\.\d+\.\d+)$",
    ),
    "ngtcp2": ReleaseSource(
        repo="https://github.com/ngtcp2/ngtcp2.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
    "lsquic": ReleaseSource(
        repo="https://github.com/litespeedtech/lsquic.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
    "neqo": ReleaseSource(
        repo="https://github.com/mozilla/neqo.git",
        tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
    ),
}


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Check upstream releases for QUIC implementations measured by perf.yml",
    )
    parser.add_argument("--repo-root", type=Path, default=repo_root)
    parser.add_argument("--manifest", type=Path, default=repo_root / "bench/implementations.json")
    parser.add_argument("--workflow", type=Path, default=repo_root / ".github/workflows/perf.yml")
    parser.add_argument(
        "--implementation",
        action="append",
        dest="implementations",
        help="implementation label to check; repeatable (default: all labels from perf.yml)",
    )
    parser.add_argument("--git", default="git", help="git executable to use")
    parser.add_argument("--timeout", type=float, default=30.0, help="git query timeout in seconds")
    parser.add_argument("--json-out", type=Path, help="write machine-readable JSON results")
    parser.add_argument(
        "--no-fail-on-outdated",
        action="store_true",
        help="report outdated release pins but exit successfully",
    )
    parser.add_argument(
        "--fail-on-pinned-commits",
        action="store_true",
        help="fail when a release-backed implementation is pinned to a non-release commit",
    )
    parser.add_argument(
        "--fail-on-head-drift",
        action="store_true",
        help="fail when a commit-only implementation does not point at upstream HEAD",
    )
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def read_text(path: Path) -> str:
    try:
        return path.read_text()
    except OSError as exc:
        raise ValueError(f"failed to read `{path}`: {exc}") from exc


def load_manifest(path: Path) -> dict[str, str]:
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse `{path}` JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"`{path}` root must be an object")
    if data.get("schema_version") != 1:
        raise ValueError(f"`{path}` schema_version must be 1")
    implementations = data.get("implementations")
    if not isinstance(implementations, dict):
        raise ValueError(f"`{path}` field `implementations` must be an object")

    versions = {}
    for label, implementation in implementations.items():
        if not isinstance(label, str) or not label:
            raise ValueError(f"`{path}` implementation labels must be non-empty strings")
        if not isinstance(implementation, dict):
            raise ValueError(f"`{path}` implementation `{label}` must be an object")
        version = implementation.get("library_version")
        if not isinstance(version, str) or not version:
            raise ValueError(f"`{path}` implementation `{label}` must have a non-empty library_version")
        versions[label] = version
    return versions


def workflow_labels(path: Path) -> list[str]:
    labels = re.findall(r"^\s+- label: ([A-Za-z0-9_-]+)$", read_text(path), re.MULTILINE)
    if not labels:
        raise ValueError("perf workflow matrix labels were not found")
    duplicates = sorted({label for label in labels if labels.count(label) > 1})
    if duplicates:
        raise ValueError("perf workflow matrix has duplicate labels: " + ", ".join(duplicates))
    return labels


def run_git(git: str, args: list[str], timeout: float) -> str:
    try:
        completed = subprocess.run(
            [git, *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise QueryError(f"`{git} {' '.join(args)}` timed out after {timeout:g}s") from exc
    except OSError as exc:
        raise QueryError(f"failed to run `{git}`: {exc}") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise QueryError(f"`{git} {' '.join(args)}` failed: {detail}")
    return completed.stdout


def parse_version(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError as exc:
        raise ValueError(f"unsupported release version `{version}`") from exc


def parse_remote_tags(output: str) -> dict[str, str]:
    direct: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        sha, ref = fields
        prefix = "refs/tags/"
        if not ref.startswith(prefix):
            continue
        tag = ref[len(prefix) :]
        if tag.endswith("^{}"):
            peeled[tag[:-3]] = sha
        else:
            direct[tag] = sha
    return {tag: peeled.get(tag, sha) for tag, sha in direct.items()}


def matching_release_tags(source: ReleaseSource, remote_tags: dict[str, str]) -> list[ReleaseTag]:
    if source.tag_pattern is None:
        return []
    pattern = re.compile(source.tag_pattern)
    releases = []
    for tag, sha in remote_tags.items():
        match = pattern.match(tag)
        if match is None:
            continue
        version = match.group("version")
        releases.append(ReleaseTag(tag=tag, version=version, key=parse_version(version), sha=sha))
    return releases


def current_version(source: ReleaseSource, current: str) -> tuple[str, tuple[int, ...]] | None:
    match = re.match(source.current_pattern, current)
    if match is None:
        return None
    version = match.group("version")
    return version, parse_version(version)


def looks_like_sha(value: str) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]{7,40}", value) is not None


def sha_matches_prefix(sha: str, value: str) -> bool:
    return looks_like_sha(value) and sha.lower().startswith(value.lower())


def short_sha(sha: str | None) -> str:
    if sha is None:
        return ""
    return sha[:7] if looks_like_sha(sha[:7]) else sha


def repo_display(repo: str | None) -> str:
    if repo is None:
        return "local"
    return repo.removeprefix("https://").removesuffix(".git")


def fetch_head(git: str, source: ReleaseSource, timeout: float) -> str | None:
    if source.repo is None:
        return None
    output = run_git(git, ["ls-remote", source.repo, "HEAD"], timeout)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == "HEAD":
            return fields[0]
    raise QueryError(f"upstream HEAD was not found for {source.repo}")


def release_for_current_sha(releases: list[ReleaseTag], current: str) -> ReleaseTag | None:
    for release in releases:
        if sha_matches_prefix(release.sha, current):
            return release
    return None


def release_for_current_version(
    releases: list[ReleaseTag],
    version: tuple[str, tuple[int, ...]] | None,
) -> ReleaseTag | None:
    if version is None:
        return None
    _version_text, key = version
    for release in releases:
        if release.key == key:
            return release
    return None


def check_label(label: str, current: str, args: argparse.Namespace) -> dict[str, object]:
    source = RELEASE_SOURCES[label]
    row: dict[str, object] = {
        "label": label,
        "current": current,
        "source": repo_display(source.repo),
        "latest_release": None,
        "latest_release_version": None,
        "latest_release_sha": None,
        "latest_ref": None,
        "current_release": None,
        "status": None,
        "note": "",
    }

    if source.local:
        row["status"] = "local"
        row["note"] = "local implementation uses the checked-out CoQUIC commit"
        return row

    try:
        remote_tags = parse_remote_tags(run_git(args.git, ["ls-remote", "--tags", source.repo], args.timeout))
        releases = matching_release_tags(source, remote_tags)

        if releases:
            latest = max(releases, key=lambda release: release.key)
            row["latest_release"] = latest.tag
            row["latest_release_version"] = latest.version
            row["latest_release_sha"] = latest.sha

            current_release = release_for_current_version(releases, current_version(source, current))
            if current_release is None:
                current_release = release_for_current_sha(releases, current)

            if current_release is None:
                row["status"] = "pinned-commit"
                row["note"] = "current value is not a recognized upstream release tag"
                return row

            row["current_release"] = current_release.tag
            if current_release.key < latest.key:
                row["status"] = "outdated"
            elif current_release.key == latest.key:
                row["status"] = "current"
            else:
                row["status"] = "newer-than-latest"
            return row

        head = fetch_head(args.git, source, args.timeout)
        row["latest_ref"] = f"HEAD {short_sha(head)}"
        if head is not None and sha_matches_prefix(head, current):
            row["status"] = "head-current"
            row["note"] = "upstream has no matching release tags"
        else:
            row["status"] = "head-differs"
            row["note"] = "upstream has no matching release tags; comparing against HEAD only"
        return row
    except QueryError as exc:
        row["status"] = "error"
        row["note"] = str(exc)
        return row


def table_value(row: dict[str, object]) -> str:
    latest_release = row.get("latest_release")
    if latest_release:
        sha = row.get("latest_release_sha")
        if sha:
            return f"{latest_release} ({short_sha(str(sha))})"
        return str(latest_release)
    latest_ref = row.get("latest_ref")
    if latest_ref:
        return str(latest_ref)
    return "-"


def render_table(rows: list[dict[str, object]]) -> str:
    headers = ["implementation", "current", "latest release/ref", "status", "source"]
    table_rows = [
        [
            str(row["label"]),
            str(row["current"]),
            table_value(row),
            str(row["status"]),
            str(row["source"]),
        ]
        for row in rows
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in table_rows))
        for index in range(len(headers))
    ]
    lines = [
        "  ".join(headers[index].ljust(widths[index]) for index in range(len(headers))),
        "  ".join("-" * width for width in widths),
    ]
    for row in table_rows:
        lines.append("  ".join(row[index].ljust(widths[index]) for index in range(len(headers))))
    return "\n".join(lines)


def should_fail(row: dict[str, object], args: argparse.Namespace) -> bool:
    status = row.get("status")
    if status == "error":
        return True
    if status == "outdated" and not args.no_fail_on_outdated:
        return True
    if status == "pinned-commit" and args.fail_on_pinned_commits:
        return True
    if status == "head-differs" and args.fail_on_head_drift:
        return True
    return False


def summarize(rows: list[dict[str, object]]) -> dict[str, int]:
    statuses: dict[str, int] = {}
    for row in rows:
        status = str(row["status"])
        statuses[status] = statuses.get(status, 0) + 1
    return statuses


def main() -> int:
    args = parse_args()
    try:
        versions = load_manifest(args.manifest)
        labels = workflow_labels(args.workflow)

        missing_manifest = sorted(set(labels) - set(versions))
        if missing_manifest:
            raise ValueError("implementation metadata is missing labels: " + ", ".join(missing_manifest))

        missing_sources = sorted(set(labels) - set(RELEASE_SOURCES))
        if missing_sources:
            raise ValueError("release source mapping is missing labels: " + ", ".join(missing_sources))

        selected = labels
        if args.implementations:
            requested = set(args.implementations)
            unknown = sorted(requested - set(labels))
            if unknown:
                raise ValueError("requested implementations are not in perf workflow: " + ", ".join(unknown))
            selected = [label for label in labels if label in requested]

        rows = [check_label(label, versions[label], args) for label in selected]
        output = {
            "schema_version": 1,
            "workflow": str(args.workflow),
            "manifest": str(args.manifest),
            "rows": rows,
            "summary": summarize(rows),
        }
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")

        print(render_table(rows))
        notes = [row for row in rows if row.get("note")]
        if notes:
            print()
            for row in notes:
                print(f"{row['label']}: {row['note']}")

        failing = [row for row in rows if should_fail(row, args)]
        if failing:
            print()
            print("release check failed for: " + ", ".join(str(row["label"]) for row in failing))
            return 1

        return 0
    except ValueError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
