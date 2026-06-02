#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=repo_root)
    parser.add_argument("--manifest", type=Path, default=repo_root / "bench/implementations.json")
    parser.add_argument("--workflow", type=Path, default=repo_root / ".github/workflows/perf.yml")
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def read_text(path: Path) -> str:
    try:
        return path.read_text()
    except OSError as exc:
        raise ValueError(f"failed to read `{path}`: {exc}") from exc


def load_manifest(path: Path) -> dict:
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
    for label, implementation in implementations.items():
        if not isinstance(label, str) or not label:
            raise ValueError(f"`{path}` implementation labels must be non-empty strings")
        if not isinstance(implementation, dict):
            raise ValueError(f"`{path}` implementation `{label}` must be an object")
        version = implementation.get("library_version")
        if not isinstance(version, str) or not version:
            raise ValueError(f"`{path}` implementation `{label}` must have a non-empty library_version")
    return data


def workflow_labels(workflow: Path) -> set[str]:
    content = read_text(workflow)
    if re.search(r"^\s+library_version:", content, re.MULTILINE):
        raise ValueError("perf workflow duplicates implementation versions; use bench/implementations.json")
    labels = set(re.findall(r"^\s+- label: ([A-Za-z0-9_-]+)$", content, re.MULTILINE))
    if not labels:
        raise ValueError("perf workflow matrix labels were not found")
    return labels


def cargo_lock_package_version(path: Path, package_name: str) -> str:
    current: dict[str, str] = {}
    for line in read_text(path).splitlines():
        if line.strip() == "[[package]]":
            if current.get("name") == package_name and "version" in current:
                return current["version"]
            current = {}
            continue
        match = re.match(r'\s*(name|version)\s*=\s*"([^"]+)"\s*$', line)
        if match:
            current[match.group(1)] = match.group(2)
    if current.get("name") == package_name and "version" in current:
        return current["version"]
    raise ValueError(f"package `{package_name}` was not found in `{path}`")


def go_mod_module_version(path: Path, module: str) -> str:
    pattern = re.compile(rf"^\s*require\s+{re.escape(module)}\s+(\S+)\s*$", re.MULTILINE)
    match = pattern.search(read_text(path))
    if not match:
        raise ValueError(f"module `{module}` was not found in `{path}`")
    return match.group(1)


def nix_binding_body(flake: Path, binding: str) -> str:
    pattern = re.compile(
        rf"{re.escape(binding)}\s*=\s*pkgs\.fetchFromGitHub\s*\{{(?P<body>.*?)\n\s*\}};",
        re.DOTALL,
    )
    match = pattern.search(read_text(flake))
    if not match:
        raise ValueError(f"Nix fetchFromGitHub binding `{binding}` was not found in `{flake}`")
    return match.group("body")


def nix_binding_value(body: str, field: str, binding: str) -> str:
    match = re.search(rf'\b{re.escape(field)}\s*=\s*"([^"]+)";', body)
    if not match:
        raise ValueError(f"Nix binding `{binding}` is missing `{field}`")
    return match.group(1)


def nix_fetch_rev(flake: Path, binding: str) -> str:
    return nix_binding_value(nix_binding_body(flake, binding), "rev", binding)


def msquic_version(flake: Path) -> str:
    content = read_text(flake)
    match = re.search(
        r"libmsquicForMsquicPerf\s*=\s*pkgs\.libmsquic\.overrideAttrs\s*\(.*?"
        r'version\s*=\s*"([^"]+)";.*?'
        r"msquicPerfClient\s*=",
        content,
        re.DOTALL,
    )
    if not match:
        raise ValueError("Nix libmsquicForMsquicPerf version was not found")
    return match.group(1)


def facebook_quic_version(flake: Path) -> str:
    content = read_text(flake)
    match = re.search(r'facebookQuicVersion\s*=\s*"([^"]+)";', content)
    if not match:
        raise ValueError("Nix facebookQuicVersion was not found")
    return match.group(1)


def require_exact(versions: dict[str, str], label: str, expected: str) -> None:
    actual = versions[label]
    if actual != expected:
        raise ValueError(f"`{label}` library_version is `{actual}`, expected `{expected}`")


def require_semver(versions: dict[str, str], label: str, bare_version: str) -> None:
    require_exact(versions, label, f"v{bare_version}")


def require_revision_prefix(versions: dict[str, str], label: str, full_rev: str) -> None:
    actual = versions[label]
    if len(actual) < 7 or not full_rev.startswith(actual):
        raise ValueError(f"`{label}` library_version `{actual}` is not a prefix of pinned rev `{full_rev}`")


def require_marker(path: Path, marker: str, label: str) -> None:
    if marker not in read_text(path):
        raise ValueError(f"`{label}` implementation metadata points at an untracked Nixpkgs package marker: {marker}")


def validate_c_json_output_modes(repo_root: Path) -> None:
    for path in sorted((repo_root / "bench").glob("*-perf/*-perf.c")):
        content = read_text(path)
        if "open_json_output" not in content:
            continue
        match = re.search(r"static\s+FILE\s+\*open_json_output\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}", content, re.DOTALL)
        if not match:
            raise ValueError(f"`{path.relative_to(repo_root)}` open_json_output helper was not found")
        body = match.group("body")
        if "O_CREAT" not in body:
            continue
        missing = [flag for flag in ("S_IRGRP", "S_IROTH") if flag not in body]
        if missing:
            raise ValueError(
                f"`{path.relative_to(repo_root)}` open_json_output creates Docker-mounted JSON without "
                f"group/other read bits: {', '.join(missing)}"
            )


def validate(args: argparse.Namespace) -> None:
    repo_root = args.repo_root.resolve()
    data = load_manifest(args.manifest)
    versions = {
        label: implementation["library_version"]
        for label, implementation in data["implementations"].items()
    }

    labels = workflow_labels(args.workflow)
    manifest_labels = set(versions)
    if manifest_labels != labels:
        missing = sorted(labels - manifest_labels)
        extra = sorted(manifest_labels - labels)
        details = []
        if missing:
            details.append(f"missing labels: {', '.join(missing)}")
        if extra:
            details.append(f"extra labels: {', '.join(extra)}")
        raise ValueError("implementation metadata labels do not match perf workflow matrix (" + "; ".join(details) + ")")

    flake = repo_root / "flake.nix"

    require_exact(versions, "coquic", "${GITHUB_SHA}")
    require_exact(versions, "quic-go", go_mod_module_version(repo_root / "bench/quicgo-perf/go.mod", "github.com/quic-go/quic-go"))
    require_semver(versions, "quinn", cargo_lock_package_version(repo_root / "bench/quinn-perf/Cargo.lock", "quinn"))
    require_semver(versions, "quiche", cargo_lock_package_version(repo_root / "bench/quiche-perf/Cargo.lock", "quiche"))
    require_semver(versions, "s2n-quic", cargo_lock_package_version(repo_root / "bench/s2n-quic-perf/Cargo.lock", "s2n-quic"))
    require_semver(versions, "neqo", cargo_lock_package_version(repo_root / "bench/neqo-perf/Cargo.lock", "neqo-bin"))
    require_semver(versions, "msquic", msquic_version(flake))
    require_exact(versions, "mvfst", facebook_quic_version(flake))

    for label, binding in {
        "picoquic": "picoquicSrc",
        "quicly": "quiclySrc",
        "google-quiche": "googleQuicheSrc",
        "tquic": "tquicSrc",
        "xquic": "xquicSrc",
    }.items():
        require_revision_prefix(versions, label, nix_fetch_rev(flake, binding))

    for label, binding in {
        "lsquic": "lsquicSrc",
        "neqo": "neqoSrc",
    }.items():
        require_exact(versions, label, nix_fetch_rev(flake, binding))

    for label, marker in {
        "aioquic": "ps.aioquic",
        "ngtcp2": "version = pkgs.ngtcp2.version;",
    }.items():
        require_marker(flake, marker, label)

    validate_c_json_output_modes(repo_root)


def main() -> int:
    args = parse_args()
    try:
        validate(args)
        return 0
    except ValueError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
