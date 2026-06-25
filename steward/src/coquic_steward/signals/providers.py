from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import (
    HTTPDefaultErrorHandler,
    HTTPErrorProcessor,
    HTTPSHandler,
    OpenerDirector,
    Request,
)

from ..core.config import StewardConfig
from ..core.models import SignalItem
from ..core.subprocesses import run_command

SIGNAL_TIMEOUT_SECONDS = 15.0
DEFAULT_SIGNAL_WORK_ITEMS = 12
CODACY_API_HOST = "app.codacy.com"


@dataclass(frozen=True)
class ProviderSignalResult:
    items: list[SignalItem] = field(default_factory=list)
    summary: str = ""
    error: str | None = None
    has_more: bool = False


class SignalProvider(Protocol):
    name: str

    def collect(
        self, config: StewardConfig, *, max_items: int = DEFAULT_SIGNAL_WORK_ITEMS
    ) -> ProviderSignalResult:
        """Return current actionable signal items from one source."""


class GitHubActionsProvider:
    name = "github-actions"
    workflow_file: str | None = None
    signal_kind = "github-actions.workflow-failure"
    recommended_task_kind = "ci"
    recommended_worker = "ci-doctor"
    workflow_purpose = "Investigate the selected GitHub Actions workflow run."
    investigation_steps: tuple[str, ...] = (
        "Inspect the selected workflow run, failed jobs, failed steps, and log excerpts.",
        "Reproduce the closest failing command locally before changing code.",
        "Keep the fix scoped to the selected workflow run and its failure mode.",
    )
    local_validation: tuple[str, ...] = ()
    scope_limits: tuple[str, ...] = (
        "Do not rerun broad workflow lists to choose different work.",
        "Do not change GitHub workflow settings, secrets, or remote state.",
        "Commit and push remain Steward integration responsibilities.",
    )
    artifact_paths: tuple[str, ...] = ()

    def collect(
        self, config: StewardConfig, *, max_items: int = DEFAULT_SIGNAL_WORK_ITEMS
    ) -> ProviderSignalResult:
        command = [
            "gh",
            "run",
            "list",
            "-R",
            config.github_repository,
            "--branch",
            config.main_branch,
            "--limit",
            str(max_items),
            "--json",
            "databaseId,workflowName,conclusion",
        ]
        if self.workflow_file:
            command.extend(["--workflow", self.workflow_file, "--status", "failure"])
        runs = run_command(command, cwd=config.repo_root, timeout=SIGNAL_TIMEOUT_SECONDS)
        if not runs.ok:
            return ProviderSignalResult(error=runs.stderr, summary=runs.stderr)
        try:
            decoded = json.loads(runs.stdout)
        except json.JSONDecodeError:
            decoded = []
        items: list[SignalItem] = []
        for run in decoded:
            if run.get("conclusion") != "failure":
                continue
            workflow_name = str(run.get("workflowName") or "workflow")
            run_id = str(run.get("databaseId") or "")
            if not run_id:
                continue
            items.append(
                _workflow_item(
                    provider=self.name,
                    repository=config.github_repository,
                    workflow_name=workflow_name,
                    run_id=run_id,
                    kind=self._signal_kind(workflow_name),
                    workflow_file=self.workflow_file,
                    worker_context=self._worker_context(),
                )
            )
        if not items:
            return ProviderSignalResult(summary=f"No failed {self._label()} runs found")
        return ProviderSignalResult(
            items=items,
            summary=_summary_from_workflow_items(self._label(), items),
            has_more=len(decoded) > len(items),
        )

    def _signal_kind(self, workflow_name: str) -> str:
        return self.signal_kind

    def _label(self) -> str:
        return self.workflow_file or "GitHub Actions workflow"

    def _worker_context(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "workflow_file": self.workflow_file,
                "recommended_task_kind": self.recommended_task_kind,
                "recommended_worker": self.recommended_worker,
                "workflow_purpose": self.workflow_purpose,
                "investigation_steps": list(self.investigation_steps),
                "local_validation": list(self.local_validation),
                "scope_limits": list(self.scope_limits),
                "artifact_paths": list(self.artifact_paths),
            }
        )


class GitHubActionsCiProvider(GitHubActionsProvider):
    name = "github-actions:ci"
    workflow_file = "ci.yml"
    signal_kind = "github-actions.ci-failure"
    workflow_purpose = (
        "Per-commit CI covers formatting, clang-tidy diff lint, and RFC compliance "
        "checks for push and pull_request events."
    )
    investigation_steps = (
        "Use the selected run id to inspect the failed job and failed step logs.",
        "Map failures to the workflow jobs: Format, Lint, or RFC Compliance.",
        "Fix source, formatting, lint findings, or RFC annotations only for the reported failure.",
    )
    local_validation = (
        "nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure",
        "nix develop .#lint -c ./scripts/run-clang-tidy.sh --diff",
        "nix develop -c ./scripts/compliance --ci",
    )


class GitHubActionsTestProvider(GitHubActionsProvider):
    name = "github-actions:test"
    workflow_file = "test.yml"
    signal_kind = "github-actions.test-failure"
    workflow_purpose = "Build and unit-test CoQUIC on push, pull_request, and manual dispatch."
    investigation_steps = (
        "Inspect the selected run id for the Build or Test step that failed.",
        "Prefer a local reproduction with the same Zig/Nix command before editing.",
        "Fix implementation or test expectations for the selected failure only.",
    )
    local_validation = (
        "nix develop -c zig build",
        "nix develop -c zig build test",
    )


class GitHubActionsDuvetProvider(GitHubActionsProvider):
    name = "github-actions:duvet"
    workflow_file = "duvet.yml"
    signal_kind = "github-actions.duvet-failure"
    recommended_task_kind = "rfc-audit"
    recommended_worker = "rfc-auditor"
    workflow_purpose = (
        "Daily Duvet workflow generates RFC compliance reports and publishes the "
        "report artifacts for the demo site."
    )
    investigation_steps = (
        "Inspect the selected run id for compliance generation, artifact upload, or demo upload failure.",
        "Use grounded QUIC/RFC context when changing annotations or protocol behavior.",
        "Fix source annotations, compliance scripts, or report packaging for the selected failure.",
    )
    local_validation = ("nix develop -c ./scripts/compliance --ci",)
    scope_limits = (
        "Do not commit generated .duvet report output unless it is already tracked source.",
        "Do not use or expose deployment secrets.",
        "Do not change remote demo state manually.",
    )
    artifact_paths = (
        ".duvet/reports/report.html",
        ".duvet/reports/report.json",
        ".duvet/snapshot.txt",
    )


class GitHubActionsNightlyCiProvider(GitHubActionsProvider):
    name = "github-actions:nightly-ci"
    workflow_file = "nightly-ci.yml"
    signal_kind = "github-actions.nightly-ci-failure"
    workflow_purpose = (
        "Daily Nightly CI covers full clang-tidy lint, coverage, CodeQL analysis, "
        "and coverage publication."
    )
    investigation_steps = (
        "Inspect the selected run id and identify whether full-lint, coverage, CodeQL, or publishing failed.",
        "Treat generated coverage output and downloaded CI logs as local state, not source changes.",
        "Fix source, scripts, or workflow wiring only for the selected nightly failure.",
    )
    local_validation = (
        "nix develop .#lint -c ./scripts/run-clang-tidy.sh --full",
        "nix develop -c zig build coverage",
    )
    artifact_paths = (
        "coverage/lcov.info",
        "coverage/coverage-results.json",
        "coverage/html",
    )


class GitHubActionsDeployDemoProvider(GitHubActionsProvider):
    name = "github-actions:deploy-demo"
    workflow_file = "deploy-demo.yml"
    signal_kind = "github-actions.deploy-demo-failure"
    workflow_purpose = (
        "Deploy Demo builds the h3-server and Next.js demo, packages the demo app, "
        "and deploys it to the public demo host on main."
    )
    investigation_steps = (
        "Inspect the selected run id to separate build, package, SSH, and deploy-script failures.",
        "Reproduce local build/package steps when the failure does not require secrets.",
        "Fix site, build, packaging, or deployment scripts for the selected failure only.",
    )
    local_validation = (
        "nix develop .#quictls-musl -c zig build -Dtls_backend=quictls -Dtarget=x86_64-linux-musl -Dspdlog_shared=false",
        "cd site/next && npm install && npm run build:demo",
        "cd site/next && npm run package:demo -- /tmp/coquic-demo-app",
    )
    scope_limits = (
        "Do not read, print, or replace deployment secrets.",
        "Do not manually deploy to the public host from the worker.",
        "Do not change remote service state outside the repository patch.",
    )


class GitHubActionsInteropProvider(GitHubActionsProvider):
    name = "github-actions:interop"
    workflow_file = "interop.yml"
    signal_kind = "github-actions.interop-failure"
    recommended_task_kind = "interop"
    recommended_worker = "interop-doctor"
    workflow_purpose = (
        "Daily Interop runs CoQUIC against official QUIC interop peers and publishes "
        "per-peer result artifacts."
    )
    investigation_steps = (
        "Inspect the selected run id, failed matrix job, peer, direction, testcase, and log artifact.",
        "Download failed CI logs/artifacts under .remote-ci/ when needed.",
        "Reproduce with interop/run-official.sh for the same peer/testcase/direction before editing.",
    )
    local_validation = (
        "bash interop/run-official.sh",
        "nix develop -c zig build test",
    )
    scope_limits = (
        "Skip goodput and crosstraffic during daily local validation unless the selected failure requires them.",
        "Do not commit .remote-ci/ or .interop-logs/ output.",
        "Commit and push remain Steward integration responsibilities.",
    )
    artifact_paths = (
        ".interop-logs/official",
        ".interop-logs/interop-results-<peer>.json",
    )


class GitHubActionsPerfProvider(GitHubActionsProvider):
    name = "github-actions:perf"
    workflow_file = "perf.yml"
    signal_kind = "github-actions.perf-failure"
    workflow_purpose = (
        "Daily Perf checks benchmark configuration and runs performance matrices on "
        "the self-hosted coquic-perf runner."
    )
    investigation_steps = (
        "Inspect the selected run id to distinguish perf-config failures, runner infrastructure failures, and benchmark regressions.",
        "Use failed job logs before changing benchmark code or workflow cleanup steps.",
        "Fix benchmark scripts, implementation behavior, or workflow runner hygiene for the selected failure.",
    )
    local_validation = (
        "python3 scripts/check-bench-implementations.py",
        "nix develop -c zig build",
    )
    scope_limits = (
        "Do not manually delete remote runner state as part of the worker task.",
        "Do not commit benchmark result directories or generated profiling output.",
        "Commit and push remain Steward integration responsibilities.",
    )
    artifact_paths = (
        ".bench-results",
        "result",
        "coverage",
    )


class CodeScanningProvider:
    name = "code-scanning"

    def collect(
        self, config: StewardConfig, *, max_items: int = DEFAULT_SIGNAL_WORK_ITEMS
    ) -> ProviderSignalResult:
        codeql = run_command(
            [
                "gh",
                "api",
                "-X",
                "GET",
                f"repos/{config.github_repository}/code-scanning/alerts?state=open&per_page={max_items}",
            ],
            cwd=config.repo_root,
            timeout=SIGNAL_TIMEOUT_SECONDS,
        )
        if not codeql.ok:
            return ProviderSignalResult(error=codeql.stderr)
        try:
            payload = json.loads(codeql.stdout or "[]")
        except json.JSONDecodeError:
            payload = []
        items = [_code_scanning_item(item) for item in payload[:max_items]]
        return ProviderSignalResult(
            items=items,
            summary=_summary_from_items("CodeQL", items),
            has_more=len(payload) > len(items),
        )


class CodacyProvider:
    name = "codacy"

    def collect(
        self, config: StewardConfig, *, max_items: int = DEFAULT_SIGNAL_WORK_ITEMS
    ) -> ProviderSignalResult:
        owner, repository = config.github_repository.split("/", 1)
        issue_result = self._collect_issue_search(
            owner,
            repository,
            os.getenv("CODACY_API_TOKEN"),
            max_items=max_items,
        )
        if issue_result.error is None:
            return issue_result
        return self._collect_public_analysis(owner, repository, config, issue_result.error)

    def _collect_issue_search(
        self,
        owner: str,
        repository: str,
        token: str | None,
        *,
        max_items: int,
    ) -> ProviderSignalResult:
        url = (
            f"https://{CODACY_API_HOST}/api/v3/analysis/organizations/gh/"
            f"{quote(owner, safe='')}/repositories/{quote(repository, safe='')}"
            f"/issues/search?limit={max_items}"
        )
        headers = {"content-type": "application/json"}
        if token:
            headers["api-token"] = token
        request = Request(
            url,
            data=json.dumps({"levels": ["Error", "Warning"]}).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with _open_codacy_request(
                request, timeout=SIGNAL_TIMEOUT_SECONDS
            ) as response:
                payload = json.loads(
                    response.read().decode("utf-8", errors="replace") or "{}"
                )
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            return ProviderSignalResult(error=str(exc))
        data = payload.get("data", []) if isinstance(payload, dict) else []
        items = [_codacy_item(item) for item in data[:max_items]]
        return ProviderSignalResult(
            items=items,
            summary=_summary_from_items("Codacy", items),
            has_more=len(data) > len(items),
        )

    def _collect_public_analysis(
        self,
        owner: str,
        repository: str,
        config: StewardConfig,
        search_error: str,
    ) -> ProviderSignalResult:
        url = (
            f"https://{CODACY_API_HOST}/api/v3/analysis/organizations/gh/"
            f"{quote(owner, safe='')}/repositories/{quote(repository, safe='')}"
            f"?branch={quote(config.main_branch, safe='')}"
        )
        request = Request(url, method="GET")
        try:
            with _open_codacy_request(
                request, timeout=SIGNAL_TIMEOUT_SECONDS
            ) as response:
                payload = json.loads(
                    response.read().decode("utf-8", errors="replace") or "{}"
                )
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            return ProviderSignalResult(error=f"{search_error}; fallback: {exc}")
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        issues_count = data.get("issuesCount") if isinstance(data, dict) else None
        if not isinstance(issues_count, int):
            return ProviderSignalResult(
                error=f"{search_error}; fallback: Codacy response missing issuesCount"
            )
        summary = f"Codacy issuesCount={issues_count}"
        if issues_count <= 0:
            return ProviderSignalResult(summary=summary)
        item = _codacy_summary_item(owner, repository, issues_count)
        return ProviderSignalResult(items=[item], summary=summary, has_more=True)


def _open_codacy_request(request: Request, *, timeout: float):
    parsed = urlparse(request.full_url)
    if parsed.scheme != "https" or parsed.netloc != CODACY_API_HOST:
        raise URLError("refusing non-Codacy HTTPS request")
    return _codacy_opener().open(request, timeout=timeout)


def _codacy_opener() -> OpenerDirector:
    opener = OpenerDirector()
    opener.add_handler(HTTPSHandler())
    opener.add_handler(HTTPDefaultErrorHandler())
    opener.add_handler(HTTPErrorProcessor())
    return opener


def _workflow_item(
    *,
    provider: str,
    repository: str,
    workflow_name: str,
    run_id: str,
    kind: str,
    workflow_file: str | None = None,
    worker_context: dict[str, Any] | None = None,
) -> SignalItem:
    title = f"{workflow_name} workflow failed"
    summary = f"{workflow_name} run {run_id} failed"
    payload = {
        "run_id": run_id,
        "workflow_name": workflow_name,
        "conclusion": "failure",
    }
    if workflow_file:
        payload["workflow_file"] = workflow_file
    if worker_context:
        payload["worker_context"] = worker_context
    return _signal_item(
        provider=provider,
        kind=kind,
        title=title,
        summary=summary,
        severity="high",
        links=[
            {
                "label": "Open workflow run",
                "url": f"https://github.com/{repository}/actions/runs/{run_id}",
            }
        ],
        payload=payload,
    )


def _summary_from_workflow_items(label: str, items: list[SignalItem]) -> str:
    if not items:
        return f"No failed {label} runs found"
    runs = ", ".join(str(item.payload.get("run_id")) for item in items[:3])
    return f"{label} sampled {len(items)} failed run(s): {runs}"


def _code_scanning_item(item: object) -> SignalItem:
    data = item if isinstance(item, dict) else {}
    rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    location = data.get("most_recent_instance") if isinstance(data.get("most_recent_instance"), dict) else {}
    location = location.get("location") if isinstance(location.get("location"), dict) else {}
    region = location.get("region") if isinstance(location.get("region"), dict) else {}
    path = _str_or_none(location.get("path"))
    line = _int_or_none(region.get("start_line"))
    rule_id = _str_or_none(rule.get("id"))
    rule_name = _str_or_none(rule.get("name") or rule.get("description"))
    severity = _str_or_none(
        data.get("security_severity_level")
        or data.get("severity")
        or rule.get("severity")
    )
    payload = {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "state": data.get("state"),
    }
    return _signal_item(
        provider="code-scanning",
        kind="code-scanning.alert",
        title=_finding_title(rule_id or rule_name or "Code scanning alert", path, line),
        summary=_finding_summary("CodeQL", rule_id, rule_name),
        severity=severity,
        location=_location(path, line),
        links=_links("Open alert", data.get("html_url")),
        payload=payload,
    )


def _codacy_item(item: object) -> SignalItem:
    data = item if isinstance(item, dict) else {}
    pattern = data.get("patternInfo") if isinstance(data.get("patternInfo"), dict) else {}
    tool = data.get("toolInfo") if isinstance(data.get("toolInfo"), dict) else {}
    path = _str_or_none(data.get("filePath") or data.get("filename"))
    line = _int_or_none(data.get("lineNumber") or data.get("line"))
    rule_id = _str_or_none(pattern.get("id") or data.get("patternId"))
    rule_name = _str_or_none(pattern.get("title") or pattern.get("category"))
    severity = _str_or_none(pattern.get("level") or data.get("level"))
    tool_name = _str_or_none(tool.get("name"))
    payload = {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "tool": tool_name,
    }
    return _signal_item(
        provider="codacy",
        kind="codacy.issue",
        title=_finding_title(rule_id or rule_name or "Codacy issue", path, line),
        summary=_finding_summary("Codacy", rule_id, rule_name),
        severity=severity,
        location=_location(path, line),
        links=_links("Open Codacy", data.get("url") or data.get("htmlUrl")),
        payload=payload,
    )


def _codacy_summary_item(owner: str, repository: str, issues_count: int) -> SignalItem:
    return _signal_item(
        provider="codacy",
        kind="codacy.summary",
        title="Open Codacy findings",
        summary=f"Codacy issuesCount={issues_count}",
        severity=None,
        links=[
            {
                "label": "Open Codacy",
                "url": f"https://app.codacy.com/gh/{owner}/{repository}/issues/current",
            }
        ],
        payload={"issues_count": issues_count},
    )


def _signal_item(
    *,
    provider: str,
    kind: str,
    title: str,
    summary: str,
    severity: str | None = None,
    location: dict[str, Any] | None = None,
    links: list[dict[str, str]] | None = None,
    payload: dict[str, Any] | None = None,
) -> SignalItem:
    compact_payload = _compact_dict(payload or {})
    identity = _compact_dict(
        {
            "provider": provider,
            "kind": kind,
            "title": title,
            "severity": severity,
            "location": location,
            "links": links or [],
            "payload": compact_payload,
        }
    )
    digest = sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:12]
    provider_id = provider.replace(":", "-")
    return SignalItem(
        id=f"wi-{provider_id}-{kind.split('.')[-1]}-{digest}",
        provider=provider,
        kind=kind,
        fingerprint=json.dumps(identity, sort_keys=True, separators=(",", ":")),
        title=title,
        summary=summary,
        severity=severity,
        location=location,
        links=links or [],
        payload=compact_payload,
    )


def _summary_from_items(provider: str, items: list[SignalItem]) -> str:
    if not items:
        return f"{provider} reports no sampled open findings"
    files = Counter(
        str(item.location.get("path"))
        for item in items
        if item.location and item.location.get("path")
    )
    rules = Counter(
        str(item.payload.get("rule_id"))
        for item in items
        if item.payload.get("rule_id")
    )
    parts = [f"{provider} sampled {len(items)} open finding(s)"]
    if files:
        parts.append("top files: " + ", ".join(name for name, _ in files.most_common(3)))
    if rules:
        parts.append("top rules: " + ", ".join(name for name, _ in rules.most_common(3)))
    return "; ".join(parts)


def _finding_title(rule: str, path: str | None, line: int | None) -> str:
    if path and line is not None:
        return f"{rule} in {path}:{line}"
    if path:
        return f"{rule} in {path}"
    return rule


def _finding_summary(provider: str, rule_id: str | None, rule_name: str | None) -> str:
    if rule_id and rule_name:
        return f"{provider} reports {rule_id}: {rule_name}"
    if rule_id:
        return f"{provider} reports {rule_id}"
    if rule_name:
        return f"{provider} reports {rule_name}"
    return f"{provider} reports an open finding"


def _location(path: str | None, line: int | None) -> dict[str, Any] | None:
    if not path:
        return None
    result: dict[str, Any] = {"path": path}
    if line is not None:
        result["line"] = line
    return result


def _links(label: str, url: object) -> list[dict[str, str]]:
    value = _str_or_none(url)
    return [{"label": label, "url": value}] if value else []


def _compact_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if item not in (None, "", [], {})
    }


def _str_or_none(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def _int_or_none(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None
