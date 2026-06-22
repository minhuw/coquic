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

    def collect(
        self, config: StewardConfig, *, max_items: int = DEFAULT_SIGNAL_WORK_ITEMS
    ) -> ProviderSignalResult:
        runs = run_command(
            [
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
            ],
            cwd=config.repo_root,
            timeout=SIGNAL_TIMEOUT_SECONDS,
        )
        if not runs.ok:
            return ProviderSignalResult(error=runs.stderr, summary=runs.stderr)
        try:
            decoded = json.loads(runs.stdout)
        except json.JSONDecodeError:
            decoded = []
        for run in decoded:
            if run.get("conclusion") != "failure":
                continue
            workflow_name = str(run.get("workflowName") or "workflow")
            run_id = str(run.get("databaseId") or "")
            if not run_id:
                continue
            item = _workflow_item(
                repository=config.github_repository,
                workflow_name=workflow_name,
                run_id=run_id,
                is_interop=workflow_name == "Interop",
            )
            return ProviderSignalResult(
                items=[item],
                summary=item.summary,
                has_more=False,
            )
        return ProviderSignalResult(summary="No failed workflow runs found")


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
    repository: str,
    workflow_name: str,
    run_id: str,
    is_interop: bool,
) -> SignalItem:
    kind = "github-actions.interop-failure" if is_interop else "github-actions.workflow-failure"
    title = f"{workflow_name} workflow failed"
    summary = f"{workflow_name} run {run_id} failed"
    payload = {
        "run_id": run_id,
        "workflow_name": workflow_name,
        "conclusion": "failure",
    }
    return _signal_item(
        provider="github-actions",
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
    return SignalItem(
        id=f"wi-{provider}-{kind.split('.')[-1]}-{digest}",
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
