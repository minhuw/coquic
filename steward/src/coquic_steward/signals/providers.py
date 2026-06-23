from __future__ import annotations

import json
import os
from collections import Counter
from hashlib import sha256
from typing import Protocol
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
from ..core.models import ProjectSignals
from ..core.subprocesses import run_command

SIGNAL_TIMEOUT_SECONDS = 15.0
MAX_SIGNAL_WORK_ITEMS = 12
CODACY_API_HOST = "app.codacy.com"


class SignalProvider(Protocol):
    name: str

    def collect(self, config: StewardConfig, signals: ProjectSignals) -> None:
        """Mutate signals with observations from one source."""


class GitHubActionsProvider:
    name = "github-actions"

    def collect(self, config: StewardConfig, signals: ProjectSignals) -> None:
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
                "10",
                "--json",
                "databaseId,workflowName,conclusion",
            ],
            cwd=config.repo_root,
            timeout=SIGNAL_TIMEOUT_SECONDS,
        )
        signals.summary = runs.stdout if runs.ok else runs.stderr
        if not runs.ok:
            signals.signal_errors[self.name] = runs.stderr
            return
        try:
            decoded = json.loads(runs.stdout)
        except json.JSONDecodeError:
            decoded = []
        for run in decoded:
            if run.get("conclusion") == "failure":
                signals.failed_workflow_run_id = str(run.get("databaseId"))
                signals.failed_workflow_name = str(run.get("workflowName"))
                signals.summary = (
                    f"{signals.failed_workflow_name} run "
                    f"{signals.failed_workflow_run_id} failed"
                )
                if signals.failed_workflow_name == "Interop":
                    signals.failed_interop_run_id = signals.failed_workflow_run_id
                return


class CodeScanningProvider:
    name = "code-scanning"

    def collect(self, config: StewardConfig, signals: ProjectSignals) -> None:
        codeql = run_command(
            [
                "gh",
                "api",
                "-X",
                "GET",
                f"repos/{config.github_repository}/code-scanning/alerts?state=open&per_page={MAX_SIGNAL_WORK_ITEMS}",
            ],
            cwd=config.repo_root,
            timeout=SIGNAL_TIMEOUT_SECONDS,
        )
        if not codeql.ok:
            signals.signal_errors[self.name] = codeql.stderr
            return
        try:
            payload = json.loads(codeql.stdout or "[]")
        except json.JSONDecodeError:
            payload = []
        signals.has_codeql_findings = bool(payload)
        signals.has_code_quality_findings = (
            signals.has_code_quality_findings or signals.has_codeql_findings
        )
        if payload:
            items = [_code_scanning_item(item) for item in payload[:MAX_SIGNAL_WORK_ITEMS]]
            signals.summary = _summary_from_items("CodeQL", items)
            signals.signal_errors.pop(self.name, None)
            signals.work_items = items


class CodacyProvider:
    name = "codacy"

    def collect(self, config: StewardConfig, signals: ProjectSignals) -> None:
        owner, repository = config.github_repository.split("/", 1)
        token = os.getenv("CODACY_API_TOKEN")
        if token:
            self._collect_issue_search(owner, repository, signals, token)
        else:
            self._collect_public_analysis(owner, repository, config, signals)

    def _collect_issue_search(
        self,
        owner: str,
        repository: str,
        signals: ProjectSignals,
        token: str,
    ) -> None:
        url = (
            f"https://{CODACY_API_HOST}/api/v3/analysis/organizations/gh/"
            f"{quote(owner, safe='')}/repositories/{quote(repository, safe='')}/issues/search"
        )
        request = Request(
            url,
            data=json.dumps({"levels": ["Error", "Warning"]}).encode("utf-8"),
            headers={
                "api-token": token,
                "content-type": "application/json",
            },
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
            signals.signal_errors[self.name] = str(exc)
            return
        data = payload.get("data", []) if isinstance(payload, dict) else []
        signals.has_codacy_findings = bool(data)
        signals.has_code_quality_findings = (
            signals.has_code_quality_findings or signals.has_codacy_findings
        )
        if data:
            items = [_codacy_item(item) for item in data[:MAX_SIGNAL_WORK_ITEMS]]
            signals.summary = _summary_from_items("Codacy", items)
            signals.work_items = items

    def _collect_public_analysis(
        self,
        owner: str,
        repository: str,
        config: StewardConfig,
        signals: ProjectSignals,
    ) -> None:
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
            signals.signal_errors[self.name] = str(exc)
            return
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        issues_count = data.get("issuesCount") if isinstance(data, dict) else None
        if not isinstance(issues_count, int):
            signals.signal_errors[self.name] = "Codacy response missing issuesCount"
            return
        signals.has_codacy_findings = issues_count > 0
        signals.has_code_quality_findings = (
            signals.has_code_quality_findings or signals.has_codacy_findings
        )
        signals.summary = (
            f"{signals.summary}\n" if signals.summary else ""
        ) + f"Codacy issuesCount={issues_count}"
        signals.work_items = [
            _with_item_id(
                {
                    "provider": "codacy",
                    "kind": "codacy-summary",
                    "summary": f"Codacy issuesCount={issues_count}",
                    "url": f"https://app.codacy.com/gh/{owner}/{repository}/issues/current",
                }
            )
        ]


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


def _code_scanning_item(item: object) -> dict[str, object]:
    data = item if isinstance(item, dict) else {}
    rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    location = data.get("most_recent_instance") if isinstance(data.get("most_recent_instance"), dict) else {}
    location = location.get("location") if isinstance(location.get("location"), dict) else {}
    region = location.get("region") if isinstance(location.get("region"), dict) else {}
    path = location.get("path")
    return _with_item_id(
        {
            "provider": "code-scanning",
            "kind": "codeql-alert",
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name") or rule.get("description"),
            "severity": data.get("security_severity_level")
            or data.get("severity")
            or rule.get("severity"),
            "file": path,
            "line": region.get("start_line"),
            "url": data.get("html_url"),
            "state": data.get("state"),
        }
    )


def _codacy_item(item: object) -> dict[str, object]:
    data = item if isinstance(item, dict) else {}
    pattern = data.get("patternInfo") if isinstance(data.get("patternInfo"), dict) else {}
    tool = data.get("toolInfo") if isinstance(data.get("toolInfo"), dict) else {}
    return _with_item_id(
        {
            "provider": "codacy",
            "kind": "codacy-issue",
            "rule_id": pattern.get("id") or data.get("patternId"),
            "rule_name": pattern.get("title") or pattern.get("category"),
            "severity": pattern.get("level") or data.get("level"),
            "tool": tool.get("name"),
            "file": data.get("filePath") or data.get("filename"),
            "line": data.get("lineNumber") or data.get("line"),
            "url": data.get("url") or data.get("htmlUrl"),
        }
    )


def _compact_item(item: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in item.items()
        if value not in (None, "", [], {})
    }


def _with_item_id(item: dict[str, object]) -> dict[str, object]:
    compact = _compact_item(item)
    identity = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    provider = str(compact.get("provider") or "signal")
    kind = str(compact.get("kind") or "item")
    compact["id"] = f"wi-{provider}-{kind}-{sha256(identity.encode('utf-8')).hexdigest()[:12]}"
    return compact


def _summary_from_items(provider: str, items: list[dict[str, object]]) -> str:
    if not items:
        return f"{provider} reports open findings"
    files = Counter(str(item.get("file")) for item in items if item.get("file"))
    rules = Counter(str(item.get("rule_id")) for item in items if item.get("rule_id"))
    parts = [f"{provider} sampled {len(items)} open finding(s)"]
    if files:
        parts.append("top files: " + ", ".join(name for name, _ in files.most_common(3)))
    if rules:
        parts.append("top rules: " + ", ".join(name for name, _ in rules.most_common(3)))
    return "; ".join(parts)
