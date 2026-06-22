from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from hashlib import sha256

from ..core.config import StewardConfig
from ..core.models import ProjectSignals, SignalItem, SignalMessage, utc_now
from .providers import (
    CodacyProvider,
    CodeScanningProvider,
    GitHubActionsProvider,
    SignalProvider,
)

PROVIDER_TYPES: dict[str, type[SignalProvider]] = {
    GitHubActionsProvider.name: GitHubActionsProvider,
    CodeScanningProvider.name: CodeScanningProvider,
    CodacyProvider.name: CodacyProvider,
}


@dataclass(frozen=True)
class SignalCollection:
    provider: str
    signals: ProjectSignals
    messages: list[SignalMessage]
    items: list[SignalItem]
    started_at: datetime
    completed_at: datetime
    error: str | None = None


def signal_providers(names: tuple[str, ...]) -> list[SignalProvider]:
    providers: list[SignalProvider] = []
    for name in names:
        provider_type = PROVIDER_TYPES.get(name)
        if provider_type is None:
            choices = ", ".join(sorted(PROVIDER_TYPES))
            raise ValueError(
                f"unknown signal provider {name!r}; expected one of: {choices}"
            )
        providers.append(provider_type())
    return providers


def gather_signals(
    config: StewardConfig,
    providers: list[SignalProvider] | None = None,
) -> ProjectSignals:
    signals = ProjectSignals(github_repository=config.github_repository)
    selected = (
        providers if providers is not None else signal_providers(config.enabled_signals)
    )
    signals.enabled_signals = [provider.name for provider in selected]
    for provider in selected:
        provider.collect(config, signals)
    return signals


def collect_signal_messages(
    config: StewardConfig,
    providers: list[SignalProvider] | None = None,
) -> list[SignalCollection]:
    selected = (
        providers if providers is not None else signal_providers(config.enabled_signals)
    )
    collections: list[SignalCollection] = []
    for provider in selected:
        started_at = utc_now()
        signals = ProjectSignals(
            github_repository=config.github_repository,
            enabled_signals=[provider.name],
        )
        try:
            provider.collect(config, signals)
        except Exception as exc:  # pragma: no cover - provider boundary guard.
            signals.signal_errors[provider.name] = str(exc)
        completed_at = utc_now()
        messages = _messages_from_signals(provider.name, signals)
        items = _items_from_messages(messages)
        collections.append(
            SignalCollection(
                provider=provider.name,
                signals=signals,
                messages=messages,
                items=items,
                started_at=started_at,
                completed_at=completed_at,
                error=signals.signal_errors.get(provider.name),
            )
        )
    return collections


def signal_items_from_messages(messages: list[SignalMessage]) -> list[SignalItem]:
    return _items_from_messages(messages)


def project_signals_from_messages(
    config: StewardConfig, messages: list[SignalMessage]
) -> ProjectSignals:
    actionable_messages = [
        message for message in messages if message.kind != "signal-error"
    ]
    signals = ProjectSignals(
        github_repository=config.github_repository,
        enabled_signals=list(config.enabled_signals),
        inbox_messages=actionable_messages,
    )
    summaries: list[str] = []
    work_items: list[dict[str, object]] = []
    for message in actionable_messages:
        if message.summary:
            summaries.append(f"{message.provider}: {message.summary}")
        work_items.extend(_message_work_items(message))
        if message.kind == "codeql-open":
            signals.has_codeql_findings = True
            signals.has_code_quality_findings = True
        elif message.kind == "codacy-open":
            signals.has_codacy_findings = True
            signals.has_code_quality_findings = True
        elif message.kind == "interop-failure":
            run_id = _payload_str(message, "run_id")
            signals.failed_interop_run_id = run_id
            signals.failed_workflow_run_id = run_id
            signals.failed_workflow_name = _payload_str(message, "workflow_name")
        elif message.kind == "workflow-failure":
            signals.failed_workflow_run_id = _payload_str(message, "run_id")
            signals.failed_workflow_name = _payload_str(message, "workflow_name")
    signals.summary = "\n".join(summaries)
    signals.work_items = work_items
    return signals


def project_signals_from_items(
    config: StewardConfig, items: list[SignalItem]
) -> ProjectSignals:
    signals = ProjectSignals(
        github_repository=config.github_repository,
        enabled_signals=list(config.enabled_signals),
        inbox_items=items,
    )
    summaries: list[str] = []
    inbox_messages: list[SignalMessage] = []
    work_items: list[dict[str, object]] = []
    for item in items:
        if item.summary:
            summaries.append(f"{item.provider}: {item.summary}")
        work_item = dict(item.payload)
        if not isinstance(work_item.get("id"), str):
            work_item["id"] = item.id
        work_items.append(work_item)
        inbox_messages.append(_message_from_item(item, work_item))
        if item.kind == "codeql-alert" or item.provider == "code-scanning":
            signals.has_codeql_findings = True
            signals.has_code_quality_findings = True
        elif item.kind.startswith("codacy-") or item.provider == "codacy":
            signals.has_codacy_findings = True
            signals.has_code_quality_findings = True
        elif item.kind == "interop-failure":
            run_id = _item_payload_str(item, "run_id")
            signals.failed_interop_run_id = run_id
            signals.failed_workflow_run_id = run_id
            signals.failed_workflow_name = _item_payload_str(item, "workflow_name")
        elif item.kind == "workflow-failure":
            signals.failed_workflow_run_id = _item_payload_str(item, "run_id")
            signals.failed_workflow_name = _item_payload_str(item, "workflow_name")
    signals.summary = "\n".join(summaries)
    signals.inbox_messages = inbox_messages
    signals.work_items = work_items
    return signals


def _messages_from_signals(provider: str, signals: ProjectSignals) -> list[SignalMessage]:
    messages: list[SignalMessage] = []
    base_payload = signals.model_dump(mode="json", exclude={"inbox_messages"})
    if provider == GitHubActionsProvider.name and signals.failed_workflow_run_id:
        workflow_name = signals.failed_workflow_name or "workflow"
        run_id = signals.failed_workflow_run_id
        is_interop = signals.failed_interop_run_id == run_id
        kind = "interop-failure" if is_interop else "workflow-failure"
        evidence_id = f"interop:{run_id}" if is_interop else f"workflow:{run_id}"
        messages.append(
            SignalMessage(
                provider=provider,
                kind=kind,
                fingerprint=evidence_id,
                title=f"{workflow_name} failed",
                summary=f"{workflow_name} run {run_id} failed",
                evidence_id=evidence_id,
                payload=base_payload | {
                    "run_id": run_id,
                    "workflow_name": workflow_name,
                    "work_items": [
                        {
                            "provider": provider,
                            "kind": kind,
                            "run_id": run_id,
                            "workflow_name": workflow_name,
                            "summary": f"{workflow_name} run {run_id} failed",
                        }
                    ],
                },
            )
        )
    if provider == CodeScanningProvider.name and signals.has_codeql_findings:
        messages.append(
            SignalMessage(
                provider=provider,
                kind="codeql-open",
                fingerprint="codeql:open",
                title="Open CodeQL findings",
                summary="GitHub code scanning reports open CodeQL alerts",
                evidence_id="codeql:open",
                payload=base_payload
                | {"work_items": _payload_work_items(signals)},
            )
        )
    if provider == CodacyProvider.name and signals.has_codacy_findings:
        summary = signals.summary or "Codacy reports open findings"
        messages.append(
            SignalMessage(
                provider=provider,
                kind="codacy-open",
                fingerprint=f"codacy:open:{summary}",
                title="Open Codacy findings",
                summary=summary,
                evidence_id="codacy:open",
                payload=base_payload
                | {"work_items": _payload_work_items(signals)},
            )
        )
    return messages


def _items_from_messages(messages: list[SignalMessage]) -> list[SignalItem]:
    items: list[SignalItem] = []
    for message in messages:
        for work_item in _message_work_items(message):
            item_id = str(work_item.get("id") or "")
            if not item_id:
                continue
            provider = str(work_item.get("provider") or message.provider)
            kind = str(work_item.get("kind") or message.kind)
            items.append(
                SignalItem(
                    id=item_id,
                    provider=provider,
                    kind=kind,
                    fingerprint=item_id,
                    title=_item_title(message, work_item),
                    summary=str(work_item.get("summary") or message.summary),
                    evidence_id=message.evidence_id,
                    payload=work_item,
                    source_fetch_id=message.source_fetch_id,
                    source_message_id=message.id,
                )
            )
    return items


def _message_from_item(item: SignalItem, work_item: dict[str, object]) -> SignalMessage:
    return SignalMessage(
        id=item.id,
        provider=item.provider,
        kind=_message_kind_for_item(item),
        fingerprint=item.fingerprint,
        title=item.title,
        summary=item.summary,
        evidence_id=item.evidence_id,
        payload={
            "work_items": [work_item],
            "source_message_id": item.source_message_id,
            "source_fetch_id": item.source_fetch_id,
        },
        status=item.status,
        created_at=item.created_at,
        updated_at=item.updated_at,
        consumed_at=item.planned_at,
        planner_run_id=item.planner_run_id,
        source_fetch_id=item.source_fetch_id,
    )


def _payload_work_items(signals: ProjectSignals) -> list[dict[str, object]]:
    return [_with_work_item_id(item) for item in signals.work_items if isinstance(item, dict)]


def _payload_str(message: SignalMessage, key: str) -> str | None:
    value = message.payload.get(key)
    return str(value) if value is not None else None


def _message_work_items(message: SignalMessage) -> list[dict[str, object]]:
    values = message.payload.get("work_items")
    if not isinstance(values, list):
        return []
    return [_with_work_item_id(item) for item in values if isinstance(item, dict)]


def _item_payload_str(item: SignalItem, key: str) -> str | None:
    value = item.payload.get(key)
    return str(value) if value is not None else None


def _message_kind_for_item(item: SignalItem) -> str:
    if item.kind == "codeql-alert":
        return "codeql-open"
    if item.kind.startswith("codacy-"):
        return "codacy-open"
    return item.kind


def _item_title(message: SignalMessage, item: dict[str, object]) -> str:
    rule = item.get("rule_id") or item.get("rule_name")
    path = item.get("file")
    line = item.get("line")
    if rule and path and line:
        return f"{rule} in {path}:{line}"
    if rule and path:
        return f"{rule} in {path}"
    if path:
        return str(path)
    if item.get("summary"):
        return str(item["summary"])
    return message.title


def _with_work_item_id(item: dict[str, object]) -> dict[str, object]:
    if isinstance(item.get("id"), str) and item["id"]:
        return item
    compact = {
        key: value
        for key, value in item.items()
        if value not in (None, "", [], {})
    }
    identity = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    provider = str(compact.get("provider") or "signal")
    kind = str(compact.get("kind") or "item")
    return {
        "id": f"wi-{provider}-{kind}-{sha256(identity.encode('utf-8')).hexdigest()[:12]}",
        **compact,
    }
