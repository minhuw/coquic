from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from ..core.config import StewardConfig
from ..core.models import ProjectSignals, SignalFetchRun, SignalFetchStatus, SignalItem, utc_now
from .providers import (
    CodacyProvider,
    CodeScanningProvider,
    GitHubActionsProvider,
    GitHubActionsCiProvider,
    GitHubActionsDeployDemoProvider,
    GitHubActionsDuvetProvider,
    GitHubActionsInteropProvider,
    GitHubActionsNightlyCiProvider,
    GitHubActionsPerfProvider,
    GitHubActionsTestProvider,
    GitHubFeatureIssuesProvider,
    ProviderRevalidationError,
)

_SignalProvider: TypeAlias = (
    GitHubActionsProvider
    | GitHubFeatureIssuesProvider
    | CodeScanningProvider
    | CodacyProvider
)

PROVIDER_TYPES: dict[str, type[_SignalProvider]] = {
    GitHubActionsCiProvider.name: GitHubActionsCiProvider,
    GitHubActionsTestProvider.name: GitHubActionsTestProvider,
    GitHubActionsDuvetProvider.name: GitHubActionsDuvetProvider,
    GitHubActionsNightlyCiProvider.name: GitHubActionsNightlyCiProvider,
    GitHubActionsDeployDemoProvider.name: GitHubActionsDeployDemoProvider,
    GitHubActionsInteropProvider.name: GitHubActionsInteropProvider,
    GitHubActionsPerfProvider.name: GitHubActionsPerfProvider,
    GitHubFeatureIssuesProvider.name: GitHubFeatureIssuesProvider,
    CodeScanningProvider.name: CodeScanningProvider,
    CodacyProvider.name: CodacyProvider,
}


@dataclass(frozen=True)
class SignalCollection:
    fetch: SignalFetchRun
    items: list[SignalItem]


@dataclass(frozen=True)
class SignalRevalidation:
    actionable: list[SignalItem]
    stale_reasons: dict[str, str]
    refreshed: dict[str, SignalItem]


def signal_providers(names: tuple[str, ...]) -> list[_SignalProvider]:
    providers: list[_SignalProvider] = []
    for name in names:
        provider_type = PROVIDER_TYPES.get(name)
        if provider_type is None:
            choices = ", ".join(sorted(PROVIDER_TYPES))
            raise ValueError(
                f"unknown signal provider {name!r}; expected one of: {choices}"
            )
        providers.append(provider_type())
    return providers


def _revalidate_signal_items(
    config: StewardConfig,
    items: list[SignalItem],
    *,
    strict: bool,
    include_refreshed: bool,
) -> SignalRevalidation:
    providers: dict[str, _SignalProvider] = {}
    actionable: list[SignalItem] = []
    stale_reasons: dict[str, str] = {}
    refreshed: dict[str, SignalItem] = {}
    for item in items:
        provider_type = PROVIDER_TYPES.get(item.provider)
        if provider_type is None:
            if strict:
                stale_reasons[item.id] = "provider_unavailable"
            else:
                actionable.append(item)
            continue
        provider = providers.setdefault(item.provider, provider_type())
        try:
            reason = provider.stale_signal_reason(config, item, strict=strict)
        except ProviderRevalidationError:
            reason = "provider_unavailable"
        except Exception:  # pragma: no cover - ordinary planning remains fail-open.
            reason = "provider_unavailable" if strict else None
        if reason is None:
            current = item
            if include_refreshed:
                try:
                    candidate = provider.revalidated_signal_item(
                        config, item, strict=strict
                    )
                except ProviderRevalidationError:
                    candidate = None
                except AttributeError:
                    candidate = None
                except Exception:  # pragma: no cover - provider boundary guard.
                    candidate = None
                if (
                    isinstance(candidate, SignalItem)
                    and candidate.provider == item.provider
                    and candidate.kind == item.kind
                ):
                    # The Store relation remains the canonical task identity;
                    # only the provider-owned descriptive fields are refreshed.
                    if candidate.id != item.id or candidate.fingerprint != item.fingerprint:
                        candidate = candidate.model_copy(
                            update={
                                "id": item.id,
                                "fingerprint": item.fingerprint,
                            },
                            deep=True,
                        )
                    current = candidate
                    refreshed[item.id] = candidate
                elif strict:
                    stale_reasons[item.id] = "provider_unavailable"
                    continue
            actionable.append(current)
        else:
            stale_reasons[item.id] = reason
    return SignalRevalidation(actionable, stale_reasons, refreshed)


def revalidate_signal_items(
    config: StewardConfig,
    items: list[SignalItem],
    *,
    strict: bool = False,
    fail_closed: bool | None = None,
) -> tuple[list[SignalItem], dict[str, str]]:
    if fail_closed is not None:
        strict = bool(fail_closed)
    result = _revalidate_signal_items(
        config, items, strict=strict, include_refreshed=False
    )
    return result.actionable, result.stale_reasons


def revalidate_signal_items_with_context(
    config: StewardConfig,
    items: list[SignalItem],
    *,
    strict: bool = False,
    fail_closed: bool | None = None,
) -> SignalRevalidation:
    if fail_closed is not None:
        strict = bool(fail_closed)
    return _revalidate_signal_items(
        config, items, strict=strict, include_refreshed=True
    )


def collect_signal_items(
    config: StewardConfig,
    providers: list[_SignalProvider] | None = None,
    provider_names: list[str] | None = None,
) -> list[SignalCollection]:
    names = tuple(provider_names) if provider_names is not None else config.enabled_signals
    selected = (
        providers if providers is not None else signal_providers(names)
    )
    collections: list[SignalCollection] = []
    for provider in selected:
        started_at = utc_now()
        try:
            provider_config = config.signal_providers.get(provider.name)
            max_items = provider_config.max_items if provider_config else 12
            result = provider.collect(config, max_items=max_items)
            items = result.items
            error = result.error
            summary = result.summary
            has_more = result.has_more
        except Exception as exc:  # pragma: no cover - provider boundary guard.
            items = []
            error = str(exc)
            summary = ""
            has_more = False
        completed_at = utc_now()
        status = SignalFetchStatus.error if error else SignalFetchStatus.ok
        fetch = SignalFetchRun(
            provider=provider.name,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            item_count=len(items),
            new_item_count=0,
            has_more=has_more,
            error=error,
            summary=summary,
        )
        items = [
            item.model_copy(update={"source_fetch_id": fetch.id}, deep=True)
            for item in items
        ]
        collections.append(
            SignalCollection(fetch=fetch, items=items)
        )
    return collections


def project_signals_from_items(
    config: StewardConfig,
    items: list[SignalItem],
    *,
    fetches: list[SignalFetchRun] | None = None,
    enabled_signals: list[str] | None = None,
) -> ProjectSignals:
    summaries = [fetch.summary for fetch in fetches or [] if fetch.summary]
    if not summaries:
        summaries = [item.summary for item in items if item.summary]
    return ProjectSignals(
        repository=config.github_repository,
        enabled_signals=enabled_signals or list(config.enabled_signals),
        summary="\n".join(summaries),
        items=items,
        fetches=fetches or [],
    )
