from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..core.config import StewardConfig
from ..core.models import ProjectSignals, SignalFetchRun, SignalFetchStatus, SignalItem, utc_now
from .providers import (
    CodacyProvider,
    CodeScanningProvider,
    GitHubActionsCiProvider,
    GitHubActionsDeployDemoProvider,
    GitHubActionsDuvetProvider,
    GitHubActionsInteropProvider,
    GitHubActionsNightlyCiProvider,
    GitHubActionsPerfProvider,
    GitHubActionsTestProvider,
    SignalProvider,
)

PROVIDER_TYPES: dict[str, type[SignalProvider]] = {
    GitHubActionsCiProvider.name: GitHubActionsCiProvider,
    GitHubActionsTestProvider.name: GitHubActionsTestProvider,
    GitHubActionsDuvetProvider.name: GitHubActionsDuvetProvider,
    GitHubActionsNightlyCiProvider.name: GitHubActionsNightlyCiProvider,
    GitHubActionsDeployDemoProvider.name: GitHubActionsDeployDemoProvider,
    GitHubActionsInteropProvider.name: GitHubActionsInteropProvider,
    GitHubActionsPerfProvider.name: GitHubActionsPerfProvider,
    CodeScanningProvider.name: CodeScanningProvider,
    CodacyProvider.name: CodacyProvider,
}


@dataclass(frozen=True)
class SignalCollection:
    provider: str
    fetch: SignalFetchRun
    items: list[SignalItem]
    started_at: datetime
    completed_at: datetime

    @property
    def error(self) -> str | None:
        return self.fetch.error


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
    collections = collect_signal_items(config, providers=providers)
    return project_signals_from_items(
        config,
        [item for collection in collections for item in collection.items],
        fetches=[collection.fetch for collection in collections],
        enabled_signals=[collection.provider for collection in collections],
    )


def collect_signal_items(
    config: StewardConfig,
    providers: list[SignalProvider] | None = None,
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
            try:
                result = provider.collect(config, max_items=max_items)
            except TypeError as exc:
                if "max_items" not in str(exc):
                    raise
                result = provider.collect(config)
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
            SignalCollection(
                provider=provider.name,
                fetch=fetch,
                items=items,
                started_at=started_at,
                completed_at=completed_at,
            )
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
