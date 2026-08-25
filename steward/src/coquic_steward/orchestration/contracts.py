from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DaemonCancellationResult:
    """Report whether a daemon collaborator reached quiescence."""

    quiescent: bool


class PublicationTransportSetupError(RuntimeError):
    """A pinned provider transport does not expose its required shape."""

    def __init__(self) -> None:
        super().__init__("unsupported publication transport shape")


class DaemonCancellation(ABC):
    """Private cancellation boundary owned by the daemon."""

    @abstractmethod
    def cancel(self, deadline: float | None = None) -> DaemonCancellationResult:
        """Cancel one collaborator, bounded by an optional monotonic deadline."""
