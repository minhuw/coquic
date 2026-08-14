from __future__ import annotations

from abc import ABC, abstractmethod


class PublicationTransportSetupError(RuntimeError):
    """A pinned provider transport does not expose its required shape."""

    def __init__(self) -> None:
        super().__init__("unsupported publication transport shape")


class DaemonCancellation(ABC):
    """Private cancellation boundary owned by the daemon."""

    @abstractmethod
    def cancel(self) -> None:
        """Cancel the work owned by one daemon collaborator."""
