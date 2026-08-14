from __future__ import annotations

from abc import ABC, abstractmethod


class DaemonCancellation(ABC):
    """Private cancellation boundary owned by the daemon."""

    @abstractmethod
    def cancel(self) -> None:
        """Cancel the work owned by one daemon collaborator."""
