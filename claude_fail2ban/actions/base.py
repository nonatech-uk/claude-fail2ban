"""Action abstraction: enforce a ban decision."""

from __future__ import annotations

from abc import ABC, abstractmethod


class Action(ABC):
    name: str = "action"

    @abstractmethod
    def currently_banned(self) -> set[str]:
        """Return the set of IPs currently banned by this backend.

        Used to short-circuit redundant ban calls. Returns an empty set on
        backend error rather than raising — best-effort.
        """

    @abstractmethod
    def ban(self, ip: str, reason: str) -> bool:
        """Apply the ban. Return True on success, False on failure."""
