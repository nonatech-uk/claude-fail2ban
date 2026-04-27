"""Source abstraction: produce simplified log entries since the last run."""

from __future__ import annotations

from abc import ABC, abstractmethod


class Source(ABC):
    """A pluggable log source. Sources own their own cursor inside `state`."""

    name: str = "source"

    @abstractmethod
    def read_new_entries(self, state: dict) -> list[dict]:
        """Return a list of raw entries (as dicts) appended since last run.

        State is mutated in place: implementations must persist whatever
        cursor they need to avoid re-reading old entries on the next call.
        """

    @abstractmethod
    def is_suspicious(self, entry: dict) -> bool:
        """Pre-filter: cheap heuristic to keep only entries worth analysing."""

    @abstractmethod
    def simplify(self, entry: dict) -> dict:
        """Reduce a raw entry to the compact dict shape sent to the LLM.

        Must always include `client_ip` (string).
        """
