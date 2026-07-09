# SPDX-License-Identifier: GPL-3.0-or-later
"""Matcher contract.

A ``Matcher`` inspects the metadata returned by the PST walker and
either returns a ``MatchResult`` (with the reason we matched, so the
manifest can record it) or ``None``.

Matchers never touch attachment bytes or reopen the message; they work
strictly off ``PstItem`` which already carries attachment metadata
(filename, mime, size) collected by ``pst.py``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MatchResult:
    #: Short mode tag, e.g. ``"IMID"``, ``"keyword"``, ``"sender"``.
    mode: str
    #: The specific config-supplied value that matched, verbatim as the
    #: user provided it (before normalization). Populates the primary
    #: half of the ``match_reason`` manifest column.
    matched_value: str
    #: Optional context (e.g. ``"subject"`` when a keyword hit in the
    #: subject line, or an attachment filename for attachment_ext).
    detail: str = ""

    def render_reason(self) -> str:
        """Formatted value written to the ``match_reason`` manifest column."""
        core = f"{self.mode}:{self.matched_value}"
        if self.detail:
            return f"{core} [{self.detail}]"
        return core


class Matcher(ABC):
    """Abstract base for match strategies."""

    #: Human-readable mode name, e.g. ``"IMID"``. Must equal the string
    #: used in the config (``mode.type``) so the registry can look it
    #: up.
    name: str

    @abstractmethod
    def matches(self, item: Any) -> MatchResult | None:
        """Return a ``MatchResult`` if ``item`` matches, else ``None``."""

    @abstractmethod
    def report_unmatched(self) -> list[str]:
        """Return the list of config-supplied targets never matched.

        Used to populate ``not_found.txt`` at the end of a run. Modes
        where "unmatched target" doesn't apply (e.g. keyword search
        that scans every message with no fixed target set) should
        return ``[]``.
        """
