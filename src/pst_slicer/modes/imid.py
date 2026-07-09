# SPDX-License-Identifier: GPL-3.0-or-later
"""IMID (Internet Message-ID) matcher.

The PST-side value is compared using the same normalization rule that
the config loader used on the target list:

    * strip whitespace
    * strip a single surrounding pair of angle brackets, if present
    * casefold

Falls back to the ``Message-ID:`` header parsed from the transport
headers when the MAPI ``PR_INTERNET_MESSAGE_ID`` (PID 0x1035) property
is missing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import Config, _normalize_imid
from .base import Matcher, MatchResult

if TYPE_CHECKING:  # avoid circular runtime import
    from ..pst import PstItem


class ImidMatcher(Matcher):
    name = "IMID"

    def __init__(self, targets: dict[str, str]) -> None:
        """``targets`` maps normalized IMID -> original user-supplied form."""
        self._targets = targets
        self._hit: set[str] = set()

    @classmethod
    def from_config(cls, cfg: Config) -> "ImidMatcher":
        assert cfg.mode_type == "IMID"
        targets: dict[str, str] = {}
        for raw in cfg.mode.imids:  # type: ignore[union-attr]
            norm = _normalize_imid(raw)
            if not norm:
                continue
            targets.setdefault(norm, raw.strip())
        return cls(targets=targets)

    def matches(self, item: "PstItem") -> MatchResult | None:
        candidate = item.internet_message_id
        if not candidate:
            return None
        norm = _normalize_imid(candidate)
        if not norm:
            return None
        original = self._targets.get(norm)
        if original is None:
            return None
        self._hit.add(norm)
        return MatchResult(mode="IMID", matched_value=original)

    def report_unmatched(self) -> list[str]:
        missing = set(self._targets) - self._hit
        return sorted(self._targets[n] for n in missing)
