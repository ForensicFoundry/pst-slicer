# SPDX-License-Identifier: GPL-3.0-or-later
"""Sender matcher: exact-address, case-insensitive.

RFC 5321 s2.4 says the local-part is case-sensitive in principle but
"in practice" implementations treat it insensitively; the domain is
always case-insensitive. We follow the common e-discovery convention
and compare both halves case-insensitively.

Match target is the SMTP address the walker has already picked from the
best available MAPI property (SENT_REPRESENTING_SMTP_ADDRESS, then
SENDER_SMTP_ADDRESS, then the plain EMAIL_ADDRESS fields).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import Config, SenderModeConfig
from .base import Matcher, MatchResult

if TYPE_CHECKING:
    from ..pst import PstItem


class SenderMatcher(Matcher):
    name = "sender"

    def __init__(self, cfg: SenderModeConfig) -> None:
        self._originals = tuple(cfg.addresses)
        self._normalized: dict[str, str] = {
            a.strip().casefold(): a.strip() for a in cfg.addresses
        }
        self._hit: set[str] = set()

    @classmethod
    def from_config(cls, cfg: Config) -> "SenderMatcher":
        assert cfg.mode_type == "sender"
        return cls(cfg.mode)  # type: ignore[arg-type]

    def matches(self, item: "PstItem") -> MatchResult | None:
        addr = (item.sender_email or "").strip().casefold()
        if not addr:
            return None
        original = self._normalized.get(addr)
        if original is None:
            return None
        self._hit.add(addr)
        return MatchResult(mode="sender", matched_value=original)

    def report_unmatched(self) -> list[str]:
        missing = [k for k in self._normalized if k not in self._hit]
        return sorted(self._normalized[k] for k in missing)
