# SPDX-License-Identifier: GPL-3.0-or-later
"""Sender-domain matcher: case-insensitive domain of the sender.

A message matches if the domain portion of the sender's SMTP address
(what follows the last ``@``) equals a configured domain, or is a
sub-domain of it. That means configuring ``example.com`` will match
``bob@example.com``, ``bob@mail.example.com``, and
``bob@corp.example.com``, but NOT ``bob@notexample.com``.

The subdomain rule is intentional: forensic requests are typically
"find everything from suspectdomain.com and any of its mail relays."
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import Config, SenderDomainModeConfig
from .base import Matcher, MatchResult

if TYPE_CHECKING:
    from ..pst import PstItem


class SenderDomainMatcher(Matcher):
    name = "sender_domain"

    def __init__(self, cfg: SenderDomainModeConfig) -> None:
        self._originals: dict[str, str] = {}
        for raw in cfg.domains:
            norm = raw.strip().casefold().lstrip("@")
            if norm:
                self._originals.setdefault(norm, raw.strip())
        self._hit: set[str] = set()

    @classmethod
    def from_config(cls, cfg: Config) -> "SenderDomainMatcher":
        assert cfg.mode_type == "sender_domain"
        return cls(cfg.mode)  # type: ignore[arg-type]

    def matches(self, item: "PstItem") -> MatchResult | None:
        addr = (item.sender_email or "").strip().casefold()
        if "@" not in addr:
            return None
        addr_domain = addr.rsplit("@", 1)[1]
        # Match exact domain OR any subdomain.
        for norm, original in self._originals.items():
            if addr_domain == norm or addr_domain.endswith("." + norm):
                self._hit.add(norm)
                return MatchResult(
                    mode="sender_domain",
                    matched_value=original,
                    detail=addr_domain if addr_domain != norm else "",
                )
        return None

    def report_unmatched(self) -> list[str]:
        missing = [k for k in self._originals if k not in self._hit]
        return sorted(self._originals[k] for k in missing)
