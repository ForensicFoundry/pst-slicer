# SPDX-License-Identifier: GPL-3.0-or-later
"""Matcher registry.

Each ``mode.type`` in the config selects a ``Matcher`` implementation
that answers ``matches(item) -> MatchResult | None`` for every message
the walker yields. New modes plug in by registering a ``from_config``
factory keyed on their config's ``mode.type`` string.
"""

from __future__ import annotations

from typing import Callable

from ..config import Config
from .attachment_ext import AttachmentExtMatcher
from .base import Matcher, MatchResult
from .imid import ImidMatcher
from .keyword import KeywordMatcher
from .sender import SenderMatcher
from .sender_domain import SenderDomainMatcher

_REGISTRY: dict[str, Callable[[Config], Matcher]] = {
    "IMID": ImidMatcher.from_config,
    "keyword": KeywordMatcher.from_config,
    "sender": SenderMatcher.from_config,
    "sender_domain": SenderDomainMatcher.from_config,
    "attachment_ext": AttachmentExtMatcher.from_config,
}


def build_matcher(cfg: Config) -> Matcher:
    """Instantiate the matcher named by ``cfg.mode_type``."""
    factory = _REGISTRY.get(cfg.mode_type)
    if factory is None:  # pragma: no cover - guarded by config validation
        raise KeyError(f"No matcher registered for mode {cfg.mode_type!r}")
    return factory(cfg)


__all__ = ["Matcher", "MatchResult", "build_matcher"]
