# SPDX-License-Identifier: GPL-3.0-or-later
"""Attachment-extension matcher.

Matches a message if any of its attachments carries a filename whose
extension is in the configured set. Extensions are compared
case-insensitively; the config-supplied set is normalized (a leading
``.`` is added if the user omitted it).

Uses the attachment metadata that the PST walker caches on ``PstItem``
so no message re-open is needed. Longer filename wins over 8.3 name
(``PR_ATTACH_LONG_FILENAME`` before ``PR_ATTACH_FILENAME``).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ..config import AttachmentExtModeConfig, Config
from .base import Matcher, MatchResult

if TYPE_CHECKING:
    from ..pst import PstItem


class AttachmentExtMatcher(Matcher):
    name = "attachment_ext"

    def __init__(self, cfg: AttachmentExtModeConfig) -> None:
        self._originals: dict[str, str] = {}
        for raw in cfg.extensions:
            norm = raw.strip().casefold()
            if norm and not norm.startswith("."):
                norm = "." + norm
            if norm:
                self._originals.setdefault(norm, raw.strip())
        self._hit: set[str] = set()

    @classmethod
    def from_config(cls, cfg: Config) -> "AttachmentExtMatcher":
        assert cfg.mode_type == "attachment_ext"
        return cls(cfg.mode)  # type: ignore[arg-type]

    def matches(self, item: "PstItem") -> MatchResult | None:
        if not item.attachments:
            return None
        for att in item.attachments:
            filename = att.filename or ""
            if not filename:
                continue
            _root, ext = os.path.splitext(filename)
            if not ext:
                continue
            ext_norm = ext.casefold()
            original = self._originals.get(ext_norm)
            if original is not None:
                self._hit.add(ext_norm)
                return MatchResult(
                    mode="attachment_ext",
                    matched_value=original,
                    detail=filename,
                )
        return None

    def report_unmatched(self) -> list[str]:
        missing = [k for k in self._originals if k not in self._hit]
        return sorted(self._originals[k] for k in missing)
