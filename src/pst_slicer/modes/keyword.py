# SPDX-License-Identifier: GPL-3.0-or-later
"""Keyword matcher.

Searches ``subject`` and/or ``body`` (plain text + HTML-stripped text)
for any of the configured keywords. Case-insensitive by default;
opt-in case-sensitive via ``[mode.keyword].case_sensitive = true``.

Forensic notes:
  * The HTML body is stripped of tags via the stdlib ``html.parser``
    (no external deps) so keywords match rendered visible text rather
    than tag/attribute noise. We do NOT skip inline ``<script>`` /
    ``<style>`` content - a keyword hidden inside them still counts as
    "present in the message" for e-discovery purposes.
  * The manifest's ``match_reason`` column records the field that
    triggered the match (e.g. ``keyword:acquisition [subject]``).
  * "Unmatched target" reporting: a keyword that never fires is
    reported in ``not_found.txt`` to help you tune the search set.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import TYPE_CHECKING

from ..config import Config, KeywordModeConfig
from .base import Matcher, MatchResult

if TYPE_CHECKING:
    from ..pst import PstItem


class _HTMLTextExtractor(HTMLParser):
    """Concatenate visible text from HTML, preserving whitespace loosely."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._buf: list[str] = []

    def handle_data(self, data: str) -> None:
        self._buf.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # A single space between blocky tags keeps adjacent words from
        # colliding when stripping (e.g. "<p>foo</p><p>bar</p>" -> "foo bar").
        self._buf.append(" ")

    def handle_endtag(self, tag: str) -> None:
        self._buf.append(" ")

    def get_text(self) -> str:
        return "".join(self._buf)


def _html_to_text(html: str) -> str:
    if not html:
        return ""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Best-effort: some malformed HTML can throw jankiness. Fall back to raw.
        return html
    return parser.get_text()


class KeywordMatcher(Matcher):
    name = "keyword"

    def __init__(self, cfg: KeywordModeConfig) -> None:
        self._case_sensitive = cfg.case_sensitive
        self._fields = frozenset(cfg.fields)
        # Preserve the original spelling for manifest / not_found reporting,
        # store the comparison form separately.
        self._keywords = tuple(cfg.keywords)
        self._compare: tuple[str, ...] = tuple(
            k if cfg.case_sensitive else k.casefold() for k in cfg.keywords
        )
        self._hit: set[int] = set()  # indices into self._keywords

    @classmethod
    def from_config(cls, cfg: Config) -> "KeywordMatcher":
        assert cfg.mode_type == "keyword"
        return cls(cfg.mode)  # type: ignore[arg-type]

    def matches(self, item: "PstItem") -> MatchResult | None:
        # Build a mapping of field -> comparison-form haystack, only for
        # the fields this matcher was configured to search.
        haystacks: list[tuple[str, str]] = []
        if "subject" in self._fields:
            haystacks.append(("subject", self._prep(item.subject)))
        if "body" in self._fields:
            plain = item.body_plain or ""
            html_text = _html_to_text(item.body_html or "")
            haystacks.append(("body", self._prep(plain + "\n" + html_text)))

        for i, needle in enumerate(self._compare):
            for field, hay in haystacks:
                if needle in hay:
                    self._hit.add(i)
                    return MatchResult(
                        mode="keyword",
                        matched_value=self._keywords[i],
                        detail=field,
                    )
        return None

    def report_unmatched(self) -> list[str]:
        return [self._keywords[i] for i in range(len(self._keywords)) if i not in self._hit]

    def _prep(self, text: str) -> str:
        if not text:
            return ""
        return text if self._case_sensitive else text.casefold()
