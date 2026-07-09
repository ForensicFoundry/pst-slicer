# SPDX-License-Identifier: GPL-3.0-or-later
"""TSV manifest writer + run log helpers.

The manifest is a plain TSV so downstream reviewing counsel and
e-discovery tooling can consume it without a spreadsheet import wizard.

Columns (in order):

    imid
    match_reason                <mode>:<matched-value>[ (<detail>)]
    client_submit_time_utc      YYYY-MM-DD HH:MM:SS (UTC)
    message_delivery_time_utc   YYYY-MM-DD HH:MM:SS (UTC)
    date_header_utc             YYYY-MM-DD HH:MM:SS (UTC)
    sender
    recipients
    subject
    size_bytes
    sha256
    source_folder
    source_pst
    output_path

Field values are sanitized to strip TSV-hostile characters (TAB, CR, LF)
so a single malformed subject can't shear the file. Original values are
preserved inside the EML itself.
"""

from __future__ import annotations

import csv
import datetime as _dt
from dataclasses import dataclass
from pathlib import Path
from typing import IO


MANIFEST_COLUMNS: tuple[str, ...] = (
    "imid",
    "match_reason",
    "client_submit_time_utc",
    "message_delivery_time_utc",
    "date_header_utc",
    "sender",
    "recipients",
    "subject",
    "size_bytes",
    "sha256",
    "source_folder",
    "source_pst",
    "output_path",
)


@dataclass
class ManifestRow:
    imid: str
    match_reason: str
    client_submit_time_utc: _dt.datetime | None
    message_delivery_time_utc: _dt.datetime | None
    date_header_utc: _dt.datetime | None
    sender: str
    recipients: str
    subject: str
    size_bytes: int
    sha256: str
    source_folder: str
    source_pst: str
    output_path: str

    def to_row(self) -> list[str]:
        return [
            _clean(self.imid),
            _clean(self.match_reason),
            _fmt_ts(self.client_submit_time_utc),
            _fmt_ts(self.message_delivery_time_utc),
            _fmt_ts(self.date_header_utc),
            _clean(self.sender),
            _clean(self.recipients),
            _clean(self.subject),
            str(self.size_bytes),
            _clean(self.sha256),
            _clean(self.source_folder),
            _clean(self.source_pst),
            _clean(self.output_path),
        ]


class ManifestWriter:
    """Append-only TSV writer that keeps the file valid on every flush."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fh: IO[str] | None = None
        self._writer: "csv._writer" | None = None  # type: ignore[name-defined]
        self._row_count = 0

    def __enter__(self) -> "ManifestWriter":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open("w", encoding="utf-8", newline="")
        self._writer = csv.writer(
            self._fh,
            dialect="excel-tab",
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        self._writer.writerow(list(MANIFEST_COLUMNS))
        self._fh.flush()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
            finally:
                self._fh.close()
                self._fh = None
                self._writer = None

    def write(self, row: ManifestRow) -> None:
        assert self._writer is not None and self._fh is not None
        self._writer.writerow(row.to_row())
        self._fh.flush()
        self._row_count += 1

    @property
    def rows_written(self) -> int:
        return self._row_count


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fmt_ts(dt: _dt.datetime | None) -> str:
    if dt is None:
        return ""
    # Assume already UTC-aware; caller normalizes.
    if dt.tzinfo is not None:
        dt = dt.astimezone(_dt.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _clean(val: str) -> str:
    """Strip TSV-hostile characters. TAB -> single space, CR/LF -> single space."""
    if not val:
        return ""
    out = val.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    # Collapse runs of whitespace to keep the manifest legible.
    return " ".join(out.split())


def write_not_found(path: Path, imids: list[str]) -> None:
    """Emit an ordered list of unmatched IMIDs (empty file if all matched)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for imid in imids:
            fh.write(imid.rstrip() + "\n")
