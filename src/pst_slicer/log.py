# SPDX-License-Identifier: GPL-3.0-or-later
"""Colorized, TTY-aware logging helpers.

Visual style matches ``bootstrap``:

    ==> note (blue arrow)
      OK: ok (green)
      WARN: warn (yellow)
      ERROR: err (red)

Warnings and errors go to stderr. Note/ok/info go to stdout. Each call
resolves the palette against its target stream so that if stderr is a
TTY but stdout is piped, colors still render correctly on stderr.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import IO, Any

from . import palette as _palette


# ---------------------------------------------------------------------------
# In-place progress-line state
# ---------------------------------------------------------------------------
#
# A single progress line may be "live" at any moment on one TTY-attached
# stream. Any other log call (note/ok/info/warn/err/header/kv) that targets
# the same stream must first blank that live line so its output appears on a
# clean row. When the caller is done, ``progress_end`` moves the cursor to
# the next row so the final progress state is preserved in scrollback.

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_progress: dict[str, Any] = {
    "active": False,
    "last_visible_len": 0,
    "stream": None,
}


def _is_tty(stream: IO[Any]) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _end_progress_line_for(stream: IO[Any]) -> None:
    """Blank the current in-place progress line if it is live on ``stream``.

    No-op when no progress line is active, or when the caller targets a
    different stream (progress on stdout, WARN on stderr - they don't
    collide because they're independent streams; the terminal interleaves
    them). If the user redirected both into the same file, that file gets
    plain lines from every call because ``progress`` short-circuits to
    a normal line whenever the target is not a TTY.
    """
    if not _progress["active"]:
        return
    ps = _progress["stream"]
    if ps is None or ps is not stream:
        return
    pad = " " * _progress["last_visible_len"]
    try:
        ps.write(f"\r{pad}\r")
        ps.flush()
    except Exception:
        pass
    _progress["active"] = False
    _progress["last_visible_len"] = 0
    _progress["stream"] = None


def _write(stream: IO[Any], text: str) -> None:
    _end_progress_line_for(stream)
    stream.write(text)
    stream.flush()


# ---------------------------------------------------------------------------
# Standard line-oriented helpers
# ---------------------------------------------------------------------------


def note(msg: str, *, stream: IO[Any] | None = None) -> None:
    stream = stream or sys.stdout
    p = _palette.for_stream(stream)
    _write(stream, f"{p.BLUE}==>{p.RESET} {msg}\n")


def ok(msg: str, *, stream: IO[Any] | None = None) -> None:
    stream = stream or sys.stdout
    p = _palette.for_stream(stream)
    _write(stream, f"  {p.GREEN}OK:{p.RESET} {msg}\n")


def info(msg: str, *, stream: IO[Any] | None = None) -> None:
    stream = stream or sys.stdout
    p = _palette.for_stream(stream)
    _write(stream, f"  {p.BLUE}INFO:{p.RESET} {msg}\n")


def warn(msg: str, *, stream: IO[Any] | None = None) -> None:
    stream = stream or sys.stderr
    p = _palette.for_stream(stream)
    _write(stream, f"  {p.YELLOW}WARN:{p.RESET} {msg}\n")


def err(msg: str, *, stream: IO[Any] | None = None) -> None:
    stream = stream or sys.stderr
    p = _palette.for_stream(stream)
    _write(stream, f"  {p.RED}ERROR:{p.RESET} {msg}\n")


def header(title: str, *, stream: IO[Any] | None = None) -> None:
    stream = stream or sys.stdout
    p = _palette.for_stream(stream)
    _write(stream, f"\n  {p.BOLD}{title}{p.RESET}\n")
    stream.write("  " + ("-" * 40) + "\n")
    stream.flush()


def kv(key: str, value: str, *, stream: IO[Any] | None = None) -> None:
    """Left-aligned key / value pair for the run summary."""
    stream = stream or sys.stdout
    p = _palette.for_stream(stream)
    _write(stream, f"    {p.DIM}{key:<28}{p.RESET} {value}\n")


# ---------------------------------------------------------------------------
# In-place progress helper (TTY) with newline fallback (non-TTY)
# ---------------------------------------------------------------------------


def progress(msg: str, *, stream: IO[Any] | None = None) -> None:
    """Emit ``msg`` as an in-place progress line on TTYs.

    On a TTY, rewrites the current line using ``\\r``, padding with
    trailing spaces so any overhang from a longer previous line is
    erased. This produces a single, updating status line rather than
    hundreds of scrolling INFO rows.

    When the target stream is NOT a TTY (piped, redirected, teed to a
    log file), falls back to emitting a normal ``INFO`` line so redirect
    captures still contain every update in a grep-friendly form.
    """
    stream = stream or sys.stdout
    p = _palette.for_stream(stream)

    if not _is_tty(stream):
        stream.write(f"  {p.BLUE}INFO:{p.RESET} {msg}\n")
        stream.flush()
        return

    line = f"  {p.BLUE}INFO:{p.RESET} {msg}"
    visible = _visible_len(line)
    prev_visible = _progress["last_visible_len"] if _progress["active"] else 0
    pad = max(0, prev_visible - visible)
    stream.write("\r" + line + (" " * pad))
    stream.flush()
    _progress["active"] = True
    _progress["last_visible_len"] = visible
    _progress["stream"] = stream


def progress_end(*, stream: IO[Any] | None = None) -> None:
    """Finalize the current progress line: move the cursor to the next
    row so the final progress state stays in the scrollback. Idempotent;
    safe to call whether or not a progress line is currently live.
    """
    stream = stream or sys.stdout
    if _progress["active"] and _progress["stream"] is stream:
        try:
            stream.write("\n")
            stream.flush()
        except Exception:
            pass
        _progress["active"] = False
        _progress["last_visible_len"] = 0
        _progress["stream"] = None


# ---------------------------------------------------------------------------
# Auto-capture to a plain-text log file
# ---------------------------------------------------------------------------
#
# Each tool that wants to leave a forensically-preserved on-disk copy of its
# terminal session calls ``install_capture(path)`` early in ``main``. From
# that point on, everything written to ``sys.stdout`` and ``sys.stderr`` is
# duplicated into ``path``, with ANSI escape sequences stripped so the file
# is grep-friendly plain UTF-8. The TTY still receives the original bytes,
# so live output remains colored and interactive.
#
# The captured file is opened in write mode (truncates any existing content)
# so re-runs produce a fresh log rather than appending. This matches how the
# tool's other artifacts (manifest.tsv, not_found.txt, run.log) behave.


class _AnsiStrippingTee:
    """Duplicates writes to ``file_stream`` (ANSI-stripped) while
    forwarding untouched to ``tty_stream``. All other attribute access
    is forwarded to ``tty_stream`` so ``.isatty()``, ``.fileno()``, etc.
    behave as if this shim were the original stream."""

    __slots__ = ("_tty", "_file")

    def __init__(self, tty_stream: IO[Any], file_stream: IO[Any]) -> None:
        self._tty = tty_stream
        self._file = file_stream

    def write(self, data: str) -> int:
        try:
            n = self._tty.write(data)
        except Exception:
            n = len(data)
        try:
            self._file.write(_ANSI_RE.sub("", data))
        except Exception:
            pass
        return n

    def flush(self) -> None:
        try:
            self._tty.flush()
        except Exception:
            pass
        try:
            self._file.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        f = getattr(self._tty, "isatty", None)
        return bool(f()) if callable(f) else False

    def fileno(self) -> int:
        return self._tty.fileno()

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - passthrough
        return getattr(self._tty, name)


_capture: dict[str, Any] = {
    "file": None,
    "path": None,
    "orig_stdout": None,
    "orig_stderr": None,
}


def install_capture(path: Path) -> Path:
    """Duplicate ``sys.stdout`` + ``sys.stderr`` writes to ``path``.

    Idempotent: only the first call takes effect. The captured file is
    opened in write mode (truncates any prior contents). ANSI escape
    codes are stripped from the file version so the log is grep-friendly
    plain UTF-8; the TTY still sees the original colored bytes.
    """
    if _capture["file"] is not None:
        return _capture["path"]  # already installed
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("w", encoding="utf-8", newline="\n")
    _capture["file"] = fh
    _capture["path"] = path
    _capture["orig_stdout"] = sys.stdout
    _capture["orig_stderr"] = sys.stderr
    sys.stdout = _AnsiStrippingTee(sys.stdout, fh)
    sys.stderr = _AnsiStrippingTee(sys.stderr, fh)
    return path


def uninstall_capture() -> None:
    """Restore the original ``sys.stdout``/``sys.stderr`` and close the
    capture file. Safe to call multiple times. Callers should invoke
    this from the very tail of ``main`` (or in an ``atexit`` hook) so
    the log file's contents are flushed to disk."""
    if _capture["file"] is None:
        return
    try:
        sys.stdout = _capture["orig_stdout"]
        sys.stderr = _capture["orig_stderr"]
    except Exception:
        pass
    try:
        _capture["file"].flush()
        _capture["file"].close()
    except Exception:
        pass
    _capture["file"] = None
    _capture["path"] = None
    _capture["orig_stdout"] = None
    _capture["orig_stderr"] = None
