# SPDX-License-Identifier: GPL-3.0-or-later
"""TTY-aware ANSI color palette.

Every color-emitting site in the tool asks for a palette bound to a
specific output stream. If that stream is not a TTY (piped, redirected,
``NO_COLOR`` set, etc.) every code returns empty string, so the on-disk
capture log and any redirected stdout stay plain ASCII.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import IO, Any


@dataclass(frozen=True)
class Palette:
    BOLD: str
    DIM: str
    ITALIC: str
    UNDERLINE: str
    RED: str
    GREEN: str
    YELLOW: str
    BLUE: str
    MAGENTA: str
    CYAN: str
    WHITE: str
    GREY: str
    RESET: str

    @property
    def enabled(self) -> bool:
        return bool(self.RESET)


_ACTIVE = Palette(
    BOLD="\033[1m",
    DIM="\033[2m",
    ITALIC="\033[3m",
    UNDERLINE="\033[4m",
    RED="\033[31m",
    GREEN="\033[32m",
    YELLOW="\033[33m",
    BLUE="\033[34m",
    MAGENTA="\033[35m",
    CYAN="\033[36m",
    WHITE="\033[37m",
    GREY="\033[90m",
    RESET="\033[0m",
)


_INACTIVE = Palette(
    BOLD="", DIM="", ITALIC="", UNDERLINE="",
    RED="", GREEN="", YELLOW="", BLUE="", MAGENTA="",
    CYAN="", WHITE="", GREY="", RESET="",
)


def _no_color_env() -> bool:
    """Respect ``NO_COLOR`` (https://no-color.org/) and ``PST_SLICER_NO_COLOR``."""
    return bool(os.environ.get("NO_COLOR") or os.environ.get("PST_SLICER_NO_COLOR"))


def _force_color_env() -> bool:
    """Respect ``FORCE_COLOR`` / ``PST_SLICER_FORCE_COLOR`` for pipe-friendly tests."""
    return bool(os.environ.get("FORCE_COLOR") or os.environ.get("PST_SLICER_FORCE_COLOR"))


def for_stream(stream: IO[Any] | None) -> Palette:
    """Return the appropriate palette for ``stream``.

    Precedence:
      1. ``NO_COLOR`` (or ``PST_SLICER_NO_COLOR``)         -> always inactive
      2. ``FORCE_COLOR`` (or ``PST_SLICER_FORCE_COLOR``)   -> always active
      3. ``stream.isatty()``                               -> honor terminal state
    """
    if _no_color_env():
        return _INACTIVE
    if _force_color_env():
        return _ACTIVE
    if stream is None:
        return _INACTIVE
    is_tty = hasattr(stream, "isatty") and stream.isatty()
    return _ACTIVE if is_tty else _INACTIVE


def stdout() -> Palette:
    return for_stream(sys.stdout)


def stderr() -> Palette:
    return for_stream(sys.stderr)
