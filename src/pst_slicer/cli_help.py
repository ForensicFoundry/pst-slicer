# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared palette-aware ``argparse`` scaffolding.

Every ``pst-slicer-*`` tool exposes a stable
``-h/--help``, ``-v/--version``, ``CONFIG``-shaped CLI. This module
provides:

- ``ColoredHelpAction`` / ``ColoredVersionAction`` argparse Actions that
  invoke tool-supplied printers so each command still renders its own
  help/version text but the invocation mechanics are shared.
- ``ColoredArgParser`` that routes error output through the palette and
  a tool-supplied usage printer, so ``--help``, ``--version``, and
  argparse ``error()`` all obey the same TTY/color rules.
- ``help_row`` / ``strip_ansi`` formatting helpers so each tool's
  ``print_help`` implementation lines up columns cleanly regardless of
  the ANSI codes embedded in labels.
- ``print_version_line`` - a default one-liner some tools use verbatim.

Each tool provides three small functions and hands them to
``build_parser``:

    def print_version(stream): ...
    def print_usage(stream):   ...
    def print_help(stream):    ...

    parser = build_parser(
        prog="pst-slicer-verify",
        version_printer=print_version,
        usage_printer=print_usage,
        help_printer=print_help,
    )
"""

from __future__ import annotations

import argparse
import sys
from typing import IO, Any, Callable

from . import log, palette as _palette


# ---------------------------------------------------------------------------
# Formatting helpers used by each tool's ``print_help``
# ---------------------------------------------------------------------------


def strip_ansi(text: str) -> str:
    """Return ``text`` with ANSI CSI ``m`` sequences removed.

    Only used for column-alignment calculations in help output. Not
    intended as a general-purpose escape sanitizer.
    """
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "\033" and i + 1 < len(text) and text[i + 1] == "[":
            j = text.find("m", i)
            if j == -1:
                out.append(text[i])
                i += 1
                continue
            i = j + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def help_row(
    stream: IO[Any],
    palette: _palette.Palette,
    label_colored: str,
    description: str,
    *,
    label_column: int = 22,
) -> None:
    """Emit one ``  <label>   <description>\\n`` row, using ``strip_ansi``
    to compute the padding so ANSI codes don't skew the column."""
    del palette  # currently unused; accept for API stability
    visible = strip_ansi(label_colored)
    padding = max(2, label_column - len(visible))
    stream.write(f"  {label_colored}{' ' * padding}{description}\n")


def print_version_line(
    stream: IO[Any],
    *,
    prog: str,
    version: str,
    tagline: str,
    license_id: str = "GPL-3.0-or-later",
) -> None:
    """Standard one-block version output used by most tools.

    Layout:

        <PROG> v<VERSION>
          <TAGLINE> - <LICENSE>
    """
    p = _palette.for_stream(stream)
    stream.write(
        f"{p.BOLD}{p.BLUE}{prog}{p.RESET} {p.GREEN}v{version}{p.RESET}\n"
        f"  {p.DIM}{tagline} - {license_id}{p.RESET}\n"
    )
    stream.flush()


# ---------------------------------------------------------------------------
# argparse Actions + parser that route through the shared palette
# ---------------------------------------------------------------------------


_Printer = Callable[[IO[Any]], None]


class ColoredHelpAction(argparse.Action):
    """``-h/--help`` action that delegates rendering to a tool-supplied
    printer. Attach the printer to the parser via ``build_parser``."""

    def __init__(
        self,
        option_strings,
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        help=None,
    ):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        printer = getattr(parser, "_help_printer", None)
        if printer is None:
            argparse.HelpFormatter  # keep import happy
            parser.print_help(sys.stdout)
        else:
            printer(sys.stdout)
        parser.exit(0)


class ColoredVersionAction(argparse.Action):
    def __init__(
        self,
        option_strings,
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        help=None,
    ):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        printer = getattr(parser, "_version_printer", None)
        if printer is None:
            parser.exit(0)  # noqa: RET503 - defensive fallback
            return
        printer(sys.stdout)
        parser.exit(0)


class ColoredArgParser(argparse.ArgumentParser):
    """ArgumentParser that renders usage + errors via the shared palette."""

    _usage_printer: _Printer | None = None
    _help_printer: _Printer | None = None
    _version_printer: _Printer | None = None

    def error(self, message: str) -> None:  # type: ignore[override]
        printer = self._usage_printer
        if printer is not None:
            printer(sys.stderr)
        log.err(message)
        raise SystemExit(2)

    def print_usage(self, file: IO[Any] | None = None) -> None:  # type: ignore[override]
        stream = file or sys.stdout
        printer = self._usage_printer
        if printer is not None:
            printer(stream)
        else:
            super().print_usage(stream)

    def print_help(self, file: IO[Any] | None = None) -> None:  # type: ignore[override]
        stream = file or sys.stdout
        printer = self._help_printer
        if printer is not None:
            printer(stream)
        else:
            super().print_help(stream)


def build_parser(
    *,
    prog: str,
    version_printer: _Printer,
    usage_printer: _Printer,
    help_printer: _Printer,
) -> ColoredArgParser:
    """Return a ``ColoredArgParser`` pre-wired with ``-h/--help`` and
    ``-v/--version``. The caller adds its own positional / optional
    arguments before ``parse_args``.
    """
    parser = ColoredArgParser(prog=prog, add_help=False)
    parser._usage_printer = usage_printer
    parser._help_printer = help_printer
    parser._version_printer = version_printer
    parser.add_argument(
        "-h", "--help", action=ColoredHelpAction, help="Show help and exit."
    )
    parser.add_argument(
        "-v",
        "--version",
        action=ColoredVersionAction,
        help="Show version and exit.",
    )
    return parser
