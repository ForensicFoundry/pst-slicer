# SPDX-License-Identifier: GPL-3.0-or-later
"""Command-line dispatch for pst-slicer.

Surface intentionally kept minimal so calling convention is stable
across future releases:

    pst-slicer -v/--version
    pst-slicer -h/--help
    pst-slicer <path-to-config-file>

``-v`` and ``-h`` output is TTY-aware and colorized via the shared
palette. When stdout is not a TTY (piped/redirected) or ``NO_COLOR``
is set, output degrades to plain ASCII automatically.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import IO, Any, Sequence

from . import __version__, cli_help, log, palette as _palette
from .config import ConfigError, load_config
from .extract import ExtractionError, run_extraction


PROG = "pst-slicer"
TAGLINE = "Forensic PST message extractor"


# ---------------------------------------------------------------------------
# Palette-aware output for --version, --help, and usage lines.
# ---------------------------------------------------------------------------


def _print_version(stream: IO[Any]) -> None:
    cli_help.print_version_line(
        stream, prog=PROG, version=__version__, tagline=TAGLINE
    )


def _print_usage(stream: IO[Any]) -> None:
    p = _palette.for_stream(stream)
    stream.write(
        f"{p.BOLD}Usage:{p.RESET} "
        f"{p.BLUE}{PROG}{p.RESET} "
        f"[{p.GREEN}-h{p.RESET}] "
        f"[{p.GREEN}-v{p.RESET}] "
        f"[{p.YELLOW}CONFIG{p.RESET}]\n"
    )
    stream.flush()


def _print_help(stream: IO[Any]) -> None:
    p = _palette.for_stream(stream)
    w = stream.write

    _print_usage(stream)
    w("\n")
    w(
        "Forensic PST message extractor. Reads a TOML config that "
        "specifies an input PST,\n"
        "output directory, and match mode, and writes intact "
        ".eml files plus a\n"
        "TSV manifest and a run log.\n"
    )
    w("\n")

    w(f"{p.BOLD}Positional arguments:{p.RESET}\n")
    cli_help.help_row(stream, p, f"{p.YELLOW}CONFIG{p.RESET}",
                      "Path to the TOML config file describing the extraction.")
    w("\n")

    w(f"{p.BOLD}Options:{p.RESET}\n")
    cli_help.help_row(stream, p, f"{p.GREEN}-h{p.RESET}, {p.GREEN}--help{p.RESET}",
                      "Show this help message and exit.")
    cli_help.help_row(stream, p, f"{p.GREEN}-v{p.RESET}, {p.GREEN}--version{p.RESET}",
                      "Show version and exit.")
    w("\n")

    w(f"{p.BOLD}Notes:{p.RESET}\n")
    w(f"  {p.DIM}All timestamps in output are UTC.{p.RESET}\n")
    w(
        f"  {p.DIM}NO_COLOR / PST_SLICER_NO_COLOR disable color; "
        f"FORCE_COLOR / PST_SLICER_FORCE_COLOR force it.{p.RESET}\n"
    )
    stream.flush()


def _build_parser() -> cli_help.ColoredArgParser:
    parser = cli_help.build_parser(
        prog=PROG,
        version_printer=_print_version,
        usage_printer=_print_usage,
        help_printer=_print_help,
    )
    parser.add_argument(
        "config",
        nargs="?",
        metavar="CONFIG",
        help="Path to the TOML config file describing the extraction.",
    )
    return parser


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not args.config:
        _print_usage(sys.stderr)
        log.err("Missing CONFIG argument. Try `pst-slicer --help`.")
        return 2

    config_path = Path(args.config).expanduser().resolve()
    if not config_path.is_file():
        log.err(f"Config file not found: {config_path}")
        return 2

    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        log.err(f"Config error: {exc}")
        return 2

    try:
        result = run_extraction(cfg)
    except ExtractionError as exc:
        log.err(f"Extraction failed: {exc}")
        return 1
    except KeyboardInterrupt:
        log.err("Interrupted by user.")
        return 130

    return 0 if result.matched > 0 else 3
