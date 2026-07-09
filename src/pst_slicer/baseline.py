# SPDX-License-Identifier: GPL-3.0-or-later
"""Chain-of-custody baselining for pst-slicer inputs.

Purpose
-------
Before running an extraction, capture an immutable record of every
input file the run will touch: the source PST(s) and any IMID list
files. The record contains, per file:

* absolute path
* size in bytes
* modification time (UTC)
* SHA-256

Later, ``--verify`` mode reads that record back and recomputes each
hash against the current on-disk state, so we can prove the evidence
files have not been altered between baselining and extraction.

Why a separate tool?
--------------------
``pst-slicer`` already records ``input_pst_sha256`` in ``run.log`` at
extraction time, and ``pst-slicer-verify`` re-checks that value after
the run. But there is a window BEFORE the extraction begins - while
the analyst is still setting up the case file, writing configs,
sanity-checking IMID lists, etc. - during which we have no committed
record of what the evidence looked like when it arrived.
``pst-slicer-baseline`` closes that window.

Output artifact
---------------
``BASELINE.txt``. One file per baselining event, written to:

* ``<output.dir>/BASELINE.txt`` when exactly one config is baselined
  (co-locates with the run outputs that will land there later), OR
* the common parent of every config's ``output.dir`` when multiple
  configs are baselined, OR
* ``-o/--output-dir`` when specified explicitly.

The file is human-readable, deterministic (given the same inputs), and
machine-parseable by this tool's ``--verify`` code path. It records
tool + platform provenance in addition to the file fingerprints.

Exit codes
----------
* ``0``   Baseline written (default mode) or all files match (--verify).
* ``1``   ``--verify``: at least one file mismatch.
* ``2``   Setup problem (bad config, unwritable output dir, missing
          baseline in --verify mode, ...).
* ``130`` Interrupted by user (Ctrl-C).
"""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import os
import platform
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Iterable

from . import __version__, cli_help, log
from . import palette as _palette
from .config import Config, ConfigError, ImidModeConfig, load_config


PROG = "pst-slicer-baseline"
TAGLINE = "Chain-of-custody baselining for pst-slicer inputs"
BASELINE_FILENAME = "BASELINE.txt"
_CHUNK = 1024 * 1024  # 1 MiB hashing chunks


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class BaselineEntry:
    role: str  # "input_pst" | "imid_list"
    path: Path
    size_bytes: int
    mtime_utc: _dt.datetime
    sha256: str
    hash_duration_seconds: float
    configs: list[Path] = field(default_factory=list)


@dataclass
class BaselineReport:
    generated_utc: _dt.datetime
    tool_version: str
    hostname: str
    user: str
    python_version: str
    platform_str: str
    configs: list[Path]
    entries: list[BaselineEntry]


class BaselineSetupError(RuntimeError):
    """Raised when baselining cannot begin (bad inputs / IO / config)."""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        configs = _load_configs([Path(c) for c in args.configs])
    except ConfigError as exc:
        log.err(str(exc))
        return 2
    except KeyboardInterrupt:
        return _handle_interrupt()

    try:
        entries_plan = _plan_entries(configs)
    except BaselineSetupError as exc:
        log.err(str(exc))
        return 2

    output_dir = _resolve_output_dir(args.output_dir, configs)
    baseline_path = output_dir / BASELINE_FILENAME

    try:
        if args.verify:
            return _run_verify_mode(baseline_path, entries_plan, configs)
        return _run_write_mode(
            baseline_path=baseline_path,
            entries_plan=entries_plan,
            configs=configs,
            force=args.force,
        )
    except KeyboardInterrupt:
        return _handle_interrupt()


def _handle_interrupt() -> int:
    log.progress_end()
    log.err("Interrupted by user.")
    return 130


# ---------------------------------------------------------------------------
# Planning: figure out what files each config exposes for baselining
# ---------------------------------------------------------------------------


def _load_configs(paths: list[Path]) -> list[Config]:
    if not paths:
        raise ConfigError(
            "pst-slicer-baseline requires at least one config file."
        )
    configs: list[Config] = []
    for p in paths:
        resolved = p.expanduser().resolve()
        if not resolved.is_file():
            raise ConfigError(f"Config file not found: {resolved}")
        configs.append(load_config(resolved))
    return configs


@dataclass
class _PlannedFile:
    role: str
    path: Path
    configs: list[Path]


def _plan_entries(configs: list[Config]) -> list[_PlannedFile]:
    """Return the deduped list of files to baseline, in stable order.

    Each config contributes:
      * ``input.pst``  -> role ``input_pst``
      * ``mode.imid.file`` (when IMID mode was fed from a file, not an
                            inline list) -> role ``imid_list``

    If the same path is referenced by multiple configs (e.g.
    all three PSTs share one IMID list), it appears once with every
    referencing config recorded.
    """
    plan: dict[Path, _PlannedFile] = {}

    for c in configs:
        _add(plan, "input_pst", c.input_pst, c.config_path)
        if isinstance(c.mode, ImidModeConfig) and c.mode.source != "inline":
            _add(plan, "imid_list", Path(c.mode.source), c.config_path)

    # Deterministic order: role first (PSTs before lists), then path.
    ordered = sorted(
        plan.values(), key=lambda e: (0 if e.role == "input_pst" else 1, str(e.path))
    )

    if not ordered:
        raise BaselineSetupError(
            "Nothing to baseline: none of the supplied configs declare "
            "input.pst or an on-disk imid list."
        )

    for planned in ordered:
        if not planned.path.is_file():
            raise BaselineSetupError(
                f"{planned.role} does not exist: {planned.path} "
                f"(referenced by {planned.configs[0]})"
            )
    return ordered


def _add(
    plan: dict[Path, _PlannedFile],
    role: str,
    raw_path: Path,
    config_path: Path,
) -> None:
    key = raw_path.expanduser().resolve()
    existing = plan.get(key)
    if existing is None:
        plan[key] = _PlannedFile(role=role, path=key, configs=[config_path])
        return
    if config_path not in existing.configs:
        existing.configs.append(config_path)


def _resolve_output_dir(explicit: str | None, configs: list[Config]) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    if len(configs) == 1:
        return configs[0].output_dir
    common = os.path.commonpath([str(c.output_dir) for c in configs])
    return Path(common).resolve()


# ---------------------------------------------------------------------------
# Write mode
# ---------------------------------------------------------------------------


def _run_write_mode(
    *,
    baseline_path: Path,
    entries_plan: list[_PlannedFile],
    configs: list[Config],
    force: bool,
) -> int:
    log.header(f"pst-slicer-baseline v{__version__}")
    log.kv("output file", str(baseline_path))
    log.kv("files to baseline", str(len(entries_plan)))
    for planned in entries_plan:
        log.kv(f"  {planned.role}", str(planned.path))

    if baseline_path.exists() and not force:
        log.err(
            f"{baseline_path} already exists. Re-run with --force to overwrite, "
            "or delete the file first."
        )
        return 2

    try:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.err(f"cannot create output dir {baseline_path.parent}: {exc}")
        return 2

    entries: list[BaselineEntry] = []
    for i, planned in enumerate(entries_plan, start=1):
        log.note(
            f"[{i}/{len(entries_plan)}] hashing {planned.role}: {planned.path}"
        )
        try:
            entries.append(_hash_file(planned))
        except OSError as exc:
            log.err(f"cannot read {planned.path}: {exc}")
            return 2

    report = _build_report(configs=configs, entries=entries)
    text = _render_baseline_txt(report)

    tmp = baseline_path.with_suffix(baseline_path.suffix + ".partial")
    try:
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, baseline_path)
    except OSError as exc:
        log.err(f"cannot write {baseline_path}: {exc}")
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return 2

    log.header("Baseline written")
    log.kv("BASELINE.txt", str(baseline_path))
    log.kv("baseline sha256", hashlib.sha256(text.encode("utf-8")).hexdigest())
    log.ok("chain-of-custody snapshot captured")
    return 0


# ---------------------------------------------------------------------------
# Verify mode
# ---------------------------------------------------------------------------


def _run_verify_mode(
    baseline_path: Path,
    entries_plan: list[_PlannedFile],
    configs: list[Config],
) -> int:
    del entries_plan, configs  # supplied for schema symmetry; not used here.
    log.header(f"pst-slicer-baseline v{__version__} - verify mode")
    log.kv("baseline file", str(baseline_path))

    if not baseline_path.is_file():
        log.err(f"{baseline_path} does not exist. Run without --verify first.")
        return 2

    try:
        recorded = _parse_baseline_txt(baseline_path)
    except BaselineParseError as exc:
        log.err(f"cannot parse {baseline_path}: {exc}")
        return 2

    log.kv("recorded entries", str(len(recorded)))
    if not recorded:
        log.err("baseline file contains no file entries.")
        return 2

    failures: list[str] = []
    for i, entry in enumerate(recorded, start=1):
        log.note(f"[{i}/{len(recorded)}] verifying {entry.role}: {entry.path}")
        if not entry.path.is_file():
            failures.append(f"MISSING: {entry.path}")
            log.err(f"  file missing on disk: {entry.path}")
            continue
        try:
            cur = _hash_path(entry.path)
        except OSError as exc:
            failures.append(f"UNREADABLE: {entry.path} ({exc})")
            log.err(f"  cannot re-hash: {exc}")
            continue

        size_ok = cur.size_bytes == entry.size_bytes
        hash_ok = cur.sha256 == entry.sha256
        if size_ok and hash_ok:
            log.ok(f"  match (size {cur.size_bytes:,} bytes, sha256 {cur.sha256[:12]}...)")
            continue
        failures.append(str(entry.path))
        if not size_ok:
            log.err(
                f"  size mismatch: baseline={entry.size_bytes:,} current={cur.size_bytes:,}"
            )
        if not hash_ok:
            log.err(f"  sha256 mismatch:")
            log.err(f"    baseline: {entry.sha256}")
            log.err(f"    current:  {cur.sha256}")

    log.header("Verification result")
    log.kv("total entries", str(len(recorded)))
    log.kv("mismatches / missing", str(len(failures)))
    if failures:
        log.err("BASELINE VERIFY: FAIL")
        return 1
    log.ok("BASELINE VERIFY: PASS")
    return 0


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


@dataclass
class _HashedFile:
    size_bytes: int
    sha256: str
    mtime_utc: _dt.datetime
    duration_seconds: float


def _hash_file(planned: _PlannedFile) -> BaselineEntry:
    hf = _hash_path(planned.path)
    return BaselineEntry(
        role=planned.role,
        path=planned.path,
        size_bytes=hf.size_bytes,
        mtime_utc=hf.mtime_utc,
        sha256=hf.sha256,
        hash_duration_seconds=hf.duration_seconds,
        configs=list(planned.configs),
    )


def _hash_path(path: Path) -> _HashedFile:
    """SHA-256 + size + mtime for ``path``. Streamed in 1 MiB chunks so
    the tool remains bounded in RAM even on 10+ GB PSTs. mtime is read
    once at open-time so it corresponds to the same on-disk state we
    just hashed."""
    st = path.stat()
    mtime_utc = _dt.datetime.fromtimestamp(st.st_mtime, tz=_dt.timezone.utc)
    h = hashlib.sha256()
    t0 = time.perf_counter()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    duration = time.perf_counter() - t0
    return _HashedFile(
        size_bytes=st.st_size,
        sha256=h.hexdigest(),
        mtime_utc=mtime_utc,
        duration_seconds=duration,
    )


# ---------------------------------------------------------------------------
# Report construction + rendering
# ---------------------------------------------------------------------------


def _build_report(
    *, configs: list[Config], entries: list[BaselineEntry]
) -> BaselineReport:
    now = _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0)
    return BaselineReport(
        generated_utc=now,
        tool_version=__version__,
        hostname=_safe(lambda: socket.gethostname()),
        user=_safe(lambda: getpass.getuser()),
        python_version=platform.python_version(),
        platform_str=f"{platform.system()} {platform.release()} {platform.machine()}",
        configs=[c.config_path for c in configs],
        entries=entries,
    )


def _safe(fn) -> str:
    try:
        return str(fn())
    except Exception:  # pragma: no cover - defensive
        return "unknown"


def _render_baseline_txt(report: BaselineReport) -> str:
    """Format the on-disk representation. Deterministic with respect to
    entry ordering, config ordering, and value formatting so the same
    inputs produce byte-identical files (except for the timestamp header)."""
    lines: list[str] = []
    lines.append(f"pst-slicer baseline v{report.tool_version}")
    lines.append("=" * 60)
    lines.append(f"generated_utc         : {_fmt_dt(report.generated_utc)}")
    lines.append(f"tool_version          : pst-slicer-baseline {report.tool_version}")
    lines.append(f"hostname              : {report.hostname}")
    lines.append(f"user                  : {report.user}")
    lines.append(f"python_version        : {report.python_version}")
    lines.append(f"platform              : {report.platform_str}")
    lines.append("configs_baselined     :")
    for cp in report.configs:
        lines.append(f"  - {cp}")
    lines.append("")

    lines.append("Files")
    lines.append("-" * 60)
    total_bytes = 0
    total_duration = 0.0
    for i, e in enumerate(report.entries, start=1):
        lines.append(f"[{i:03d}] {e.role}")
        if e.configs:
            lines.append(f"  referenced_by : {e.configs[0]}")
            for extra in e.configs[1:]:
                lines.append(f"                : {extra}")
        lines.append(f"  path          : {e.path}")
        lines.append(f"  size_bytes    : {e.size_bytes}")
        lines.append(f"  mtime_utc     : {_fmt_dt(e.mtime_utc)}")
        lines.append(f"  sha256        : {e.sha256}")
        lines.append(f"  hash_seconds  : {e.hash_duration_seconds:.3f}")
        lines.append("")
        total_bytes += e.size_bytes
        total_duration += e.hash_duration_seconds

    lines.append("Summary")
    lines.append("-" * 60)
    lines.append(f"total_files           : {len(report.entries)}")
    lines.append(f"total_bytes_hashed    : {total_bytes}")
    lines.append(f"total_hash_seconds    : {total_duration:.3f}")
    lines.append("")
    lines.append(
        "Notes: sha256 covers the raw file bytes. Compare with "
        "`sha256sum <file>` for independent verification. Re-run with "
        "--verify to recompute against the current on-disk state."
    )
    lines.append("")
    return "\n".join(lines)


def _fmt_dt(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Parser for --verify mode
# ---------------------------------------------------------------------------


class BaselineParseError(ValueError):
    """Raised when BASELINE.txt cannot be parsed."""


_ENTRY_HEADER = re.compile(r"^\[(\d+)\]\s+(\S+)\s*$")
_KV_LINE = re.compile(r"^\s{2}(\S+)\s+:\s+(.*?)\s*$")


def _parse_baseline_txt(path: Path) -> list[BaselineEntry]:
    """Extract file entries from a BASELINE.txt. Only the fields
    ``--verify`` actually needs are populated (role, path, size_bytes,
    sha256, mtime_utc). ``configs``, ``hash_duration_seconds`` are best-
    effort. Robust to added trailing sections and human edits of the
    provenance header."""
    text = path.read_text(encoding="utf-8")
    entries: list[BaselineEntry] = []
    current: dict[str, Any] | None = None

    for raw in text.splitlines():
        header = _ENTRY_HEADER.match(raw)
        if header:
            if current is not None:
                entries.append(_finalize_parsed(current, path))
            current = {"role": header.group(2), "configs": []}
            continue
        if current is None:
            continue  # in the header / summary area
        if not raw.strip():
            # blank line = entry terminator
            entries.append(_finalize_parsed(current, path))
            current = None
            continue
        kv = _KV_LINE.match(raw)
        if kv:
            key, val = kv.group(1), kv.group(2)
            if key == "referenced_by":
                current.setdefault("configs", []).append(Path(val))
            elif key == "" or val == "":
                pass
            else:
                current[key] = val

    if current is not None:
        entries.append(_finalize_parsed(current, path))

    return entries


def _finalize_parsed(current: dict[str, Any], baseline_path: Path) -> BaselineEntry:
    role = current.get("role", "unknown")
    try:
        path_str = current["path"]
        size = int(current["size_bytes"])
        sha256 = current["sha256"]
    except (KeyError, ValueError) as exc:
        raise BaselineParseError(
            f"entry [{current.get('role', '?')}] in {baseline_path} is missing "
            f"required field: {exc}"
        ) from exc
    mtime_raw = current.get("mtime_utc", "1970-01-01 00:00:00 UTC")
    try:
        mtime = _dt.datetime.strptime(mtime_raw, "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=_dt.timezone.utc
        )
    except ValueError:
        mtime = _dt.datetime.fromtimestamp(0, tz=_dt.timezone.utc)

    return BaselineEntry(
        role=role,
        path=Path(path_str),
        size_bytes=size,
        mtime_utc=mtime,
        sha256=sha256,
        hash_duration_seconds=0.0,
        configs=list(current.get("configs", [])),
    )


# ---------------------------------------------------------------------------
# argparse plumbing (colorized via cli_help)
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
        f"[{p.GREEN}--verify{p.RESET}] "
        f"[{p.GREEN}--force{p.RESET}] "
        f"[{p.GREEN}-o {p.YELLOW}DIR{p.RESET}] "
        f"{p.YELLOW}CONFIG{p.RESET} "
        f"[{p.YELLOW}CONFIG{p.RESET} ...]\n"
    )
    stream.flush()


def _print_help(stream: IO[Any]) -> None:
    p = _palette.for_stream(stream)
    w = stream.write

    _print_usage(stream)
    w("\n")
    w(
        "Chain-of-custody baselining for pst-slicer inputs.\n"
        "\n"
        "Given one or more TOML configs, compute SHA-256, size, and\n"
        "mtime for every input file each config references (the source\n"
        "PST and, when applicable, the IMID list file) and write a\n"
        "BASELINE.txt to the output directory. Use --verify to\n"
        "recompute against the current on-disk state and prove the\n"
        "evidence files have not been altered.\n"
    )
    w("\n")

    w(f"{p.BOLD}Positional arguments:{p.RESET}\n")
    cli_help.help_row(
        stream, p, f"{p.YELLOW}CONFIG{p.RESET}",
        "One or more TOML configs to baseline.",
    )
    w("\n")

    w(f"{p.BOLD}Options:{p.RESET}\n")
    cli_help.help_row(
        stream, p, f"{p.GREEN}-h{p.RESET}, {p.GREEN}--help{p.RESET}",
        "Show this help message and exit.",
    )
    cli_help.help_row(
        stream, p, f"{p.GREEN}-v{p.RESET}, {p.GREEN}--version{p.RESET}",
        "Show version and exit.",
    )
    cli_help.help_row(
        stream, p, f"{p.GREEN}--verify{p.RESET}",
        "Recompute hashes and compare against an existing",
    )
    cli_help.help_row(stream, p, "", "BASELINE.txt at the target location.")
    cli_help.help_row(
        stream, p, f"{p.GREEN}--force{p.RESET}",
        "Overwrite an existing BASELINE.txt (write mode only).",
    )
    cli_help.help_row(
        stream,
        p,
        f"{p.GREEN}-o{p.RESET}, {p.GREEN}--output-dir {p.YELLOW}DIR{p.RESET}",
        "Directory to write / read BASELINE.txt. Default:",
    )
    cli_help.help_row(
        stream, p, "",
        "the single config's output.dir, or the common parent",
    )
    cli_help.help_row(stream, p, "", "of every config's output.dir.")
    w("\n")

    w(f"{p.BOLD}Output artifact:{p.RESET}\n")
    w(f"  {p.DIM}<output-dir>/BASELINE.txt{p.RESET}\n")
    w(
        f"    {p.DIM}Human-readable + machine-parseable chain-of-custody\n"
        f"    snapshot. Preserve alongside run.log + verify.log.{p.RESET}\n"
    )
    w("\n")

    w(f"{p.BOLD}Exit codes:{p.RESET}\n")
    cli_help.help_row(stream, p, f"{p.GREEN}0{p.RESET}", "Baseline written / verified OK.")
    cli_help.help_row(stream, p, f"{p.GREEN}1{p.RESET}", "--verify: at least one file mismatch.")
    cli_help.help_row(stream, p, f"{p.GREEN}2{p.RESET}",
                      "Setup problem (bad config, unwritable dir, ...).")
    cli_help.help_row(stream, p, f"{p.GREEN}130{p.RESET}", "Interrupted by user (Ctrl-C).")
    stream.flush()


def _build_parser() -> cli_help.ColoredArgParser:
    parser = cli_help.build_parser(
        prog=PROG,
        version_printer=_print_version,
        usage_printer=_print_usage,
        help_printer=_print_help,
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Recompute hashes against an existing BASELINE.txt.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing BASELINE.txt (write mode).",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        metavar="DIR",
        help=(
            "Directory to write/read BASELINE.txt. Default: the single "
            "config's output.dir, or the common parent of every "
            "config's output.dir."
        ),
    )
    parser.add_argument(
        "configs",
        nargs="+",
        metavar="CONFIG",
        help="One or more TOML configs to baseline.",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
