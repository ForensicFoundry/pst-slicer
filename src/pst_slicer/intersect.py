# SPDX-License-Identifier: GPL-3.0-or-later
"""Cross-PST IMID-not-found intersection.

Given two or more TOML configs that were used for parallel
``pst-slicer`` runs against slices of the same mailbox, compute the
set of IMIDs that were **not** matched in **any** of the runs (i.e.
the intersection of every run's ``not_found.txt``), and produce two
audit artifacts:

  - ``unmatched_across_all_psts.txt`` : one IMID per line, original
                                        spelling, sorted case-insensitively.
  - ``unmatched_summary.txt``          : counts + provenance record.

Design notes:

* All configs MUST be ``mode.type = "IMID"`` and MUST agree on the
  IMID universe (i.e. the same normalized set of targets). If they
  disagree, we fail with exit code 2 rather than silently unioning -
  a cross-PST intersection only makes sense when every run was
  hunting the same list.

* IMID normalization matches the tool's own
  (``config._normalize_imid``): strip whitespace, strip one pair of
  angle brackets, casefold.

* Artifact placement: the default output directory is the common
  parent of every run's output directory (e.g. runs at
  ``.../imid/001``, ``.../imid/002``, ``.../imid/003`` -> artifacts
  at ``.../imid/``). Override with ``-o/--output-dir``.

Exit codes:
    0  Analysis completed and artifacts written.
    2  Setup / input problem (bad config, mixed universes, missing
       not_found.txt, unwritable output dir, ...).
  130  Interrupted by user (Ctrl-C).
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Iterable

from . import __version__, cli_help, log
from . import palette as _palette
from .config import Config, ConfigError, ImidModeConfig, load_config


PROG = "pst-slicer-intersect"
TAGLINE = "Cross-PST IMID not-found intersection"


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
        _check_imid_mode(configs)
        universe = _check_shared_universe(configs)
        per_run = _load_not_found_sets(configs)
    except IntersectSetupError as exc:
        log.err(str(exc))
        return 2
    except KeyboardInterrupt:
        return _handle_interrupt()

    output_dir = _resolve_output_dir(args.output_dir, configs)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.err(f"cannot create output dir {output_dir}: {exc}")
        return 2

    try:
        report = _compute(configs, universe, per_run)
    except KeyboardInterrupt:
        return _handle_interrupt()

    try:
        _write_artifacts(report, output_dir)
        _render_report(report, output_dir)
    except KeyboardInterrupt:
        return _handle_interrupt()
    return 0


def _handle_interrupt() -> int:
    log.progress_end()
    log.err("Interrupted by user.")
    return 130


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class IntersectSetupError(RuntimeError):
    """Raised when the analysis cannot begin (misconfigured inputs)."""


@dataclass
class RunSlice:
    """Per-config metadata + normalized not_found set."""

    config: Config
    not_found_norm: frozenset[str]

    @property
    def label(self) -> str:
        """Short label used in reports. Uses the config file's stem."""
        return self.config.config_path.stem


@dataclass
class IntersectReport:
    slices: list[RunSlice]
    universe_norm: frozenset[str]  # normalized IMIDs
    universe_norm_to_original: dict[str, str]  # normalized -> first-seen spelling
    missing_from_all: frozenset[str]  # normalized
    matched_in_all: frozenset[str]  # normalized
    matched_in_exactly_k: dict[int, frozenset[str]]  # k -> normalized set
    matched_only_in: dict[str, frozenset[str]]  # slice label -> normalized set

    @property
    def total(self) -> int:
        return len(self.universe_norm)

    def missing_originals(self) -> list[str]:
        """Return the not-found IMIDs in original spelling, sorted."""
        return sorted(
            (self.universe_norm_to_original[n] for n in self.missing_from_all),
            key=lambda s: s.casefold(),
        )


# ---------------------------------------------------------------------------
# Loading + validation
# ---------------------------------------------------------------------------


def _load_configs(paths: list[Path]) -> list[Config]:
    if len(paths) < 2:
        raise ConfigError(
            "pst-slicer-intersect requires at least two config files "
            "(one per parallel PST run)."
        )
    configs: list[Config] = []
    for p in paths:
        resolved = p.expanduser().resolve()
        if not resolved.is_file():
            raise ConfigError(f"Config file not found: {resolved}")
        configs.append(load_config(resolved))
    return configs


def _check_imid_mode(configs: list[Config]) -> None:
    bad = [c for c in configs if c.mode_type != "IMID"]
    if bad:
        names = ", ".join(str(c.config_path) for c in bad)
        raise IntersectSetupError(
            "pst-slicer-intersect only supports IMID-mode runs. "
            f"Non-IMID configs: {names}"
        )


def _check_shared_universe(configs: list[Config]) -> frozenset[str]:
    """Every config must reference the same IMID set (normalized). Return that set."""
    normalized_sets: list[frozenset[str]] = []
    for c in configs:
        assert isinstance(c.mode, ImidModeConfig)
        normalized_sets.append(frozenset(_normalize_imid(x) for x in c.mode.imids))
    universe = normalized_sets[0]
    for c, s in zip(configs[1:], normalized_sets[1:]):
        if s != universe:
            only_a = universe - s
            only_b = s - universe
            raise IntersectSetupError(
                f"Config {configs[0].config_path} and {c.config_path} do not "
                f"agree on the IMID universe: "
                f"{len(only_a):,} in first only, {len(only_b):,} in second only. "
                "All runs to be intersected must have used the same target list."
            )
    return universe


def _load_not_found_sets(configs: list[Config]) -> list[RunSlice]:
    slices: list[RunSlice] = []
    for c in configs:
        nf_path = c.output_dir / "not_found.txt"
        if not nf_path.is_file():
            raise IntersectSetupError(
                f"not_found.txt missing from run output dir: {nf_path} "
                f"(expected because config {c.config_path} declared "
                f"output.dir = {c.output_dir})"
            )
        norm: set[str] = set()
        for line in nf_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s:
                continue
            norm.add(_normalize_imid(s))
        slices.append(RunSlice(config=c, not_found_norm=frozenset(norm)))
    return slices


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def _compute(
    configs: list[Config],
    universe: frozenset[str],
    slices: list[RunSlice],
) -> IntersectReport:
    # Preserve first-seen original spelling for each normalized IMID so the
    # produced artifact matches the input file's presentation.
    universe_norm_to_original: dict[str, str] = {}
    for c in configs:
        assert isinstance(c.mode, ImidModeConfig)
        for raw in c.mode.imids:
            n = _normalize_imid(raw)
            if n and n not in universe_norm_to_original:
                universe_norm_to_original[n] = raw

    not_found_sets = [s.not_found_norm for s in slices]

    # IMID missing from ALL runs = intersection of all not_found sets.
    missing_from_all = frozenset.intersection(*not_found_sets)

    # IMID matched in ALL runs = universe - union of not_found sets.
    matched_in_all = universe - frozenset.union(*not_found_sets)

    # For each run: IMIDs matched ONLY in that run (in universe, absent from
    # its own not_found, present in every OTHER run's not_found).
    matched_only_in: dict[str, frozenset[str]] = {}
    for i, s in enumerate(slices):
        others = [o.not_found_norm for j, o in enumerate(slices) if j != i]
        only_here = (universe - s.not_found_norm) & frozenset.intersection(*others)
        matched_only_in[s.label] = only_here

    # Bucket by count of runs that matched.
    matched_in_exactly_k: dict[int, set[str]] = {k: set() for k in range(len(slices) + 1)}
    for imid in universe:
        matched_count = sum(1 for s in slices if imid not in s.not_found_norm)
        matched_in_exactly_k[matched_count].add(imid)
    matched_in_exactly_k_frozen = {
        k: frozenset(v) for k, v in matched_in_exactly_k.items()
    }

    return IntersectReport(
        slices=slices,
        universe_norm=universe,
        universe_norm_to_original=universe_norm_to_original,
        missing_from_all=missing_from_all,
        matched_in_all=matched_in_all,
        matched_in_exactly_k=matched_in_exactly_k_frozen,
        matched_only_in=matched_only_in,
    )


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


def _write_artifacts(report: IntersectReport, output_dir: Path) -> None:
    list_path = output_dir / "unmatched_across_all_psts.txt"
    sum_path = output_dir / "unmatched_summary.txt"

    originals = report.missing_originals()
    list_path.write_text(
        ("\n".join(originals) + "\n") if originals else "",
        encoding="utf-8",
    )

    now = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("pst-slicer cross-PST not-found intersection")
    lines.append("=" * 46)
    lines.append(f"generated_utc         : {now}")
    lines.append(f"tool_version          : pst-slicer-intersect {__version__}")
    lines.append(f"runs_analyzed         :")
    for s in report.slices:
        lines.append(f"  - config     : {s.config.config_path}")
        lines.append(f"    output_dir : {s.config.output_dir}")
        lines.append(f"    input_pst  : {s.config.input_pst}")
    lines.append("")
    lines.append("Counts")
    lines.append("-" * 46)
    lines.append(f"universe (unique IMIDs)             : {report.total:>7,}")
    lines.append(f"missing from ALL runs               : {len(report.missing_from_all):>7,}")
    lines.append(
        f"matched in AT LEAST ONE run         : "
        f"{report.total - len(report.missing_from_all):>7,}"
    )
    lines.append(f"matched in ALL runs                 : {len(report.matched_in_all):>7,}")
    for s in report.slices:
        lines.append(
            f"matched only in run {s.label:<20}: "
            f"{len(report.matched_only_in[s.label]):>7,}"
        )
    lines.append("")
    lines.append("Distribution by match count (k = number of runs that matched):")
    for k in sorted(report.matched_in_exactly_k):
        lines.append(f"  k = {k}                              : "
                     f"{len(report.matched_in_exactly_k[k]):>7,}")
    lines.append("")
    lines.append("Artifacts")
    lines.append("-" * 46)
    lines.append(f"unmatched_across_all_psts.txt       : {list_path}")
    lines.append(f"unmatched_summary.txt               : {sum_path}")
    lines.append("")
    sum_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _render_report(report: IntersectReport, output_dir: Path) -> None:
    log.header(f"pst-slicer-intersect v{__version__}")
    log.kv("runs analyzed", str(len(report.slices)))
    for s in report.slices:
        log.kv(f"  {s.label}", str(s.config.output_dir))

    log.header("Counts")
    log.kv("universe (unique IMIDs)", f"{report.total:,}")
    log.kv("MISSING FROM ALL RUNS", f"{len(report.missing_from_all):,}")
    log.kv(
        "matched in at least one run",
        f"{report.total - len(report.missing_from_all):,}",
    )
    log.kv("matched in all runs", f"{len(report.matched_in_all):,}")
    for s in report.slices:
        log.kv(
            f"matched only in {s.label}",
            f"{len(report.matched_only_in[s.label]):,}",
        )

    log.header("Match-count distribution (k = number of runs that matched)")
    for k in sorted(report.matched_in_exactly_k):
        log.kv(f"k = {k}", f"{len(report.matched_in_exactly_k[k]):,}")

    log.header("Artifacts")
    log.kv("output dir", str(output_dir))
    log.kv("list file", str(output_dir / "unmatched_across_all_psts.txt"))
    log.kv("summary file", str(output_dir / "unmatched_summary.txt"))

    if report.missing_from_all:
        log.warn(
            f"{len(report.missing_from_all):,} IMID(s) were not found in ANY run; "
            "see unmatched_across_all_psts.txt"
        )
    else:
        log.ok("every IMID in the target list matched in at least one run")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_imid(value: str) -> str:
    """Match pst-slicer's own IMID normalization (config._normalize_imid)."""
    v = value.strip()
    if v.startswith("<") and v.endswith(">") and len(v) >= 2:
        v = v[1:-1].strip()
    return v.casefold()


def _resolve_output_dir(explicit: str | None, configs: list[Config]) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    # Default: common ancestor of every run's output directory. On our
    # sample case that's ``.../imid/`` when the runs live at
    # ``.../imid/001``, ``.../imid/002``, ``.../imid/003``.
    common = os.path.commonpath([str(c.output_dir) for c in configs])
    return Path(common).resolve()


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
        f"[{p.GREEN}-o {p.YELLOW}DIR{p.RESET}] "
        f"{p.YELLOW}CONFIG{p.RESET} {p.YELLOW}CONFIG{p.RESET} "
        f"[{p.YELLOW}CONFIG{p.RESET} ...]\n"
    )
    stream.flush()


def _print_help(stream: IO[Any]) -> None:
    p = _palette.for_stream(stream)
    w = stream.write

    _print_usage(stream)
    w("\n")
    w(
        "Compute the set of IMIDs that were not matched in ANY of\n"
        "several parallel pst-slicer runs. Point at the same TOML\n"
        "configs that were used for the runs; the tool resolves each\n"
        "run's output.dir/not_found.txt and intersects them. Writes:\n"
        "\n"
        "  unmatched_across_all_psts.txt  one IMID per line, sorted\n"
        "  unmatched_summary.txt          counts + provenance record\n"
        "\n"
        "All configs must be mode.type = \"IMID\" and must agree on the\n"
        "IMID universe. Otherwise the run is refused (exit 2) rather\n"
        "than silently unioning inputs.\n"
    )
    w("\n")

    w(f"{p.BOLD}Positional arguments:{p.RESET}\n")
    cli_help.help_row(
        stream, p, f"{p.YELLOW}CONFIG{p.RESET}",
        "Two or more IMID-mode TOML configs, one per parallel run.",
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
        stream,
        p,
        f"{p.GREEN}-o{p.RESET}, {p.GREEN}--output-dir {p.YELLOW}DIR{p.RESET}",
        "Directory for the artifacts. Default: the common parent",
    )
    cli_help.help_row(stream, p, "", "of every run's output.dir.")
    w("\n")

    w(f"{p.BOLD}Exit codes:{p.RESET}\n")
    cli_help.help_row(stream, p, f"{p.GREEN}0{p.RESET}", "Analysis complete; artifacts written.")
    cli_help.help_row(stream, p, f"{p.GREEN}2{p.RESET}",
                      "Setup problem (bad config, mixed IMID universes, ...).")
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
        "-o",
        "--output-dir",
        default=None,
        metavar="DIR",
        help=(
            "Directory to write the intersection artifacts into. "
            "Defaults to the common parent of every run's output.dir."
        ),
    )
    parser.add_argument(
        "configs",
        nargs="+",
        metavar="CONFIG",
        help="Two or more IMID-mode TOML configs, one per parallel run.",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
