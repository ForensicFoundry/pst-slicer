# SPDX-License-Identifier: GPL-3.0-or-later
"""Post-run integrity + coercion verification.

Runs the four-check verification protocol against a completed
``pst-slicer`` run. Given the same TOML config used for the
extraction, we resolve the source PST path and the output directory
from the config itself (so this script and the original run cannot
disagree about which files they are talking about), then perform:

1. **Source PST unchanged.**
   Re-hash the source PST and compare its SHA-256 to the value the
   tool wrote into ``run.log`` (``input_pst_sha256``). Also confirm
   the on-disk file size matches ``input_pst_size_bytes``. Proves the
   evidence file was not mutated between extraction and verification.

2. **Manifest / disk / run.log agree on counts.**
   Manifest data-row count MUST equal the number of ``.eml`` files
   under the output tree, and BOTH must equal the ``eml_files_written``
   counter in ``run.log``. Detects orphaned files, missing files,
   truncated manifests, and any drift between the three views.

3. **Every EML matches its manifest fingerprint.**
   For every row in the manifest, re-read the EML from disk, recompute
   its SHA-256 and byte size, and compare to the ``sha256`` and
   ``size_bytes`` columns. This is the cryptographic proof that the
   manifest is truthful.

4. **Coercion audit.**
   Scan every extracted EML for ``X-PstSlicer-Original-Content-Type``
   and ``X-PstSlicer-Original-Filename`` annotations, report how many
   messages contained coerced attachments, and summarize the
   distribution of what was coerced. Provides the forensic-audit
   record of the sanitization mechanism described in ``README.md``.

Exit codes:
    0  All four checks passed.
    1  At least one check failed.
    2  Verification could not run (config problem, run.log missing,
       manifest missing, ...).
"""

from __future__ import annotations

import atexit
import csv
import hashlib
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Iterable

from . import __version__, cli_help, log
from . import palette as _palette
from .config import ConfigError, load_config


PROG = "pst-slicer-verify"
TAGLINE = "Post-run integrity + coercion verification for a pst-slicer run"
LOG_FILENAME = "verify.log"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    config_path = Path(args.config).expanduser().resolve()
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        log.err(str(exc))
        return 2
    except KeyboardInterrupt:
        return _handle_interrupt()

    # Auto-capture the terminal session to <output_dir>/verify.log unless
    # explicitly disabled. Everything printed from this point on lands in
    # both the TTY (colorized) and the log file (ANSI-stripped, grep-friendly).
    if not args.no_log:
        log_path = cfg.output_dir / LOG_FILENAME
        try:
            cfg.output_dir.mkdir(parents=True, exist_ok=True)
            log.install_capture(log_path)
            atexit.register(log.uninstall_capture)
        except OSError as exc:
            log.err(f"cannot write log file {log_path}: {exc}")
            return 2

    try:
        report = verify(
            input_pst=cfg.input_pst,
            output_dir=cfg.output_dir,
        )
    except VerificationSetupError as exc:
        log.err(str(exc))
        return 2
    except KeyboardInterrupt:
        return _handle_interrupt()

    try:
        _render_report(report)
    except KeyboardInterrupt:
        return _handle_interrupt()

    log.uninstall_capture()
    return 0 if report.ok else 1


def _handle_interrupt() -> int:
    """Emit a clean interrupt line (blanking any live progress row) and
    return the SIGINT-conventional exit code 130 (128 + 2). Called from
    every ``KeyboardInterrupt`` handler in this module so we never dump
    a Python traceback on the analyst's screen when they Ctrl-C out of
    a long-running check."""
    log.progress_end()
    log.err("Interrupted by user.")
    log.uninstall_capture()
    return 130


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class VerificationSetupError(RuntimeError):
    """Raised when verification could not even begin (missing run.log,
    missing manifest, unreadable output dir, etc.)."""


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: list[str]


@dataclass
class VerificationReport:
    config_path: Path
    input_pst: Path
    output_dir: Path
    checks: list[CheckResult]

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


# ---------------------------------------------------------------------------
# Check driver
# ---------------------------------------------------------------------------


def verify(*, input_pst: Path, output_dir: Path) -> VerificationReport:
    manifest_path = output_dir / "manifest.tsv"
    run_log_path = output_dir / "run.log"

    if not output_dir.is_dir():
        raise VerificationSetupError(f"Output directory does not exist: {output_dir}")
    if not manifest_path.is_file():
        raise VerificationSetupError(f"manifest.tsv not found under {output_dir}")
    if not run_log_path.is_file():
        raise VerificationSetupError(f"run.log not found under {output_dir}")

    run_log = _parse_run_log(run_log_path)

    log.header(f"pst-slicer verify v{__version__}")
    log.kv("config-derived input PST", str(input_pst))
    log.kv("config-derived output dir", str(output_dir))
    log.kv("run.log tool version", run_log.get("tool_version", "?"))
    log.kv("run.log started_utc", run_log.get("started_utc", "?"))
    log.kv("run.log ended_utc", run_log.get("ended_utc", "?"))

    checks: list[CheckResult] = []
    checks.append(_check_source_unchanged(input_pst, run_log))
    checks.append(_check_counts(output_dir, manifest_path, run_log))
    checks.append(_check_manifest_vs_disk(output_dir, manifest_path))
    checks.append(_coercion_audit(output_dir))

    return VerificationReport(
        config_path=Path.cwd(),  # display only
        input_pst=input_pst,
        output_dir=output_dir,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# Check 1 - source PST unchanged
# ---------------------------------------------------------------------------


def _check_source_unchanged(input_pst: Path, run_log: dict[str, str]) -> CheckResult:
    log.header("Check 1 / 4 - source PST unchanged (read-only proof)")

    detail: list[str] = []
    expected_sha = run_log.get("input_pst_sha256", "").strip()
    expected_size = run_log.get("input_pst_size_bytes", "").strip()

    if not expected_sha:
        return CheckResult(
            name="source-unchanged",
            ok=False,
            detail=["run.log did not record input_pst_sha256"],
        )
    if not input_pst.is_file():
        return CheckResult(
            name="source-unchanged",
            ok=False,
            detail=[f"source PST does not exist: {input_pst}"],
        )

    log.note(f"re-hashing source PST (may take a while on large PSTs): {input_pst}")
    actual_size = input_pst.stat().st_size
    actual_sha = _sha256_file(input_pst)

    detail.append(f"expected SHA-256 : {expected_sha}")
    detail.append(f"actual   SHA-256 : {actual_sha}")
    detail.append(f"expected size    : {expected_size}")
    detail.append(f"actual   size    : {actual_size}")

    sha_ok = actual_sha == expected_sha
    size_ok = not expected_size or str(actual_size) == expected_size

    if sha_ok and size_ok:
        log.ok("source PST byte-identical to pre-run baseline")
    else:
        if not sha_ok:
            log.err("source PST SHA-256 has drifted since the run")
        if not size_ok:
            log.err("source PST byte size has drifted since the run")

    return CheckResult(
        name="source-unchanged",
        ok=sha_ok and size_ok,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Check 2 - count agreement across manifest / disk / run.log
# ---------------------------------------------------------------------------


def _check_counts(
    output_dir: Path, manifest_path: Path, run_log: dict[str, str]
) -> CheckResult:
    log.header("Check 2 / 4 - manifest / disk / run.log count agreement")

    with manifest_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        try:
            next(reader)  # header
        except StopIteration:
            return CheckResult(
                name="counts",
                ok=False,
                detail=["manifest.tsv is empty (no header row)"],
            )
        manifest_rows = sum(1 for _ in reader)

    eml_on_disk = sum(1 for _ in output_dir.rglob("*.eml"))

    expected_written_raw = run_log.get("eml_files_written", "").strip()
    try:
        expected_written = int(expected_written_raw)
    except ValueError:
        expected_written = None

    detail = [
        f"manifest data rows : {manifest_rows:,}",
        f"eml files on disk  : {eml_on_disk:,}",
        f"run.log written    : {expected_written_raw or '?'}",
    ]

    if (
        expected_written is not None
        and manifest_rows == eml_on_disk == expected_written
    ):
        log.ok(
            f"manifest ({manifest_rows:,}) == on-disk ({eml_on_disk:,}) "
            f"== run.log ({expected_written:,})"
        )
        return CheckResult(name="counts", ok=True, detail=detail)

    log.err("count disagreement")
    if expected_written is not None:
        if manifest_rows != expected_written:
            log.err(
                f"manifest rows ({manifest_rows:,}) != run.log eml_files_written "
                f"({expected_written:,})"
            )
        if eml_on_disk != expected_written:
            log.err(
                f"eml files on disk ({eml_on_disk:,}) != run.log eml_files_written "
                f"({expected_written:,})"
            )
    if manifest_rows != eml_on_disk:
        log.err(
            f"manifest rows ({manifest_rows:,}) != eml files on disk ({eml_on_disk:,})"
        )
    return CheckResult(name="counts", ok=False, detail=detail)


# ---------------------------------------------------------------------------
# Check 3 - every EML's SHA-256 + size matches manifest
# ---------------------------------------------------------------------------


def _check_manifest_vs_disk(output_dir: Path, manifest_path: Path) -> CheckResult:
    log.header("Check 3 / 4 - manifest fingerprints vs on-disk EML bytes")

    verified = 0
    missing: list[str] = []
    sha_mismatches: list[tuple[str, str, str]] = []
    size_mismatches: list[tuple[str, str, int]] = []
    unreadable: list[tuple[str, str]] = []

    with manifest_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        total_rows = 0
        for row in reader:
            total_rows += 1
            if total_rows % 500 == 0:
                log.progress(
                    f"verified {verified:,} / {total_rows:,} rows"
                )
            rel = row.get("output_path") or ""
            eml_path = output_dir / rel
            if not eml_path.is_file():
                missing.append(rel)
                continue
            try:
                data = eml_path.read_bytes()
            except OSError as exc:
                unreadable.append((rel, str(exc)))
                continue
            actual_sha = hashlib.sha256(data).hexdigest()
            actual_size = len(data)
            expected_sha = (row.get("sha256") or "").strip()
            expected_size_raw = (row.get("size_bytes") or "").strip()
            if actual_sha != expected_sha:
                sha_mismatches.append((rel, expected_sha, actual_sha))
                continue
            try:
                expected_size = int(expected_size_raw)
            except ValueError:
                expected_size = -1
            if expected_size != actual_size:
                size_mismatches.append((rel, expected_size_raw, actual_size))
                continue
            verified += 1

    log.progress(f"verified {verified:,} / {total_rows:,} rows")
    log.progress_end()

    detail = [
        f"verified            : {verified:,}",
        f"missing files       : {len(missing):,}",
        f"sha256 mismatches   : {len(sha_mismatches):,}",
        f"size mismatches     : {len(size_mismatches):,}",
        f"unreadable          : {len(unreadable):,}",
    ]

    if missing or sha_mismatches or size_mismatches or unreadable:
        log.err("one or more EML files failed cryptographic verification")
        for m in missing[:10]:
            log.err(f"missing on disk: {m}")
        for rel, want, got in sha_mismatches[:10]:
            log.err(f"sha256 mismatch: {rel}")
            log.err(f"  manifest: {want}")
            log.err(f"  on-disk : {got}")
        for rel, want, got in size_mismatches[:10]:
            log.err(f"size mismatch : {rel} manifest={want} disk={got:,}")
        for rel, exc in unreadable[:10]:
            log.err(f"unreadable    : {rel} ({exc})")
        return CheckResult(name="manifest-vs-disk", ok=False, detail=detail)

    log.ok(f"all {verified:,} manifest rows match on-disk EML bytes")
    return CheckResult(name="manifest-vs-disk", ok=True, detail=detail)


# ---------------------------------------------------------------------------
# Check 4 - coercion audit
# ---------------------------------------------------------------------------


_ORIG_CT_RE = re.compile(
    rb"^X-PstSlicer-Original-Content-Type:\s*(.*?)\r?$", re.MULTILINE
)
_ORIG_FN_RE = re.compile(
    rb"^X-PstSlicer-Original-Filename:\s*(.*?)\r?$", re.MULTILINE
)


def _coercion_audit(output_dir: Path) -> CheckResult:
    log.header("Check 4 / 4 - attachment metadata coercion audit")

    total_emls = 0
    emls_with_any_coercion = 0
    ct_counter: Counter[str] = Counter()
    fn_counter: Counter[str] = Counter()

    for eml in output_dir.rglob("*.eml"):
        total_emls += 1
        if total_emls % 500 == 0:
            log.progress(f"scanned {total_emls:,} EML files for coercion markers")
        try:
            data = eml.read_bytes()
        except OSError:
            continue
        cts = _ORIG_CT_RE.findall(data)
        fns = _ORIG_FN_RE.findall(data)
        if cts or fns:
            emls_with_any_coercion += 1
        for ct in cts:
            ct_counter[ct.decode("utf-8", "replace").strip()] += 1
        for fn in fns:
            fn_counter[fn.decode("utf-8", "replace").strip()] += 1

    log.progress(f"scanned {total_emls:,} EML files for coercion markers")
    log.progress_end()

    pct = (emls_with_any_coercion / total_emls * 100.0) if total_emls else 0.0
    detail = [
        f"total EMLs scanned              : {total_emls:,}",
        f"EMLs with at least one coercion : {emls_with_any_coercion:,} ({pct:.2f}%)",
        f"distinct Content-Type coercions : {len(ct_counter):,}",
        f"distinct filename sanitisations : {len(fn_counter):,}",
    ]

    log.ok(
        f"{emls_with_any_coercion:,} / {total_emls:,} EMLs "
        f"({pct:.2f}%) contained a coerced attachment"
    )
    if ct_counter:
        log.note("Original Content-Type distribution (count -- claimed type):")
        for ct, n in ct_counter.most_common():
            log.kv(f"  {n:>6,}", ct)
    if fn_counter:
        log.note("Original filenames (up to 20 shown; unique = count of that exact string):")
        for fn, n in fn_counter.most_common(20):
            log.kv(f"  {n:>6,}", fn)
        if len(fn_counter) > 20:
            log.note(f"  ... and {len(fn_counter) - 20:,} more distinct filenames")

    # Coercion audit is informational: presence of coercion is NOT a failure.
    # The X- headers exist precisely so coercion is auditable, not so it's
    # flagged as an error. We only return ok=False if no EMLs were found at
    # all (which would already be caught by check 2, but belt-and-suspenders).
    ok = total_emls > 0
    return CheckResult(name="coercion-audit", ok=ok, detail=detail)


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _render_report(report: VerificationReport) -> None:
    log.header("Verification summary")
    for c in report.checks:
        _emit_check_line(c)
    log.header("Overall")
    if report.ok:
        log.ok("all four checks PASSED - run is forensically verifiable")
    else:
        log.err("one or more checks FAILED - see details above")


def _emit_check_line(c: CheckResult) -> None:
    stream = sys.stdout
    p = _palette.for_stream(stream)
    status = f"{p.GREEN}PASS{p.RESET}" if c.ok else f"{p.RED}FAIL{p.RESET}"
    stream.write(f"    {status}  {c.name}\n")
    for d in c.detail:
        stream.write(f"      {p.DIM}{d}{p.RESET}\n")
    stream.flush()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_run_log(path: Path) -> dict[str, str]:
    """Return the top-of-file ``key : value`` pairs from a run.log."""
    out: dict[str, str] = {}
    tool_version_re = re.compile(r"^pst-slicer v(\S+) run log")
    for line in path.read_text(encoding="utf-8").splitlines():
        if not out:
            m = tool_version_re.match(line)
            if m:
                out["tool_version"] = m.group(1)
                continue
        if ":" not in line:
            continue
        # Field names in run.log are alnum + underscore, then padding
        # spaces, then ": ", then value. Split on the FIRST ": " only.
        k, sep, v = line.partition(":")
        if not sep:
            continue
        key = k.strip()
        val = v.strip()
        if not key or not val or " " in key:
            # Skip any TOML config-dump lines (indented, or contain spaces).
            continue
        out[key] = val
    return out


def _sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


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
        f"[{p.GREEN}--no-log{p.RESET}] "
        f"{p.YELLOW}CONFIG{p.RESET}\n"
    )
    stream.flush()


def _print_help(stream: IO[Any]) -> None:
    p = _palette.for_stream(stream)
    w = stream.write

    _print_usage(stream)
    w("\n")
    w(
        "Post-run integrity + coercion verification for a completed\n"
        "pst-slicer run. Point at the same TOML config that was used for\n"
        "the extraction; the tool resolves input.pst and output.dir from\n"
        "the config and performs the four-check verification protocol:\n"
        "\n"
        "  1. source PST unchanged (SHA-256 pre- vs post-run)\n"
        "  2. manifest.tsv rows == on-disk EMLs == run.log counter\n"
        "  3. every EML's SHA-256 + size matches its manifest row\n"
        "  4. attachment-metadata coercion audit\n"
    )
    w("\n")

    w(f"{p.BOLD}Positional arguments:{p.RESET}\n")
    cli_help.help_row(
        stream, p, f"{p.YELLOW}CONFIG{p.RESET}",
        "TOML config file that was used for the extraction.",
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
        stream, p, f"{p.GREEN}--no-log{p.RESET}",
        "Do not auto-write verify.log to the output directory.",
    )
    w("\n")

    w(f"{p.BOLD}Output artifact:{p.RESET}\n")
    w(f"  {p.DIM}<output.dir>/verify.log{p.RESET}\n")
    w(f"    {p.DIM}ANSI-stripped copy of the terminal session, suitable\n")
    w(f"    for preservation in the case file. Suppress with --no-log.{p.RESET}\n")
    w("\n")

    w(f"{p.BOLD}Exit codes:{p.RESET}\n")
    cli_help.help_row(stream, p, f"{p.GREEN}0{p.RESET}", "All four checks passed.")
    cli_help.help_row(stream, p, f"{p.GREEN}1{p.RESET}", "At least one check failed.")
    cli_help.help_row(stream, p, f"{p.GREEN}2{p.RESET}",
                      "Setup problem (bad config, missing run.log, ...).")
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
        "--no-log",
        action="store_true",
        help="Do not auto-write verify.log alongside the run outputs.",
    )
    parser.add_argument(
        "config",
        metavar="CONFIG",
        help="Path to the same TOML config file that was passed to pst-slicer.",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
