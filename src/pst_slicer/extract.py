# SPDX-License-Identifier: GPL-3.0-or-later
"""Extraction orchestrator.

Wires together config -> matcher -> PST walker -> EML writer -> manifest.

Forensic-soundness invariants enforced here:

  * The source PST is opened read-only. Its SHA-256 is computed BEFORE
    any walk begins and recorded in ``run.log`` so we can prove the
    tool never mutated the evidence.
  * Every extracted EML is written atomically (``*.eml.tmp`` +
    ``os.replace``), then hashed, then a manifest row is appended.
    Order matters: the manifest never references a file that isn't
    fully on disk.
  * All timestamps recorded are UTC.
  * Any per-item failure (malformed message, unreadable attachment,
    etc.) is logged as WARN and the walk continues; individual failures
    never abort the run.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from . import __version__, log
from .config import Config
from .eml import build_eml, parse_date_header
from .manifest import ManifestRow, ManifestWriter, write_not_found
from .modes import MatchResult, build_matcher
from .pst import PstItem, open_pst


class ExtractionError(RuntimeError):
    """Raised for unrecoverable extraction errors (bad PST, IO failure, etc.)."""


@dataclass
class ExtractionResult:
    scanned: int
    matched: int
    written: int
    failed: int
    unmatched_targets: int


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_extraction(cfg: Config) -> ExtractionResult:
    started_utc = _now_utc()
    output_dir = cfg.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = output_dir / "manifest.tsv"
    not_found_path = output_dir / "not_found.txt"
    run_log_path = output_dir / "run.log"

    log.header(f"pst-slicer v{__version__}")
    log.kv("config", str(cfg.config_path))
    log.kv("input PST", str(cfg.input_pst))
    log.kv("output dir", str(output_dir))
    log.kv("mode", cfg.mode_type)

    log.note("Hashing source PST (SHA-256, read-only)")
    try:
        source_sha = _sha256_file(cfg.input_pst)
    except OSError as exc:
        raise ExtractionError(f"Cannot read source PST: {exc}") from exc
    source_size = cfg.input_pst.stat().st_size
    log.ok(f"source PST SHA-256 = {source_sha}")
    log.kv("source PST bytes", f"{source_size:,}")

    matcher = build_matcher(cfg)
    log.note(f"Matcher: {matcher.name} (targets: {_target_count(cfg)})")

    scanned = 0
    matched = 0
    written = 0
    failed = 0

    with ManifestWriter(manifest_path) as manifest:
        try:
            with open_pst(cfg.input_pst) as pst:
                log.note("Walking PST...")
                for item in pst.iter_messages():
                    scanned += 1
                    if scanned % 500 == 0:
                        log.progress(
                            f"scanned {scanned:,} messages "
                            f"({matched:,} matched, {written:,} written, {failed:,} failed)"
                        )
                    result = matcher.matches(item)
                    if result is None:
                        continue
                    matched += 1
                    try:
                        row = _extract_one(item, result, cfg, output_dir)
                    except Exception as exc:  # pragma: no cover - resilience
                        failed += 1
                        log.warn(
                            f"failed to extract identifier={item.identifier} imid={item.internet_message_id!r}: {exc}"
                        )
                        continue
                    manifest.write(row)
                    written += 1
                # Emit one final progress tick so the last partial window
                # is captured, then move the cursor off the live line.
                log.progress(
                    f"scanned {scanned:,} messages "
                    f"({matched:,} matched, {written:,} written, {failed:,} failed)"
                )
                log.progress_end()
        except OSError as exc:
            raise ExtractionError(f"PST access failed: {exc}") from exc

    unmatched = matcher.report_unmatched()
    write_not_found(not_found_path, unmatched)

    ended_utc = _now_utc()
    _write_run_log(
        path=run_log_path,
        cfg=cfg,
        started_utc=started_utc,
        ended_utc=ended_utc,
        source_sha=source_sha,
        source_size=source_size,
        scanned=scanned,
        matched=matched,
        written=written,
        failed=failed,
        unmatched=unmatched,
        manifest_path=manifest_path,
        not_found_path=not_found_path,
    )

    log.header("Summary")
    log.kv("scanned messages", f"{scanned:,}")
    log.kv("matched", f"{matched:,}")
    log.kv("EML written", f"{written:,}")
    log.kv("failures", f"{failed:,}")
    log.kv("unmatched targets", f"{len(unmatched):,}")
    log.kv("manifest", str(manifest_path))
    log.kv("run log", str(run_log_path))
    if unmatched:
        log.kv("not_found list", str(not_found_path))
        log.warn(
            f"{len(unmatched)} configured {matcher.name!r} target(s) never matched; see not_found.txt"
        )

    return ExtractionResult(
        scanned=scanned,
        matched=matched,
        written=written,
        failed=failed,
        unmatched_targets=len(unmatched),
    )


# ---------------------------------------------------------------------------
# Per-item extraction
# ---------------------------------------------------------------------------


def _extract_one(
    item: PstItem, match: MatchResult, cfg: Config, output_root: Path
) -> ManifestRow:
    """Reconstruct the EML for ``item``, hash it, drop it in place, and
    return the manifest row."""
    eml_bytes = build_eml(item)

    folder_rel = _sanitize_folder_path(item.folder_path)
    dest_dir = output_root / folder_rel
    dest_dir.mkdir(parents=True, exist_ok=True)

    filename = _eml_filename(item)
    dest = dest_dir / filename

    dest = _atomic_write(dest, eml_bytes)

    size_bytes = dest.stat().st_size
    sha = hashlib.sha256(eml_bytes).hexdigest()

    date_header_utc = (
        parse_date_header(item.transport_headers)
        if item.has_transport_headers
        else None
    )

    return ManifestRow(
        imid=item.internet_message_id or "",
        match_reason=match.render_reason(),
        client_submit_time_utc=item.client_submit_time_utc,
        message_delivery_time_utc=item.message_delivery_time_utc,
        date_header_utc=date_header_utc,
        sender=_format_sender(item),
        recipients=_format_recipients(item),
        subject=item.subject,
        size_bytes=size_bytes,
        sha256=sha,
        source_folder=item.folder_path,
        source_pst=cfg.input_pst.name,
        output_path=str(dest.relative_to(output_root)),
    )


def _format_sender(item: PstItem) -> str:
    name = (item.sender_name or "").strip()
    email = (item.sender_email or "").strip()
    if name and email:
        return f"{name} <{email}>"
    return email or name


def _format_recipients(item: PstItem) -> str:
    parts: list[str] = []
    for label, val in (
        ("To", item.display_to),
        ("Cc", item.display_cc),
        ("Bcc", item.display_bcc),
    ):
        val = (val or "").strip()
        if val:
            parts.append(f"{label}: {val}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


_INVALID_NAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _sanitize_folder_path(folder_path: str) -> Path:
    parts: list[str] = []
    for raw in folder_path.split("/"):
        cleaned = _sanitize_component(raw)
        if cleaned in ("", ".", ".."):
            continue
        parts.append(cleaned)
    if not parts:
        parts = ["_root"]
    return Path(*parts)


def _sanitize_component(name: str) -> str:
    cleaned = _INVALID_NAME_CHARS.sub("_", name)
    cleaned = cleaned.strip().rstrip(".")
    if not cleaned:
        return ""
    if len(cleaned) > 120:
        cleaned = cleaned[:120].rstrip(".")
    return cleaned


def _eml_filename(item: PstItem) -> str:
    ts = item.client_submit_time_utc or item.message_delivery_time_utc
    prefix = (
        ts.strftime("%Y%m%dT%H%M%SZ") if ts is not None else "unknown-time"
    )
    imid_hash = hashlib.sha1(
        (item.internet_message_id or f"id-{item.identifier}").encode("utf-8")
    ).hexdigest()[:12]
    return f"{prefix}__{imid_hash}.eml"


def _atomic_write(dest: Path, payload: bytes) -> Path:
    """Write ``payload`` to ``dest`` atomically; if the target already
    exists, append a numeric suffix rather than overwrite (defensive)."""
    final = dest
    counter = 1
    while final.exists():
        final = dest.with_name(f"{dest.stem}__dup{counter:03d}{dest.suffix}")
        counter += 1
    tmp = final.with_suffix(final.suffix + ".tmp")
    with tmp.open("wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, final)
    return final


# ---------------------------------------------------------------------------
# Run log
# ---------------------------------------------------------------------------


def _write_run_log(
    *,
    path: Path,
    cfg: Config,
    started_utc: _dt.datetime,
    ended_utc: _dt.datetime,
    source_sha: str,
    source_size: int,
    scanned: int,
    matched: int,
    written: int,
    failed: int,
    unmatched: list[str],
    manifest_path: Path,
    not_found_path: Path,
) -> None:
    duration = ended_utc - started_utc
    buf = io.StringIO()
    buf.write(f"pst-slicer v{__version__} run log\n")
    buf.write("=" * 60 + "\n")
    buf.write(f"started_utc                : {_fmt(started_utc)}\n")
    buf.write(f"ended_utc                  : {_fmt(ended_utc)}\n")
    buf.write(f"duration_seconds           : {duration.total_seconds():.3f}\n")
    buf.write(f"tool_argv0                 : {sys.argv[0] if sys.argv else ''}\n")
    buf.write(f"python                     : {sys.version.splitlines()[0]}\n")
    buf.write(f"config_path                : {cfg.config_path}\n")
    buf.write(f"mode_type                  : {cfg.mode_type}\n")
    buf.write(f"input_pst_path             : {cfg.input_pst}\n")
    buf.write(f"input_pst_size_bytes       : {source_size}\n")
    buf.write(f"input_pst_sha256           : {source_sha}\n")
    buf.write(f"output_dir                 : {cfg.output_dir}\n")
    buf.write(f"manifest_path              : {manifest_path}\n")
    buf.write(f"not_found_path             : {not_found_path}\n")
    buf.write(f"messages_scanned           : {scanned}\n")
    buf.write(f"messages_matched           : {matched}\n")
    buf.write(f"eml_files_written          : {written}\n")
    buf.write(f"failures                   : {failed}\n")
    buf.write(f"unmatched_target_count     : {len(unmatched)}\n")
    buf.write("\n")
    buf.write("config_dump (verbatim TOML values as parsed):\n")
    _dump_dict(buf, cfg.raw, indent=2)

    path.write_text(buf.getvalue(), encoding="utf-8")


def _dump_dict(buf: io.StringIO, obj, indent: int) -> None:
    pad = " " * indent
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                buf.write(f"{pad}{k}:\n")
                _dump_dict(buf, v, indent + 2)
            elif isinstance(v, list):
                buf.write(f"{pad}{k}:\n")
                for item in v:
                    buf.write(f"{pad}  - {item!r}\n")
            else:
                buf.write(f"{pad}{k}: {v!r}\n")


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _now_utc() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _fmt(dt: _dt.datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _target_count(cfg: Config) -> int:
    """Count of config-supplied match targets, whatever the mode calls them."""
    m = cfg.mode
    for attr in ("imids", "keywords", "addresses", "domains", "extensions"):
        val = getattr(m, attr, None)
        if val is not None:
            return len(val)
    return 0
