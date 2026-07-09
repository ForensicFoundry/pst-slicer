# SPDX-License-Identifier: GPL-3.0-or-later
"""TOML config loader for pst-slicer.

Schema (v2):

    [input]
    pst = "/absolute/path/to/file.pst"

    [output]
    dir = "/absolute/path/to/output"

    [mode]
    type = "IMID"   # "IMID" | "keyword" | "sender" | "sender_domain" | "attachment_ext"

    # Exactly one of the mode-specific tables below must be present,
    # matching mode.type.

    [mode.imid]
    list = ["<abc@example.com>", "def@example.com"]
    # or:
    # file = "imids.txt"

    [mode.keyword]
    keywords = ["confidential", "acquisition"]
    fields = ["subject", "body"]         # optional; default = both
    case_sensitive = false               # optional; default = false

    [mode.sender]
    addresses = ["john@example.com", "jane@example.com"]

    [mode.sender_domain]
    domains = ["suspectdomain.com", "malicious.example"]

    [mode.attachment_ext]
    extensions = [".pdf", ".js", ".exe"]

Design goals:
  * Fail loudly with the exact key that's wrong.
  * Resolve all relative paths against the config file's directory.
  * Return a frozen dataclass tree so downstream code can't mutate.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


class ConfigError(ValueError):
    """Raised for any config-shape or content problem."""


# ---------------------------------------------------------------------------
# Mode-specific config payloads
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImidModeConfig:
    """Payload for ``mode.type = "IMID"``."""

    imids: tuple[str, ...]
    #: Origin of the list ("inline" or absolute path). Provenance only.
    source: str


@dataclass(frozen=True)
class KeywordModeConfig:
    """Payload for ``mode.type = "keyword"``."""

    keywords: tuple[str, ...]
    fields: tuple[str, ...]  # subset of {"subject", "body"}
    case_sensitive: bool


@dataclass(frozen=True)
class SenderModeConfig:
    """Payload for ``mode.type = "sender"``."""

    addresses: tuple[str, ...]


@dataclass(frozen=True)
class SenderDomainModeConfig:
    """Payload for ``mode.type = "sender_domain"``."""

    domains: tuple[str, ...]


@dataclass(frozen=True)
class AttachmentExtModeConfig:
    """Payload for ``mode.type = "attachment_ext"``."""

    extensions: tuple[str, ...]  # each normalized to ``.<ext>`` lowercase


ModeConfig = (
    ImidModeConfig
    | KeywordModeConfig
    | SenderModeConfig
    | SenderDomainModeConfig
    | AttachmentExtModeConfig
)


@dataclass(frozen=True)
class Config:
    config_path: Path
    input_pst: Path
    output_dir: Path
    mode_type: str
    mode: ModeConfig
    raw: dict[str, Any] = field(repr=False, default_factory=dict)


# ---------------------------------------------------------------------------
# Loader entry point
# ---------------------------------------------------------------------------


def load_config(path: Path) -> Config:
    """Parse and validate the TOML config at ``path``."""
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ConfigError(f"Config file does not exist: {path}")

    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc

    config_dir = path.parent

    input_section = _require_table(raw, "input")
    input_pst = _resolve_path(_require_string(input_section, "input.pst"), config_dir)
    if not input_pst.is_file():
        raise ConfigError(f"input.pst does not exist: {input_pst}")

    output_section = _require_table(raw, "output")
    output_dir = _resolve_path(_require_string(output_section, "output.dir"), config_dir)

    mode_section = _require_table(raw, "mode")
    mode_type_raw = _require_string(mode_section, "mode.type")
    mode_type = _normalize_mode_type(mode_type_raw)

    loader = _MODE_LOADERS.get(mode_type)
    if loader is None:
        raise ConfigError(
            f"mode.type = {mode_type_raw!r} is not supported. "
            f"Supported modes: {sorted(_MODE_LOADERS)}"
        )
    mode_payload = loader(mode_section, config_dir)

    return Config(
        config_path=path,
        input_pst=input_pst,
        output_dir=output_dir,
        mode_type=mode_type,
        mode=mode_payload,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Per-mode loaders (registered below)
# ---------------------------------------------------------------------------


def _load_imid_mode(mode_section: dict[str, Any], config_dir: Path) -> ImidModeConfig:
    section = mode_section.get("imid")
    if not isinstance(section, dict):
        raise ConfigError(
            'mode.type = "IMID" but [mode.imid] table is missing.'
        )
    inline = section.get("list")
    file_ref = section.get("file")
    if inline is None and file_ref is None:
        raise ConfigError(
            "[mode.imid] must define either `list` (array of IMIDs) or `file`."
        )
    if inline is not None and file_ref is not None:
        raise ConfigError("[mode.imid] must define exactly one of `list` or `file`.")

    if inline is not None:
        if not isinstance(inline, list) or not all(isinstance(x, str) for x in inline):
            raise ConfigError("[mode.imid].list must be an array of strings.")
        imids = tuple(_dedupe_norm_preserve(inline, _normalize_imid))
        source = "inline"
    else:
        if not isinstance(file_ref, str):
            raise ConfigError("[mode.imid].file must be a string path.")
        p = _resolve_path(file_ref, config_dir)
        if not p.is_file():
            raise ConfigError(f"[mode.imid].file does not exist: {p}")
        imids = tuple(_dedupe_norm_preserve(_read_line_file(p), _normalize_imid))
        source = str(p)

    if not imids:
        raise ConfigError("[mode.imid] resolved to zero IMIDs after cleanup.")
    return ImidModeConfig(imids=imids, source=source)


def _load_keyword_mode(
    mode_section: dict[str, Any], config_dir: Path
) -> KeywordModeConfig:
    section = mode_section.get("keyword")
    if not isinstance(section, dict):
        raise ConfigError(
            'mode.type = "keyword" but [mode.keyword] table is missing.'
        )
    kws = section.get("keywords")
    if not isinstance(kws, list) or not all(isinstance(x, str) for x in kws):
        raise ConfigError("[mode.keyword].keywords must be an array of strings.")
    cleaned = tuple(_dedupe_norm_preserve(kws, lambda s: s.strip().casefold()))
    if not cleaned:
        raise ConfigError("[mode.keyword].keywords resolved to zero terms.")

    fields_raw = section.get("fields", ["subject", "body"])
    if not isinstance(fields_raw, list) or not all(isinstance(x, str) for x in fields_raw):
        raise ConfigError("[mode.keyword].fields must be an array of strings.")
    allowed = {"subject", "body"}
    fields = tuple(f.strip().lower() for f in fields_raw)
    for f in fields:
        if f not in allowed:
            raise ConfigError(
                f"[mode.keyword].fields entry {f!r} is not one of {sorted(allowed)}."
            )
    if not fields:
        raise ConfigError("[mode.keyword].fields resolved to zero fields.")

    case_sensitive_raw = section.get("case_sensitive", False)
    if not isinstance(case_sensitive_raw, bool):
        raise ConfigError("[mode.keyword].case_sensitive must be a boolean.")

    return KeywordModeConfig(
        keywords=cleaned,
        fields=fields,
        case_sensitive=bool(case_sensitive_raw),
    )


def _load_sender_mode(
    mode_section: dict[str, Any], config_dir: Path
) -> SenderModeConfig:
    section = mode_section.get("sender")
    if not isinstance(section, dict):
        raise ConfigError(
            'mode.type = "sender" but [mode.sender] table is missing.'
        )
    addrs = section.get("addresses")
    if not isinstance(addrs, list) or not all(isinstance(x, str) for x in addrs):
        raise ConfigError("[mode.sender].addresses must be an array of strings.")
    cleaned = tuple(_dedupe_norm_preserve(addrs, lambda s: s.strip().casefold()))
    if not cleaned:
        raise ConfigError("[mode.sender].addresses resolved to zero entries.")
    for a in cleaned:
        if "@" not in a:
            raise ConfigError(
                f"[mode.sender].addresses entry {a!r} does not look like an email address."
            )
    return SenderModeConfig(addresses=cleaned)


def _load_sender_domain_mode(
    mode_section: dict[str, Any], config_dir: Path
) -> SenderDomainModeConfig:
    section = mode_section.get("sender_domain")
    if not isinstance(section, dict):
        raise ConfigError(
            'mode.type = "sender_domain" but [mode.sender_domain] table is missing.'
        )
    domains = section.get("domains")
    if not isinstance(domains, list) or not all(isinstance(x, str) for x in domains):
        raise ConfigError("[mode.sender_domain].domains must be an array of strings.")

    def _norm_domain(s: str) -> str:
        v = s.strip().casefold()
        if v.startswith("@"):
            v = v[1:]
        return v

    cleaned = tuple(_dedupe_norm_preserve(domains, _norm_domain))
    if not cleaned:
        raise ConfigError("[mode.sender_domain].domains resolved to zero entries.")
    for d in cleaned:
        if "." not in d:
            raise ConfigError(
                f"[mode.sender_domain].domains entry {d!r} does not look like a domain."
            )
    return SenderDomainModeConfig(domains=cleaned)


def _load_attachment_ext_mode(
    mode_section: dict[str, Any], config_dir: Path
) -> AttachmentExtModeConfig:
    section = mode_section.get("attachment_ext")
    if not isinstance(section, dict):
        raise ConfigError(
            'mode.type = "attachment_ext" but [mode.attachment_ext] table is missing.'
        )
    exts = section.get("extensions")
    if not isinstance(exts, list) or not all(isinstance(x, str) for x in exts):
        raise ConfigError(
            "[mode.attachment_ext].extensions must be an array of strings."
        )

    def _norm_ext(s: str) -> str:
        v = s.strip().casefold()
        if not v:
            return ""
        if not v.startswith("."):
            v = "." + v
        return v

    cleaned = tuple(_dedupe_norm_preserve(exts, _norm_ext))
    if not cleaned:
        raise ConfigError("[mode.attachment_ext].extensions resolved to zero entries.")
    return AttachmentExtModeConfig(extensions=cleaned)


_MODE_LOADERS: dict[str, Callable[[dict[str, Any], Path], ModeConfig]] = {
    "IMID": _load_imid_mode,
    "keyword": _load_keyword_mode,
    "sender": _load_sender_mode,
    "sender_domain": _load_sender_domain_mode,
    "attachment_ext": _load_attachment_ext_mode,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_mode_type(raw: str) -> str:
    """Case-normalize the mode.type string against the registry keys.

    IMID stays uppercase (matches its all-caps display form). Other
    modes are lowercase snake_case.
    """
    v = raw.strip()
    if v.casefold() == "imid":
        return "IMID"
    return v.casefold()


def _require_table(root: dict[str, Any], key: str) -> dict[str, Any]:
    val = root.get(key)
    if not isinstance(val, dict):
        raise ConfigError(f"Missing required [{key}] table in config.")
    return val


def _require_string(section: dict[str, Any], dotted: str) -> str:
    leaf = dotted.rsplit(".", 1)[-1]
    val = section.get(leaf)
    if not isinstance(val, str) or not val.strip():
        raise ConfigError(f"Missing or empty required string field: {dotted}")
    return val


def _resolve_path(raw: str, config_dir: Path) -> Path:
    p = Path(raw).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (config_dir / p).resolve()


def _read_line_file(path: Path) -> list[str]:
    """Read a line-delimited file: one value per line, ``#`` comments."""
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    out: list[str] = []
    for line in raw.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            out.append(stripped)
    return out


def _dedupe_norm_preserve(
    items: list[str], norm: Callable[[str], str]
) -> list[str]:
    """De-dupe by ``norm(item)`` while preserving first-occurrence spelling."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        n = norm(raw)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(raw.strip())
    return out


def _normalize_imid(value: str) -> str:
    """Canonicalize an IMID for comparison: strip whitespace + one pair of
    angle brackets + casefold. Empty string when the input is meaningless."""
    v = value.strip()
    if v.startswith("<") and v.endswith(">") and len(v) >= 2:
        v = v[1:-1].strip()
    return v.casefold()
