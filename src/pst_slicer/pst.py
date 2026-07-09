# SPDX-License-Identifier: GPL-3.0-or-later
"""libpff-backed PST walker.

Wraps ``pypff`` (the ``libpff-python`` module, upstream version
``20231205``) into a small, typed API that yields ``PstItem`` records
with pre-collected MAPI properties. All access is read-only. The
underlying ``pypff.file`` is opened via ``open_file_object`` on a
``BufferedReader`` handle we own, so libpff never gets a chance to
modify the on-disk PST.

MAPI property access on this libpff release goes through
``record_sets -> record_entries``. Each entry exposes ``entry_type``
(the 16-bit PidTag ID), ``value_type``, and typed accessors
(``get_data_as_string``, ``get_data_as_integer``,
``get_data_as_datetime``, ``get_data``). We match on ``entry_type``.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import pypff  # type: ignore[import-untyped]


# ---------------------------------------------------------------------------
# MAPI PidTag IDs (16-bit; value_type nibble stripped)
# ---------------------------------------------------------------------------

# Message-level
PT_MESSAGE_CLASS = 0x001A
PT_SUBJECT = 0x0037
PT_CLIENT_SUBMIT_TIME = 0x0039
PT_SENT_REPRESENTING_NAME = 0x0042
PT_SENT_REPRESENTING_EMAIL_ADDRESS = 0x0065
PT_SENDER_NAME = 0x0C1A
PT_SENDER_EMAIL_ADDRESS = 0x0C1F
PT_DISPLAY_BCC = 0x0E02
PT_DISPLAY_CC = 0x0E03
PT_DISPLAY_TO = 0x0E04
PT_MESSAGE_DELIVERY_TIME = 0x0E06
PT_BODY = 0x1000
PT_BODY_HTML = 0x1013
PT_INTERNET_MESSAGE_ID = 0x1035
PT_TRANSPORT_MESSAGE_HEADERS = 0x007D
PT_SENDER_SMTP_ADDRESS = 0x5D01
PT_SENT_REPRESENTING_SMTP_ADDRESS = 0x5D02

# Attachment-level
PT_ATTACH_DATA_BIN = 0x3701
PT_ATTACH_FILENAME = 0x3704
PT_ATTACH_LONG_FILENAME = 0x3707
PT_ATTACH_MIME_TAG = 0x370E


# ---------------------------------------------------------------------------
# Data record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttachmentMeta:
    """Attachment metadata cached during walk so matchers don't have
    to re-open the message. Payload bytes are never cached here - the
    EML writer streams them on demand from the message handle."""

    filename: str  # long filename preferred, short (8.3) fallback
    mime_type: str  # e.g. "image/png", "application/pdf", or "" if unknown
    size: int  # bytes, as libpff reports it; 0 if unavailable


@dataclass
class PstItem:
    """Snapshot of one PST message.

    ``handle`` is retained so the EML writer can stream attachment bytes
    without walking the tree twice. The caller must not use the handle
    after ``open_pst`` exits.
    """

    handle: Any = field(repr=False)
    identifier: int
    folder_path: str  # POSIX-style; joined with "/"
    message_class: str
    subject: str
    internet_message_id: str
    transport_headers: str
    client_submit_time_utc: _dt.datetime | None
    message_delivery_time_utc: _dt.datetime | None
    sender_name: str
    sender_email: str
    display_to: str
    display_cc: str
    display_bcc: str
    body_plain: str
    body_html: str
    attachments: tuple[AttachmentMeta, ...] = ()

    @property
    def has_transport_headers(self) -> bool:
        return bool(self.transport_headers.strip())


# ---------------------------------------------------------------------------
# Open + walk
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def open_pst(path: Path) -> Iterator["PstFile"]:
    """Open ``path`` read-only and yield a ``PstFile`` wrapper.

    We manage the underlying file descriptor and hand libpff the
    file-like object via ``open_file_object`` so the tool never opens
    the evidence with write intent.
    """
    fh = path.open("rb")
    pff = pypff.file()
    try:
        pff.open_file_object(fh)
        yield PstFile(pff=pff, path=path)
    finally:
        with contextlib.suppress(Exception):
            pff.close()
        fh.close()


class PstFile:
    """Wrapper that yields ``PstItem`` records."""

    def __init__(self, pff: Any, path: Path) -> None:
        self._pff = pff
        self._path = path

    def iter_messages(self) -> Iterator[PstItem]:
        root = _safe_call(self._pff, "get_root_folder", default=None)
        if root is None:
            return
        yield from self._walk_folder(root, parents=[])

    def _walk_folder(self, folder: Any, parents: list[str]) -> Iterator[PstItem]:
        name = _safe_get_name(folder) or "(unnamed)"
        here = [*parents, name] if parents or name != "(unnamed)" else [name]
        path_str = "/".join(here) if here else "/"

        n_msg = _safe_call(folder, "get_number_of_sub_messages", default=0) or 0
        for i in range(n_msg):
            msg = _safe_call(folder, "get_sub_message", i, default=None)
            if msg is None:
                continue
            item = _snapshot_message(msg, folder_path=path_str)
            if item is not None:
                yield item

        n_sub = _safe_call(folder, "get_number_of_sub_folders", default=0) or 0
        for i in range(n_sub):
            sub = _safe_call(folder, "get_sub_folder", i, default=None)
            if sub is not None:
                yield from self._walk_folder(sub, parents=here)


# ---------------------------------------------------------------------------
# Message snapshot
# ---------------------------------------------------------------------------


def _snapshot_message(msg: Any, *, folder_path: str) -> PstItem | None:
    identifier = _safe_call(msg, "get_identifier", default=0) or 0

    subject = _str(_safe_call(msg, "get_subject", default=None)) or _prop_string(
        msg, PT_SUBJECT
    )
    imid = _prop_string(msg, PT_INTERNET_MESSAGE_ID)
    headers = _str(_safe_call(msg, "get_transport_headers", default=None)) or _prop_string(
        msg, PT_TRANSPORT_MESSAGE_HEADERS
    )

    submit_time = _to_utc(_safe_call(msg, "get_client_submit_time", default=None))
    delivery_time = _to_utc(_safe_call(msg, "get_delivery_time", default=None))

    sender_name = _prop_string(msg, PT_SENT_REPRESENTING_NAME) or _prop_string(
        msg, PT_SENDER_NAME
    )
    sender_email = (
        _prop_string(msg, PT_SENT_REPRESENTING_SMTP_ADDRESS)
        or _prop_string(msg, PT_SENDER_SMTP_ADDRESS)
        or _prop_string(msg, PT_SENT_REPRESENTING_EMAIL_ADDRESS)
        or _prop_string(msg, PT_SENDER_EMAIL_ADDRESS)
    )

    display_to = _prop_string(msg, PT_DISPLAY_TO)
    display_cc = _prop_string(msg, PT_DISPLAY_CC)
    display_bcc = _prop_string(msg, PT_DISPLAY_BCC)

    body_plain = _str(_safe_call(msg, "get_plain_text_body", default=None))
    body_html = _bytes_to_str(_safe_call(msg, "get_html_body", default=None))

    message_class = _prop_string(msg, PT_MESSAGE_CLASS)

    attachments = _snapshot_attachments(msg)

    return PstItem(
        handle=msg,
        identifier=int(identifier),
        folder_path=folder_path,
        message_class=message_class,
        subject=subject,
        internet_message_id=imid,
        transport_headers=headers,
        client_submit_time_utc=submit_time,
        message_delivery_time_utc=delivery_time,
        sender_name=sender_name,
        sender_email=sender_email,
        display_to=display_to,
        display_cc=display_cc,
        display_bcc=display_bcc,
        body_plain=body_plain,
        body_html=body_html,
        attachments=attachments,
    )


def _snapshot_attachments(msg: Any) -> tuple[AttachmentMeta, ...]:
    """Collect attachment metadata (not payload) for matcher use."""
    try:
        n = int(_safe_call(msg, "get_number_of_attachments", default=0) or 0)
    except Exception:
        n = 0
    out: list[AttachmentMeta] = []
    for i in range(n):
        att = _safe_call(msg, "get_attachment", i, default=None)
        if att is None:
            continue
        long_name = _prop_string(att, PT_ATTACH_LONG_FILENAME)
        short_name = _prop_string(att, PT_ATTACH_FILENAME)
        mime = _prop_string(att, PT_ATTACH_MIME_TAG)
        try:
            size = int(att.get_size() or 0)
        except Exception:
            size = 0
        out.append(
            AttachmentMeta(
                filename=long_name or short_name or "",
                mime_type=mime or "",
                size=size,
            )
        )
    return tuple(out)


# ---------------------------------------------------------------------------
# MAPI property access
# ---------------------------------------------------------------------------


def _find_entry(container: Any, tag: int) -> Any:
    """Return the first record_entry with ``entry_type == tag``, or None."""
    try:
        rs_count = int(container.get_number_of_record_sets() or 0)
    except Exception:
        return None
    for rs_idx in range(rs_count):
        try:
            rs = container.get_record_set(rs_idx)
        except Exception:
            continue
        if rs is None:
            continue
        try:
            n = int(rs.get_number_of_entries() or 0)
        except Exception:
            continue
        for e_idx in range(n):
            try:
                e = rs.get_entry(e_idx)
            except Exception:
                continue
            if e is None:
                continue
            try:
                et = e.get_entry_type()
            except Exception:
                continue
            if et == tag:
                return e
    return None


def prop_string(container: Any, tag: int) -> str:
    """Public alias so other modules (eml.py) can query attachment props."""
    return _prop_string(container, tag)


def prop_bytes(container: Any, tag: int) -> bytes:
    """Return the raw bytes of the entry, or ``b''``."""
    e = _find_entry(container, tag)
    if e is None:
        return b""
    for meth in ("get_data",):
        fn = getattr(e, meth, None)
        if fn is None:
            continue
        try:
            val = fn()
        except Exception:
            continue
        if isinstance(val, bytes):
            return val
    return b""


def prop_integer(container: Any, tag: int) -> int | None:
    e = _find_entry(container, tag)
    if e is None:
        return None
    fn = getattr(e, "get_data_as_integer", None)
    if fn is None:
        return None
    try:
        return int(fn())
    except Exception:
        return None


def _prop_string(container: Any, tag: int) -> str:
    e = _find_entry(container, tag)
    if e is None:
        return ""
    fn = getattr(e, "get_data_as_string", None)
    if fn is not None:
        try:
            val = fn()
        except Exception:
            val = None
        if val:
            return _str(val)
    # Fallback: raw bytes -> best-effort decode
    return _bytes_to_str(prop_bytes(container, tag))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_get_name(folder: Any) -> str:
    try:
        val = folder.get_name()
        return val or ""
    except Exception:
        return ""


def _safe_call(obj: Any, name: str, *args: Any, default: Any) -> Any:
    try:
        fn = getattr(obj, name, None)
        if fn is None:
            return default
        return fn(*args)
    except Exception:
        return default


def _str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace")
        except Exception:
            return val.decode("latin-1", errors="replace")
    return str(val)


def _bytes_to_str(val: Any) -> str:
    if val is None or val == "":
        return ""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8")
        except UnicodeDecodeError:
            return val.decode("cp1252", errors="replace")
    return str(val)


def _to_utc(val: Any) -> _dt.datetime | None:
    """Normalize whatever libpff hands us into an aware UTC datetime.

    ``pypff`` returns naive Python ``datetime`` for FILETIME properties;
    the FILETIME epoch is UTC so we tag it accordingly.
    """
    if val is None:
        return None
    if isinstance(val, _dt.datetime):
        dt = val if val.tzinfo else val.replace(tzinfo=_dt.timezone.utc)
        return dt.astimezone(_dt.timezone.utc)
    if isinstance(val, int):
        try:
            return _filetime_to_utc(val)
        except Exception:
            return None
    return None


_FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)


def _filetime_to_utc(ft: int) -> _dt.datetime:
    seconds, hundreds_ns = divmod(ft, 10_000_000)
    return _FILETIME_EPOCH + _dt.timedelta(
        seconds=seconds, microseconds=hundreds_ns // 10
    )
