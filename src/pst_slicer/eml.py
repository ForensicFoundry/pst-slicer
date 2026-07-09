# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct RFC 5322 EML bytes from a MAPI-backed ``PstItem``.

Strategy (forensic-priority order):

1. **Transport headers verbatim.** If the PST retains
   ``PR_TRANSPORT_MESSAGE_HEADERS`` (PID 0x007D) - the RFC 822 header
   block Exchange stored when the message arrived - we use it as the
   header section, unmodified. This is the "closest to wire" evidence
   the PST holds, so we do not paraphrase it.

2. **Body reassembly.** Below the headers we place a MIME body that
   includes all recoverable content: plain text, HTML (if present),
   and every attachment. If the transport headers already advertise a
   ``multipart/*`` Content-Type with a boundary, we replace that
   Content-Type line with one that matches the boundary we actually
   emit; we do NOT re-encode the parts themselves.

3. **Synthesized headers fallback.** If no transport headers exist
   (common for locally-composed drafts), we synthesize a minimal RFC
   5322 header block from MAPI properties (From, To, Cc, Bcc, Subject,
   Date, Message-ID) so the file is still a valid ``.eml``.

All line endings in the emitted bytes are CRLF, per RFC 5322 s2.1.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import mimetypes
import re
from email import policy
from email.header import Header
from email.message import EmailMessage
from email.utils import format_datetime, formataddr
from typing import Any, Iterable

from . import pst as _pst
from .pst import (
    PT_ATTACH_DATA_BIN,
    PT_ATTACH_FILENAME,
    PT_ATTACH_LONG_FILENAME,
    PT_ATTACH_MIME_TAG,
    PstItem,
)


CRLF = b"\r\n"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_eml(item: PstItem) -> bytes:
    """Return the fully-assembled EML bytes for ``item``.

    Output is deterministic: given the same PST content, the returned
    bytes are byte-identical across runs. That guarantees the manifest
    SHA-256 is reproducible for chain-of-custody purposes.
    """
    attachments = list(_iter_attachments(item.handle))

    body_msg = _build_body_message(item, attachments)
    _make_boundaries_deterministic(body_msg, seed=_boundary_seed(item))
    body_bytes = _dump_message(body_msg)

    if item.has_transport_headers:
        header_section, has_ctype = _extract_header_section(item.transport_headers)
        # Extract the body's Content-Type + boundary + MIME-Version so we can
        # graft them on top of the transport headers (or replace the ones
        # already there). The body payload starts after the first blank line.
        body_headers, body_payload = _split_headers_payload(body_bytes)
        merged_headers = _merge_headers(header_section, body_headers, replace_ctype=has_ctype)
        return _to_crlf(merged_headers) + CRLF + CRLF + _to_crlf(body_payload)

    # No transport headers -> synthesize a full RFC 5322 message.
    synthesized = _synthesize_full_message(item, body_msg)
    return _dump_message(synthesized)


# ---------------------------------------------------------------------------
# Body assembly
# ---------------------------------------------------------------------------


def _build_body_message(item: PstItem, attachments: list["_Attachment"]) -> EmailMessage:
    """Build the MIME body, mirroring exactly which bodies the source held.

    We never fabricate a plain-text placeholder when the source lacked
    one - that would be evidence tampering. If the source has HTML
    only, we emit ``text/html`` at the top level (or wrapped in
    multipart/mixed if there are attachments).
    """
    msg = EmailMessage(policy=policy.SMTP)
    plain = item.body_plain or ""
    html = item.body_html or ""
    has_plain = bool(plain.strip())
    has_html = bool(html.strip())

    if has_plain and has_html:
        msg.set_content(plain, subtype="plain", cte="quoted-printable")
        msg.add_alternative(html, subtype="html", cte="quoted-printable")
    elif has_html:
        msg.set_content(html, subtype="html", cte="quoted-printable")
    elif has_plain:
        msg.set_content(plain, subtype="plain", cte="quoted-printable")
    else:
        # Source had no body at all - preserve that fact with an empty body.
        msg.set_content("", subtype="plain", cte="7bit")

    for att in attachments:
        _attach_safely(msg, att)

    return msg


def _attach_safely(msg: EmailMessage, att: "_Attachment") -> None:
    """Attach ``att.data`` to ``msg`` while dodging known email-lib landmines.

    Forensic priority: **never lose the attachment payload bytes**. Bytes are
    the evidence; the metadata (filename, MIME type) is descriptive and can be
    coerced without altering the payload. When the source PST hands us
    attachment metadata that Python's ``email`` package would either refuse
    to serialize (CR/LF in Content-Disposition filename) or actively crash
    on (``message/delivery-status`` triggers a generator handler that
    assumes the payload is a list of Message objects, not raw bytes), we
    coerce that metadata to something the serializer can handle and record
    the coercion via the attachment's ``X-PstSlicer-Original-*`` headers so
    an analyst can reconstruct the original claim from the EML alone.
    """
    filename_raw = att.filename or "attachment.bin"
    filename_safe = _sanitize_filename(filename_raw)
    maintype, subtype, mime_coerced = _safe_split_mime_type(att.mime_type, filename_safe)
    filename_coerced = filename_safe != filename_raw

    def _do_add(mt: str, st: str, fn: str) -> None:
        msg.add_attachment(
            att.data,
            maintype=mt,
            subtype=st,
            filename=fn,
        )

    try:
        _do_add(maintype, subtype, filename_safe)
    except (ValueError, TypeError, AttributeError):
        # Belt-and-suspenders: if the coerced values still upset the email
        # library for any reason we did not foresee, drop to the safest
        # possible representation - octet-stream, plain-ASCII filename.
        _do_add("application", "octet-stream", _ascii_only_filename(filename_safe))
        mime_coerced = True
        filename_coerced = True

    # Record any coercion on the newly-attached part so evidence of the
    # original metadata is preserved in the EML itself.
    if mime_coerced or filename_coerced:
        payload = msg.get_payload()
        if isinstance(payload, list) and payload:
            last = payload[-1]
            if mime_coerced and att.mime_type:
                last["X-PstSlicer-Original-Content-Type"] = _sanitize_header_value(
                    att.mime_type
                )
            if filename_coerced:
                last["X-PstSlicer-Original-Filename"] = _sanitize_header_value(
                    filename_raw
                )


def _boundary_seed(item: PstItem) -> str:
    """Stable per-message seed for deterministic MIME boundary generation."""
    return (
        item.internet_message_id.strip()
        or f"id-{item.identifier}"
    )


def _make_boundaries_deterministic(msg: EmailMessage, *, seed: str) -> None:
    """Replace every multipart boundary in ``msg`` with a value derived
    from ``seed`` + the part's depth-first ordinal position.

    Called before serialization so that the on-wire bytes are stable
    across runs. Content boundaries never appear in the actual message
    parts, so replacing them is safe and does not alter any payload.
    """
    counter = 0
    seed_bytes = seed.encode("utf-8", errors="replace")
    for part in msg.walk():
        if part.is_multipart():
            counter += 1
            digest = hashlib.sha256(
                seed_bytes + b":" + str(counter).encode()
            ).hexdigest()[:32]
            part.set_boundary(f"----=_pst_slicer_{digest}")


def _synthesize_full_message(item: PstItem, body_msg: EmailMessage) -> EmailMessage:
    """Add From/To/Cc/Bcc/Subject/Date/Message-ID to a body-only message."""
    msg = body_msg  # in-place; caller does not reuse body_msg
    sender_name = _sanitize_header_value(item.sender_name)
    sender_email = _sanitize_header_value(item.sender_email)
    if sender_email or sender_name:
        msg["From"] = _format_addr(sender_name, sender_email)
    display_to = _sanitize_header_value(item.display_to)
    if display_to:
        msg["To"] = display_to
    display_cc = _sanitize_header_value(item.display_cc)
    if display_cc:
        msg["Cc"] = display_cc
    display_bcc = _sanitize_header_value(item.display_bcc)
    if display_bcc:
        msg["Bcc"] = display_bcc
    subject = _sanitize_header_value(item.subject)
    if subject:
        msg["Subject"] = str(Header(subject, "utf-8"))
    dt = item.client_submit_time_utc or item.message_delivery_time_utc
    if dt is not None:
        msg["Date"] = format_datetime(dt)
    if item.internet_message_id:
        mid = _sanitize_header_value(item.internet_message_id).strip()
        if mid and not (mid.startswith("<") and mid.endswith(">")):
            mid = f"<{mid}>"
        if mid:
            msg["Message-ID"] = mid
    if "Message-ID" not in msg:
        # Deterministic synthetic Message-ID so re-runs are reproducible.
        digest = hashlib.sha256(
            f"pst-slicer:{item.identifier}:{item.folder_path}:{item.subject}".encode(
                "utf-8", errors="replace"
            )
        ).hexdigest()[:32]
        msg["Message-ID"] = f"<synthetic-{digest}@pst-slicer.local>"
    if "MIME-Version" not in msg:
        msg["MIME-Version"] = "1.0"
    return msg


# ---------------------------------------------------------------------------
# Header handling
# ---------------------------------------------------------------------------


_CTYPE_RE = re.compile(r"^Content-Type\s*:", re.IGNORECASE)
_MIME_VER_RE = re.compile(r"^MIME-Version\s*:", re.IGNORECASE)
_CTE_RE = re.compile(r"^Content-Transfer-Encoding\s*:", re.IGNORECASE)


def _extract_header_section(headers: str) -> tuple[str, bool]:
    """Return (header block, whether it already declares a Content-Type)."""
    # Normalize to LF for processing; we CRLF-ify on the way out.
    text = headers.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    lines = text.split("\n")
    # Some PSTs include a trailing blank line separating headers from what
    # would have been the body; keep only the header block itself.
    trimmed: list[str] = []
    for line in lines:
        if line == "":
            # header/body separator hit; stop
            break
        trimmed.append(line)
    header_block = "\n".join(trimmed)
    has_ctype = any(_CTYPE_RE.match(line) for line in _unfold_lines(trimmed))
    return header_block, has_ctype


def _split_headers_payload(dumped: bytes) -> tuple[str, bytes]:
    """Split ``dumped`` (bytes, CRLF or LF endings) into (header text, body bytes)."""
    # EmailMessage.as_bytes(policy=SMTP) uses CRLF already.
    sep = dumped.find(b"\r\n\r\n")
    if sep == -1:
        sep = dumped.find(b"\n\n")
        if sep == -1:
            return dumped.decode("latin-1", errors="replace"), b""
        header_bytes = dumped[:sep]
        payload = dumped[sep + 2 :]
    else:
        header_bytes = dumped[:sep]
        payload = dumped[sep + 4 :]
    return header_bytes.decode("latin-1", errors="replace"), payload


def _merge_headers(transport: str, body_headers: str, *, replace_ctype: bool) -> str:
    """Merge transport (original) headers with the body headers we generated.

    Rules:
      * Take Content-Type, MIME-Version, and Content-Transfer-Encoding from
        the body headers (they describe what we actually wrote).
      * Everything else comes from ``transport`` (unchanged).
      * If ``replace_ctype`` is True, we drop any existing Content-Type in
        ``transport`` and let the body's Content-Type win.
    """
    body_ctype = _find_header(body_headers, "Content-Type")
    body_mime = _find_header(body_headers, "MIME-Version") or "1.0"
    body_cte = _find_header(body_headers, "Content-Transfer-Encoding")

    transport_lines = [
        line
        for line in transport.split("\n")
        if not _MIME_VER_RE.match(line)
        and (not replace_ctype or not _CTYPE_RE.match(line))
        and not _CTE_RE.match(line)
        and not _is_folded_continuation_of_dropped(line, transport, replace_ctype)
    ]

    out_lines = list(transport_lines)
    out_lines.append(f"MIME-Version: {body_mime}")
    if body_ctype:
        # If transport had a Content-Type we did not drop, keep the body's
        # version at the end - Python's parser accepts the last occurrence,
        # and MUAs generally follow suit. To avoid duplicates, remove any
        # remaining Content-Type header.
        out_lines = [l for l in out_lines if not _CTYPE_RE.match(l)]
        out_lines.append(f"Content-Type: {body_ctype}")
    if body_cte:
        out_lines.append(f"Content-Transfer-Encoding: {body_cte}")
    return "\n".join(out_lines)


def _find_header(block: str, name: str) -> str | None:
    """Return the first value of ``name`` from a header block, unfolded."""
    unfolded = list(_unfold_lines(block.replace("\r\n", "\n").split("\n")))
    prefix = name.lower() + ":"
    for line in unfolded:
        if line.lower().startswith(prefix):
            return line[len(prefix):].strip()
    return None


def _unfold_lines(lines: Iterable[str]) -> Iterable[str]:
    """Yield RFC 5322-unfolded header lines from a raw sequence."""
    buffer = ""
    for line in lines:
        if line.startswith((" ", "\t")):
            buffer += " " + line.strip()
            continue
        if buffer:
            yield buffer
        buffer = line
    if buffer:
        yield buffer


def _is_folded_continuation_of_dropped(
    line: str, transport: str, replace_ctype: bool
) -> bool:
    """Best-effort: drop folded continuation lines that belong to a header
    we're removing. Used only for Content-Type/MIME-Version/CTE."""
    if not line.startswith((" ", "\t")):
        return False
    # Walk backwards to find the field-name owning this continuation.
    text_lines = transport.split("\n")
    try:
        idx = text_lines.index(line)
    except ValueError:
        return False
    for prev in reversed(text_lines[:idx]):
        if prev.startswith((" ", "\t")):
            continue
        if _MIME_VER_RE.match(prev) or _CTE_RE.match(prev):
            return True
        if replace_ctype and _CTYPE_RE.match(prev):
            return True
        return False
    return False


def _to_crlf(data: str | bytes) -> bytes:
    """Return ``data`` with every line ending normalized to CRLF."""
    if isinstance(data, bytes):
        return (
            data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
        )
    normalized = data.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    return normalized.encode("utf-8", errors="replace")


def _dump_message(msg: EmailMessage) -> bytes:
    """Serialize an EmailMessage using CRLF endings (SMTP policy)."""
    return msg.as_bytes(policy=policy.SMTP)


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------


class _Attachment:
    __slots__ = ("filename", "mime_type", "data")

    def __init__(self, filename: str, mime_type: str, data: bytes) -> None:
        self.filename = filename
        self.mime_type = mime_type
        self.data = data


def _iter_attachments(msg_handle: Any) -> Iterable[_Attachment]:
    try:
        n = int(msg_handle.get_number_of_attachments() or 0)
    except Exception:
        n = 0
    for i in range(n):
        try:
            att = msg_handle.get_attachment(i)
        except Exception:
            continue
        if att is None:
            continue
        try:
            data = _read_attachment_bytes(att)
        except Exception:
            data = b""
        filename = _attachment_filename(att) or f"attachment-{i + 1:03d}.bin"
        mime = _attachment_mime(att) or _guess_mime(filename)
        yield _Attachment(filename=filename, mime_type=mime, data=data or b"")


def _read_attachment_bytes(att: Any) -> bytes:
    """Best-effort read of an attachment's bytes.

    Preferred path: use libpff's stream ``read_buffer(size)`` (needs a
    prior implicit rewind, which we get from re-seeking to zero when
    possible). Fallback: pull the raw ``PR_ATTACH_DATA_BIN`` entry from
    the record set.
    """
    size = 0
    try:
        size = int(att.get_size() or 0)
    except Exception:
        size = 0

    if size > 0:
        fn = getattr(att, "read_buffer", None)
        if fn is not None:
            try:
                seek = getattr(att, "seek_offset", None)
                if seek is not None:
                    try:
                        seek(0, 0)
                    except Exception:
                        pass
                val = fn(size)
                if val:
                    return bytes(val)
            except Exception:
                pass

    # Fallback path via record_set property.
    return _pst.prop_bytes(att, PT_ATTACH_DATA_BIN)


def _attachment_filename(att: Any) -> str:
    long_name = _pst.prop_string(att, PT_ATTACH_LONG_FILENAME)
    if long_name:
        return long_name
    short = _pst.prop_string(att, PT_ATTACH_FILENAME)
    return short


def _attachment_mime(att: Any) -> str:
    return _pst.prop_string(att, PT_ATTACH_MIME_TAG)


def _guess_mime(filename: str) -> str:
    guess, _ = mimetypes.guess_type(filename or "")
    return guess or "application/octet-stream"


def _split_mime_type(mime: str, filename: str) -> tuple[str, str]:
    if mime and "/" in mime:
        maintype, subtype = mime.split("/", 1)
        subtype = subtype.split(";", 1)[0].strip()
        return maintype.strip() or "application", subtype or "octet-stream"
    guessed = _guess_mime(filename)
    maintype, subtype = guessed.split("/", 1)
    return maintype, subtype


# MIME (maintype, subtype) pairs that Python's ``email`` generator refuses to
# serialize when the payload is raw bytes rather than a nested Message list.
# ``message/delivery-status`` is the confirmed case (Python 3.13's
# ``Generator._handle_message_delivery_status`` iterates the payload assuming
# it is a list of Message objects; when we hand it bytes, the payload becomes
# a base64 string, iteration yields characters, and the first ``.policy``
# attribute lookup on a ``str`` raises AttributeError). Any future landmines
# discovered against real PST corpora belong here.
_UNSAFE_BYTES_MIME_TYPES: frozenset[tuple[str, str]] = frozenset(
    {
        ("message", "delivery-status"),
    }
)


# Characters that MUST NOT appear in an RFC 5322 header value.  We fold each
# to a single ASCII space so surrounding tokens are preserved for review.
_HEADER_UNSAFE_RE = re.compile(r"[\r\n\t\x00-\x1f\x7f]")

# Characters that MUST NOT appear inside a Content-Disposition filename.
# We swap these for ``_`` (rather than a space) so word boundaries are
# preserved when analysts read the filename back out of the EML.
_FILENAME_UNSAFE_RE = re.compile(r"[\r\n\t\x00-\x1f\x7f]")


def _sanitize_header_value(v: str | None) -> str:
    """Return ``v`` with all CR/LF/control chars folded to spaces.

    Python's SMTP policy rejects a header value containing raw CR/LF at
    serialization time. Some MAPI properties (Subject, filenames, display-*
    strings) preserve those chars from malformed messages; we sanitize
    defensively so extraction succeeds. The original bytes remain in the
    source PST for anyone who needs to re-examine them.
    """
    if not v:
        return ""
    cleaned = _HEADER_UNSAFE_RE.sub(" ", v)
    # Collapse runs of whitespace so a mangled header does not blow up
    # into a wall of spaces, but do not touch leading/trailing content
    # aggressively - only strip the outer edges.
    return re.sub(r"\s{2,}", " ", cleaned).strip()


def _sanitize_filename(name: str) -> str:
    """Sanitize a filename for embedding in a Content-Disposition header."""
    if not name:
        return "attachment.bin"
    cleaned = _FILENAME_UNSAFE_RE.sub("_", name).strip()
    # Also strip characters that break header folding: raw ``"`` inside a
    # quoted-string form; Python usually handles this but be conservative.
    cleaned = cleaned.replace('"', "_")
    return cleaned or "attachment.bin"


def _ascii_only_filename(name: str) -> str:
    """Fallback filename with non-ASCII stripped, for the last-resort path."""
    return "".join(c if 32 <= ord(c) < 127 and c != '"' else "_" for c in name) or "attachment.bin"


def _safe_split_mime_type(mime: str, filename: str) -> tuple[str, str, bool]:
    """Return ``(maintype, subtype, coerced)``.

    ``coerced=True`` means we substituted a safer type than the source
    claimed. Callers should record the original type in the resulting
    MIME part so evidence of the source claim is preserved.
    """
    maintype, subtype = _split_mime_type(mime, filename)
    coerced = False

    # Guard against invalid characters that would injection-attack the
    # Content-Type header (or trip verify_generated_headers).
    for candidate in (maintype, subtype):
        if _HEADER_UNSAFE_RE.search(candidate) or "/" in candidate:
            return "application", "octet-stream", True

    if (maintype.lower(), subtype.lower()) in _UNSAFE_BYTES_MIME_TYPES:
        return "application", "octet-stream", True

    return maintype, subtype, coerced


# ---------------------------------------------------------------------------
# Address formatting
# ---------------------------------------------------------------------------


def _format_addr(name: str, email: str) -> str:
    name = (name or "").strip()
    email = (email or "").strip()
    if not email:
        return name
    return formataddr((name, email))


def parse_date_header(headers: str) -> _dt.datetime | None:
    """Return the ``Date:`` header from a raw transport-headers block, as UTC."""
    val = _find_header(headers, "Date")
    if not val:
        return None
    from email.utils import parsedate_to_datetime

    try:
        dt = parsedate_to_datetime(val)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)
