# Output layout, manifest, run log, EML filenames

Every `pst-slicer` invocation produces a self-describing output tree:
extracted `.eml` files under a mirror of the PST's folder hierarchy,
plus three top-level bookkeeping artifacts (`manifest.tsv`,
`run.log`, `not_found.txt`).

- [Output layout](#output-layout)
- [Manifest columns](#manifest-columns)
- [Run log](#run-log)
- [How EML filenames are chosen](#how-eml-filenames-are-chosen)

## Output layout

The output directory mirrors the PST's folder hierarchy. Given a PST
whose Inbox contains a message that matches, the tool produces:

```
output/
├── manifest.tsv
├── not_found.txt
├── run.log
└── <PST-folder-tree>/
    └── Inbox/
        └── 20260413T143559Z__353f4735aabf.eml
```

- Folder names from the PST are used verbatim after light sanitization
  (any of `< > : " / \ | ? *` or control characters replaced with
  `_`; trailing dots/spaces stripped).
- `manifest.tsv`, `not_found.txt`, and `run.log` always sit at the
  output root, regardless of match mode.

## Manifest columns

The manifest is TSV with a header row on line 1. All timestamps are
UTC in `YYYY-MM-DD HH:MM:SS` format; empty timestamps are the empty
string (never a `-` or `null`).

| Column                       | Source / meaning |
|------------------------------|------------------|
| `imid`                       | `PR_INTERNET_MESSAGE_ID` from the extracted message |
| `match_reason`               | `<mode>:<matched-value>[ [<detail>]]` |
| `client_submit_time_utc`     | `PR_CLIENT_SUBMIT_TIME` (when the sender sent it) |
| `message_delivery_time_utc`  | `PR_MESSAGE_DELIVERY_TIME` (when the server delivered) |
| `date_header_utc`            | `Date:` header parsed from `PR_TRANSPORT_MESSAGE_HEADERS` |
| `sender`                     | `PR_SENT_REPRESENTING_NAME` + `<...SMTP_ADDRESS>` |
| `recipients`                 | `To: ... ; Cc: ... ; Bcc: ...` from MAPI display fields |
| `subject`                    | `PR_SUBJECT` |
| `size_bytes`                 | Byte size of the on-disk `.eml` |
| `sha256`                     | SHA-256 hex of the on-disk `.eml` |
| `source_folder`              | POSIX-style path within the PST |
| `source_pst`                 | Basename of the input PST |
| `output_path`                | Path to the `.eml` relative to the output root |

TSV-hostile characters (tab, CR, LF) are replaced with spaces in cell
values so a single pathological subject can't shear the manifest. The
original values are preserved intact inside the `.eml` itself.

## Run log

`run.log` is a plain-text ledger written at the output root. It
captures:

- The tool version and Python interpreter used.
- The absolute path of the source PST, its byte size, and its
  **SHA-256** (computed read-only, before any walking).
- The config's absolute path, the mode selected, and the resolved
  output directory.
- Start/end UTC timestamps and elapsed seconds.
- Counts: messages scanned, messages matched, `.eml` files written,
  individual-message failures, and unmatched target count.
- A verbatim dump of the parsed config values.

This file is the primary chain-of-custody artefact and should be
preserved alongside the extracted `.eml` set. See also
[Forensic soundness](./forensic-soundness.md) for how `run.log` fits
into the full audit trail.

## How EML filenames are chosen

Every extracted message lands at a path of the form:

```
<PST-folder-mirrored>/<submit-time-UTC>__<sha1(IMID)[:12]>.eml
```

**Example:** `20260413T143559Z__353f4735aabf.eml`

The `<submit-time-UTC>` component is `YYYYMMDDTHHMMSSZ` (ISO 8601
basic profile) derived from `PR_CLIENT_SUBMIT_TIME`; the `__` is a
double-underscore separator; the 12-hex-char tail is the first 48
bits of the SHA-1 of the Internet Message-ID.

The convention is defined in `_eml_filename` in
[`src/pst_slicer/extract.py`](../src/pst_slicer/extract.py). It was
chosen for these reasons, in decreasing order of priority:

1. **Chain-of-custody reproducibility.** Every component is derived
   deterministically from the message content, so two runs against
   the same PST produce identical filenames. This is a hard
   requirement for defensibility - if the filename ever varied
   between runs, the manifest's `output_path` could not be
   independently verified after the fact.
2. **Chronological sortability at a glance.** The
   `YYYYMMDDTHHMMSSZ` prefix means `ls -1` sorts messages by
   submit-time (the timestamp that most closely reflects when the
   sender clicked *Send*), which is how reviewing counsel naturally
   scan an extract set. The `Z` suffix makes the UTC intent explicit
   in the filename itself; there is no timezone ambiguity.
3. **Uniqueness without leaking evidence.** The 12-hex-char SHA-1
   fingerprint of the IMID provides 48 bits of entropy - a birthday
   collision would require ~16.7 million messages with the same
   submit-second before crossing a ~1% collision probability. Vastly
   more than any realistic e-discovery export. Meanwhile the full
   IMID often contains sensitive information (sender identifiers,
   tenant IDs, message routing metadata) that would be inappropriate
   to display in `ls` listings on a shared machine. SHA-1 is used
   purely as a compact fingerprint; no cryptographic security is
   assumed.
4. **Filesystem-portable.** Only characters in `[A-Z0-9_.]` appear
   in the generated segment, so filenames are safe on NTFS, exFAT,
   ext4, HFS+, ZFS, and SMB shares, and case-safe on
   case-insensitive filesystems.
5. **Uninformative by default.** Subject line and sender name are
   deliberately kept out of the filename. `ls` in the export
   directory does not leak message content or PII; the manifest is
   the correlation layer.
6. **Graceful fallbacks.**
   - Submit-time missing -> falls back to
     `PR_MESSAGE_DELIVERY_TIME`.
   - Both missing -> the prefix becomes `unknown-time`.
   - IMID missing -> the hash input becomes `id-<pst-internal-id>`,
     so we still produce a stable, unique filename.
7. **Collision safety at the filesystem layer.** If a name still
   somehow collides (e.g. a duplicate PST item with the identical
   IMID and identical submit-time), the atomic-write step appends
   `__dup001`, `__dup002`, etc. rather than overwriting. The export
   set is guaranteed lossless.

If you ever need a different convention (e.g. include a subject
preview, drop the hash suffix, or embed the mode name), only
`_eml_filename` needs to change - nothing else in the pipeline
depends on the format.
