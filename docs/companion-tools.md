# Companion tools

The pst-slicer suite ships four tools that surround the core
extractor. Each has its own `--help` (colorized, TTY-aware) that is
the authoritative option reference. This document explains **when** to
run each tool and **why** it exists in forensic terms.

- [Chain-of-custody baselining (`pst-slicer-baseline`)](#chain-of-custody-baselining-pst-slicer-baseline)
- [Post-run verification (`pst-slicer-verify`)](#post-run-verification-pst-slicer-verify)
  - [Auto-written `verify.log`](#auto-written-verifylog)
- [Cross-PST intersection (`pst-slicer-intersect`)](#cross-pst-intersection-pst-slicer-intersect)
- [OST conversion (`ost2pst`)](#ost-conversion-ost2pst)

## Chain-of-custody baselining (`pst-slicer-baseline`)

`./pst-slicer-baseline` captures an immutable pre-run snapshot of every
input file the extraction will touch - the source PST(s) and any
on-disk IMID list files - so the case record can prove what the
evidence looked like at the moment the analyst received it, before any
tool was ever pointed at it.

```bash
./pst-slicer-baseline case-config.toml
./pst-slicer-baseline case-config-001.toml case-config-002.toml case-config-003.toml
./pst-slicer-baseline --verify case-config-001.toml case-config-002.toml case-config-003.toml
```

For each config supplied, the tool resolves `input.pst` and (when
IMID mode is used with a file-backed target list) `mode.imid.file`,
then streams SHA-256 over each unique file. If several configs
reference the same physical file (e.g. all three slice-runs share one
`unique_imids.txt`), it appears once in the artifact with every
referencing config recorded under `referenced_by`.

Output location:

- Exactly one config -> `<config.output.dir>/BASELINE.txt` (co-locates
  with the run outputs that will land there later).
- Multiple configs -> `<common_parent>/BASELINE.txt`, i.e. the deepest
  common ancestor of every config's output directory.
- Override either with `-o/--output-dir`.

`BASELINE.txt` is human-readable and machine-parseable. It records:

- UTC generation timestamp, tool version, hostname, user, Python
  version, and platform (chain-of-custody provenance).
- Every config path baselined.
- For each unique input file: role (`input_pst` / `imid_list`),
  referencing configs, absolute path, size in bytes, UTC mtime,
  SHA-256, and the hashing duration.
- A summary block with total files and total bytes hashed.

Two modes:

- **Write mode (default).** Produces `BASELINE.txt`. Refuses to
  overwrite an existing baseline unless `--force` is passed, so an
  accidental re-run cannot destroy the original chain-of-custody
  snapshot.
- **`--verify` mode.** Reads the previously written `BASELINE.txt`,
  streams SHA-256 over each recorded file again, and compares. Any
  size or hash mismatch is reported per-file and forces exit code `1`.
  Use this whenever evidence storage is moved, restored from backup,
  or checked out onto a new workstation to prove nothing changed in
  transit.

Independent verification: because `sha256` covers the raw file bytes,
any auditor can spot-check any row with `sha256sum <path>` and get
the same digest.

Exit codes:

| Code | Meaning |
|------|---------|
| `0`  | Baseline written (write mode) or all files match (`--verify`). |
| `1`  | `--verify`: at least one recorded file failed to match. |
| `2`  | Setup problem (bad config, unwritable output dir, missing baseline in `--verify`, ...). |
| `130`| Interrupted by user (Ctrl-C). |

## Post-run verification (`pst-slicer-verify`)

The companion tool `./pst-slicer-verify` runs a four-check verification
protocol against the outputs of a completed extraction. Point it at the
**same TOML config** you passed to `pst-slicer` - it re-resolves
`[input].pst` and `[output].dir` from the config itself, so the audit
and the run cannot disagree about which files they are talking about.

```bash
./pst-slicer-verify path/to/config.toml
```

Exit codes: `0` if all four checks pass, `1` if any check fails, `2` if
the audit could not run (missing config, missing `run.log`, unreadable
output directory, ...).

The four checks:

1. **Source PST unchanged.**
   Re-hashes the source PST with SHA-256 and compares to
   `input_pst_sha256` in `run.log`. Also compares on-disk size to
   `input_pst_size_bytes`. Proves the evidence file was not mutated
   between extraction and verification.

2. **Manifest / disk / run.log count agreement.**
   The number of data rows in `manifest.tsv` MUST equal the number of
   `.eml` files under the output tree, and BOTH must equal the
   `eml_files_written` counter in `run.log`. Detects orphaned files,
   missing files, truncated manifests, and any drift between the three
   independent views of what was written.

3. **Manifest fingerprints vs on-disk bytes.**
   For every row in `manifest.tsv`, re-reads the corresponding EML,
   recomputes SHA-256 and byte size, and compares to the manifest's
   `sha256` and `size_bytes` columns. This is the cryptographic proof
   that the manifest is truthful.

4. **Coercion audit (informational).**
   Scans every extracted EML for `X-PstSlicer-Original-Content-Type`
   and `X-PstSlicer-Original-Filename` annotations and reports how
   many messages contained coerced attachments plus the distribution
   of what was coerced. This surfaces the sanitization mechanism
   described in [Forensic soundness](./forensic-soundness.md).
   Coercion is not a failure - this check reports `PASS` as long as
   there are EMLs to audit; a `FAIL` here means the output tree is
   empty, which check 2 will already have caught.

### Auto-written `verify.log`

Every run of `pst-slicer-verify` automatically captures the terminal
session to `<output.dir>/verify.log` (ANSI-stripped, plain UTF-8) so
the analyst gets a preservation-ready audit record without needing
`tee`. The TTY still receives colored output; only the on-disk copy
is stripped so it is grep-friendly. Suppress the auto-log with
`--no-log` when you want a truly read-only invocation.

Suggested workflow for a case file:

```bash
# 1. baseline the inputs BEFORE running anything else
./pst-slicer-baseline case-config.toml

# 2. run the extraction
./pst-slicer case-config.toml

# 3. verify the run (auto-writes <output.dir>/verify.log)
./pst-slicer-verify case-config.toml
```

Preserve `BASELINE.txt` (produced by pst-slicer-baseline, at the
output directory), `run.log` (produced by pst-slicer, inside the
output directory), and `verify.log` (auto-written by pst-slicer-verify
into the same output directory) as part of the deliverable. Together
they document what was received, what was extracted, and independently
confirm the extraction was faithful, byte-for-byte, to what the
manifest claims.

## Cross-PST intersection (`pst-slicer-intersect`)

When a single mailbox has been sliced into multiple PSTs (Exchange
Online exports typically split at ~10 GB boundaries), the same IMID
target list must be run against every slice as an independent
`pst-slicer` invocation. `not_found.txt` from any *one* of those runs
only reports IMIDs missing from *that* PST - it does not answer
"which IMIDs are missing from the entire evidence set?"

`./pst-slicer-intersect` answers that question. Given two or more
TOML configs from parallel IMID-mode runs, it intersects every run's
`not_found.txt` to produce the set of IMIDs that were not matched in
**any** run.

```bash
./pst-slicer-intersect \
  -o path/to/case-dir \
  configs/case-001.toml \
  configs/case-002.toml \
  configs/case-003.toml
```

`-o/--output-dir` is optional; if omitted, the artifacts land in the
common parent of every run's output directory (e.g. `.../imid/` when
the runs live at `.../imid/001`, `.../imid/002`, `.../imid/003`).

Preconditions enforced at startup (exit 2 if any fail):

- All configs are `mode.type = "IMID"`. Other modes have no
  meaningful cross-run intersection.
- All configs reference the **same** normalized IMID universe. If
  two configs disagree on the target list, the intersection is
  ill-defined and the tool refuses to proceed rather than silently
  union the sets.
- Each config's `output.dir/not_found.txt` exists and is readable.

Artifacts written:

- **`unmatched_across_all_psts.txt`** - one IMID per line, in the
  original spelling from the input list, sorted case-insensitively.
  Suitable for handing back to the party who provided the target
  list ("of the N IMIDs you gave us, these are the ones we could
  not locate anywhere in the evidence").
- **`unmatched_summary.txt`** - provenance record. UTC timestamp,
  tool version, every config path + resolved output dir + input PST
  path, and a full match-count distribution across the runs
  (matched in exactly zero runs, exactly one, ..., exactly all N).
  Suitable for the case-file audit trail.

Both artifacts are plain UTF-8. `unmatched_across_all_psts.txt` is
deterministic across analyses (byte-identical from run to run given
the same inputs), so its SHA-256 is a stable citation for the case
report.

Exit codes:

| Code | Meaning |
|------|---------|
| `0`  | Analysis completed and artifacts written. (The count of universally-unmatched IMIDs is informational, not an error.) |
| `2`  | Setup / input problem (bad config, mixed universes, missing `not_found.txt`, unwritable output dir). |
| `130`| Interrupted by user (Ctrl-C). |

## OST conversion (`ost2pst`)

`./ost2pst` is a **completely stand-alone stdlib-only Python 3
script**. It has no dependency on `pst_slicer` and can be dropped
into any tools directory. It converts an Outlook OST file to a
portable mailbox format for downstream forensic and e-discovery
work, wrapped with the same chain-of-custody rigor as the rest of
the suite.

```bash
./ost2pst /evidence/mailbox.ost /case/output      # default: MBOX per folder
./ost2pst --format eml /evidence/mailbox.ost /case/output
./ost2pst --include-deleted /evidence/mailbox.ost /case/output
```

**Important limitation.** No free, open-source Linux tool writes
native Microsoft PST format. Every open-source Personal Folder File
library (libpff, libpst) ships read-only support; the only tools that
can produce a real `.pst` file are proprietary and Windows-only
(Outlook itself, Stellar OST-to-PST, Kernel for OST, SysTools, ...).
On Linux this tool therefore converts OST **to MBOX or per-message
EML** using [`readpst`](https://linux.die.net/man/1/readpst) from the
`libpst-utils` package as the actual mailbox reader.

For 99% of downstream forensic and e-discovery workflows MBOX or EML
is a **better** intermediate than PST anyway: both are RFC-standardized
plain text, both are trivially indexable by every e-discovery
platform, and both round-trip losslessly through every forensic mail
tool including `pst-slicer` itself. If you truly need a native `.pst`
file (e.g. because the receiving party's tooling demands it), feed
the resulting MBOX/EML tree to a Windows-based OST-to-PST converter
or import it into Outlook via `File > Open & Export`.

What the tool does beyond invoking `readpst`:

1. **Signature check.** Refuses to run on anything that is not a
   Personal Folder File (`!BDN` / `0x21424E44` magic - the signature
   is shared by OST and PST). Prevents pointing `readpst` at
   arbitrary data.
2. **SHA-256 chain of custody.** Streams SHA-256 over the input file
   both *before* and *after* the conversion and records both values
   in `CONVERSION.txt`. Proves `readpst` did not mutate the OST
   (`readpst` opens read-only; this check is belt-and-suspenders).
3. **Output manifest.** After the conversion, walks the output tree
   and records `relative_path`, `size_bytes`, and `sha256` for every
   file in `MANIFEST.tsv`.
4. **Provenance record.** Writes `CONVERSION.txt` with UTC start /
   end timestamps, tool version, `readpst` path + version, hostname,
   user, Python version, platform string, the exact invocation, and
   a 40-line excerpt of `readpst`'s stdout/stderr. Preserves the
   record even when `readpst` fails, so the failure itself is on
   record.

Artifacts under `OUTPUT_DIR`:

- `messages/` - the raw output tree produced by `readpst`.
- `MANIFEST.tsv` - every file under `messages/` with SHA-256 + size.
- `CONVERSION.txt` - provenance + invocation record.

Requires `readpst` on `PATH`:

```bash
sudo apt install libpst-utils    # Debian / Ubuntu
sudo dnf install libpst          # Fedora / RHEL
brew install libpst              # macOS / Homebrew
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0`  | Conversion succeeded and manifest written. |
| `1`  | `readpst` returned non-zero (partial `CONVERSION.txt` is still written for the audit trail). |
| `2`  | Setup problem (bad path, wrong signature, `readpst` missing, unwritable output dir, ...). |
| `130`| Interrupted by user (Ctrl-C). |

`OST2PST_NO_COLOR` / `NO_COLOR` disable colored output;
`OST2PST_FORCE_COLOR` / `FORCE_COLOR` force it. TTY-detection is
otherwise automatic.
