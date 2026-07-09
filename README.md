# pst-slicer

Forensic extractor that pulls intact `.eml` files from a Microsoft
Outlook Personal Storage Table (`.pst`) based on a TOML configuration
file, and emits a chain-of-custody-friendly TSV manifest and run log
alongside them.

Alongside the core extractor, this repo ships three companion tools
(`pst-slicer-baseline`, `pst-slicer-verify`, `pst-slicer-intersect`)
and one stand-alone helper (`ost2pst`) that together cover the full
forensic workflow from evidence receipt through post-run audit.

- **Language / runtime:** Python 3.13+, single-file entry scripts
  whose shebangs are managed by the [`bootstrap`](./bootstrap) helper
  against a `uv`-managed venv. `ost2pst` is stdlib-only and
  independent of the venv.
- **PST reader:** [`libpff-python`](https://pypi.org/project/libpff-python/)
  (upstream libyal `libpff`) - opens the PST read-only via
  `pypff.file.open_file_object` on a file handle owned by this tool,
  so libpff is never given write intent on the evidence.
- **Per-message output:** RFC 5322 `.eml`, with the original
  `PR_TRANSPORT_MESSAGE_HEADERS` block preserved verbatim wherever the
  PST retained it.
- **Determinism:** every `.eml` and the `manifest.tsv` are byte-identical
  across re-runs given the same source PST. The manifest's `sha256`
  column is therefore reproducible after the fact.

---

## Requirements

- Linux or macOS host with a working C toolchain (`libpff-python`
  ships an sdist that compiles a C extension against the local
  Python).
- Python `>= 3.13`.
- [`uv`](https://docs.astral.sh/uv/) on `PATH` (used by
  [`bootstrap`](./bootstrap) to sync the venv).
- Read access to the source PST. The tool never modifies the source
  file, but disk space for the extracted `.eml` files plus manifest is
  required at the output path.
- Optional: `readpst` (from the `libpst-utils` package) is required
  only if you plan to use [`ost2pst`](./docs/companion-tools.md).

## Installation

From the repository root:

```bash
./bootstrap
```

`bootstrap` verifies `uv` is present, runs `uv sync` (which builds
the `pst_slicer` package plus the `libpff-python` C extension into
`.venv/`), and rewrites the shebangs of the four `pst-slicer*`
entry scripts to point at the venv's `python3`. `ost2pst` is left
alone because it is deliberately stand-alone. After bootstrap
succeeds, the tools are invoked directly by path:

```bash
./pst-slicer --version
./pst-slicer-baseline --version
./pst-slicer-verify --version
./pst-slicer-intersect --version
./ost2pst --version
```

## Quick start

For a typical case-file workflow - receive PST, baseline, extract,
verify - three commands cover the whole path:

```bash
# 1. baseline the input files BEFORE running anything else
./pst-slicer-baseline case-config.toml

# 2. run the extraction
./pst-slicer case-config.toml

# 3. verify the run (auto-writes <output.dir>/verify.log)
./pst-slicer-verify case-config.toml
```

Preserve `BASELINE.txt`, `run.log`, `manifest.tsv`, `verify.log`, and
the extracted `.eml` tree together as the deliverable. Every one of
those artefacts is either byte-identical across re-runs or
cryptographically fingerprinted, so a defense examiner can
independently verify every claim the tool makes.

For multi-PST cases (Exchange Online typically slices at ~10 GB),
run each PST as its own config, then intersect their `not_found.txt`
lists with [`pst-slicer-intersect`](./docs/companion-tools.md).

## The tool suite

| Tool | Purpose | Docs |
|------|---------|------|
| `pst-slicer` | The core extractor. Given a TOML config, walks a PST and emits intact `.eml` files matching the configured mode, plus `manifest.tsv`, `run.log`, and `not_found.txt`. | [CLI + config reference](./docs/cli-and-config.md) ~ [Match modes](./docs/match-modes.md) ~ [Output layout + manifest](./docs/output-and-manifest.md) |
| `pst-slicer-baseline` | Chain-of-custody baselining. Pre-run SHA-256 snapshot of every input file the extraction will touch. `--verify` re-checks a prior baseline. | [Companion tools](./docs/companion-tools.md) |
| `pst-slicer-verify` | Post-run four-check audit: source PST unchanged, manifest / disk / run.log counts agree, every EML's SHA-256 matches its manifest row, coercion audit. Auto-writes `verify.log` next to the run outputs. | [Companion tools](./docs/companion-tools.md) |
| `pst-slicer-intersect` | Cross-PST IMID analysis. Given N parallel IMID-mode runs, computes the set of IMIDs that were not matched in ANY run. | [Companion tools](./docs/companion-tools.md) |
| `ost2pst` | Stand-alone stdlib-only script. Converts an Outlook OST to a portable mailbox format (MBOX / per-message EML) via `readpst`, with chain-of-custody hashing and a manifest. | [Companion tools](./docs/companion-tools.md) |

Every tool's `-v/--version`, `-h/--help`, and error output is
colorized and TTY-aware; the `--help` for each tool is the in-band reference for its exact options.

## Forensic soundness at a glance

- **Read-only PST access.** The source PST is opened on a file handle
  the tool owns, so libpff never gets write intent on the evidence.
  The source's SHA-256 is recorded in `run.log` before the walk.
- **Deterministic output.** Given the same source PST, every re-run
  produces byte-identical `.eml` files and a byte-identical
  `manifest.tsv`. The SHA-256 column is reproducible after the fact.
- **Transparent metadata coercion.** In the small fraction of cases
  where source attachment metadata violates RFC 5322 in ways that
  would make the resulting EML unserializable, pst-slicer applies a
  fixed, published rule and records the original source claim on the
  affected MIME part via `X-PstSlicer-Original-*` headers. Full
  defensibility argument in [Forensic soundness](./docs/forensic-soundness.md).
- **Independently verifiable.** Every claim the tool makes can be
  re-checked without trusting pst-slicer: re-hash the source PST,
  re-hash the EMLs, read the coercion headers in plain ASCII,
  base64-decode any coerced attachment to recover source bytes, or
  re-run the tool. `pst-slicer-verify` mechanizes all of that.

Read the full [Forensic soundness](./docs/forensic-soundness.md)
document before treating output from this tool as evidence.

## Documentation

- [CLI + config reference](./docs/cli-and-config.md) - every tool's
  command-line surface, the TOML config schema, environment
  variables, and exit codes.
- [Companion tools](./docs/companion-tools.md) - practitioner guide
  to `pst-slicer-baseline`, `pst-slicer-verify`,
  `pst-slicer-intersect`, and `ost2pst`.
- [Match modes](./docs/match-modes.md) - how the five match modes
  (IMID, keyword, sender, sender_domain, attachment_ext) work, with
  a sample config for each.
- [Output layout, manifest, run log, EML filenames](./docs/output-and-manifest.md)
  - the on-disk shape of an extraction and how filenames are
  derived.
- [Forensic soundness](./docs/forensic-soundness.md) -
  implementation statements and the full defensibility argument for
  the `X-PstSlicer-Original-*` headers.
- [Testing / sample runs](./docs/testing.md) - the sample configs
  under `tests/` and expected outputs.

## License

GPL-3.0-or-later. See individual source files for SPDX identifiers.
