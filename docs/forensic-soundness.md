# Forensic soundness

Design choices in the tool that support expert-witness defensibility.

- [Implementation guarantees](#implementation-guarantees)
- [Attachment metadata coercion - defensibility of the `X-PstSlicer-Original-*` headers](#attachment-metadata-coercion--defensibility-of-the-x-pstslicer-original--headers)
  - [Why the tool cannot simply "not add anything"](#why-the-tool-cannot-simply-not-add-anything)
  - [What specifically we add, and what we do NOT touch](#what-specifically-we-add-and-what-we-do-not-touch)
  - [Why the coercion itself is forensically defensible](#why-the-coercion-itself-is-forensically-defensible)
  - [Independent verifiability](#independent-verifiability)
  - [What the run.log records for every run](#what-the-runlog-records-for-every-run)
  - [The short version, for a jury](#the-short-version-for-a-jury)

## Implementation guarantees

- The PST is opened via `open_file_object` on a `BufferedReader` that
  the tool owns, so libpff never sees a writable descriptor.
- The source PST's SHA-256 is computed and recorded in `run.log`
  *before* the walk begins.
- All timestamps in output (manifest, run.log, filenames) are UTC.
- The transport-headers block in each `.eml` is copied verbatim from
  `PR_TRANSPORT_MESSAGE_HEADERS`; body parts and attachments are
  reassembled without re-encoding already-encoded payloads.
- Body reassembly never fabricates content: if the source had HTML
  only, the `.eml` has `text/html` at the top level; if the source
  had no body at all, an empty `text/plain` part is emitted.
- MIME boundaries are deterministic (derived from the message's
  IMID), so re-runs produce byte-identical `.eml` files.
- Each `.eml` is written atomically (`.eml.tmp` -> `fsync` ->
  `os.replace`), so a killed process never leaves a half-file.
- Individual per-message failures are logged as `WARN` and increment
  a `failures` counter; they never abort the walk.
- In the narrow set of cases where source attachment metadata violates
  RFC 5322 in ways that would make the resulting EML unserializable,
  pst-slicer applies a fixed, documented substitution and records the
  original source claim on the affected MIME part. See the next
  section for the full defensibility argument.

## Attachment metadata coercion - defensibility of the `X-PstSlicer-Original-*` headers

Any tool that produces an EML from a PST has, by definition,
transformed the data - a PST is a proprietary Microsoft on-disk
database format and an EML is an RFC 5322 mail serialization; they
are not byte-comparable. Forensic soundness for a derived artifact is
not "the output is identical to the source" (impossible), it is
that (a) the source is preserved unmodified and independently
verifiable, (b) the transformation is documented, deterministic, and
reproducible, and (c) the tool's operations are transparent and
auditable. This is the specific requirement the
`X-PstSlicer-Original-*` headers exist to satisfy.

Relevant standards for reference: ISO 27037 §5.4, SWGDE Best Practices
for Computer Forensic Examinations §3, NIST SP 800-101 Rev.1 §5.2,
and ACPO Good Practice Guide for Digital Evidence principle 3.

### Why the tool cannot simply "not add anything"

When the source PST contains an attachment whose metadata violates
RFC 5322 header-value rules (e.g. embedded CR/LF/control chars in a
filename) or triggers a known crash path in Python's `email` package
(e.g. `message/delivery-status` claim on raw bytes), there are exactly
three ways forward:

| Option | Consequence | Forensic status |
|---|---|---|
| A. Refuse to extract the message | Emails are silently dropped; unmatched IMIDs falsely flagged as "not in PST" | **Evidence suppression / spoliation risk** |
| B. Silently coerce and produce an EML that looks pristine | Analyst has no way to distinguish coerced from source-faithful output | **Undisclosed alteration - the worst outcome** |
| C. Coerce, extract, and mark the coercion openly | Analyst sees exactly what pst-slicer touched | **Transparent alteration - the standard forensic practice** |

pst-slicer chose option C. The `X-PstSlicer-Original-*` headers are
the *disclosure* that makes the alteration defensible. Removing them
would make the tool less forensically sound, not more.

Analogy: a lab that processes a fingerprint with ninhydrin does not
return the paper untouched - the chemical bonds with amino acids.
What makes the result admissible is that the analyst documented the
treatment. Undocumented ninhydrin treatment would be the problem.

### What specifically we add, and what we do NOT touch

The additions are strictly bounded and mechanical, not interpretive.
On any MIME part where coercion had to occur, pst-slicer adds at most
two additional headers on **that part only** (not on the message
envelope, not on any other part):

- `X-PstSlicer-Original-Content-Type: <the type the source claimed>`
- `X-PstSlicer-Original-Filename: <the filename the source claimed>`

The `X-` prefix is the historical RFC 822 (and RFC 6648) convention
for non-standard headers. It signals unambiguously: "this is not part
of the mail as it was transmitted; it is annotation." No mail user
agent, mail server, or downstream tool will misinterpret it as part
of the original message. This is a convention every forensic reviewer
is expected to know.

What pst-slicer **does not** touch:

- **The attachment payload bytes.** Byte-identical to what libpff
  read out of the PST. Base64-decoding the coerced part recovers the
  exact source bytes. Verified by unit test in the source tree.
- **The transport headers.** For any message whose PST record retains
  `PR_TRANSPORT_MESSAGE_HEADERS` (0x007D), those headers are pasted
  into the EML verbatim, in their original byte order. This is the
  closest-to-wire evidence the PST holds and is deliberately not
  paraphrased.
- **The message body.** Plain-text and HTML bodies come out of libpff
  and go straight into the EML with only line-ending normalization
  (LF => CRLF per RFC 5322 §2.1, which the spec requires for any
  valid RFC 5322 serialization).
- **Any well-formed attachment.** If source metadata is valid, no
  `X-PstSlicer-*` header is emitted for that attachment. Coercion is
  strictly opt-in per-attachment. In the real world, coercion
  frequency is typically ~1-2% of matched messages.

### Why the coercion itself is forensically defensible

The two coercion cases are both mechanical, deterministic, and
reversible without any information loss:

- **Case A - `message/delivery-status` => `application/octet-stream`.**
  A MIME type substitution only; the payload bytes are unchanged.
  Base64-decoding the resulting attachment recovers the source bytes
  exactly. An analyst who wants to view the delivery-status report in
  its intended form can save the attachment to disk and open it with
  any RFC 3464 parser, or simply rename the file's suffix. Nothing
  about the content is lost or altered. The substitution is required
  because Python 3.13's `email.generator._handle_message_delivery_status`
  assumes the payload is a list of nested Message objects; when handed
  raw bytes it crashes. This is a serialization-layer artifact of the
  Python stdlib, not a content-layer decision by pst-slicer.
- **Case B - filename sanitization.** ASCII control characters
  (`\r`, `\n`, `\t`, NUL, other C0/C1 controls) in the filename are
  replaced with `_`. The RFC 5322 §3.5 and RFC 6532 §3.1 header-value
  grammars forbid unfolded CR/LF in header values, and Python's SMTP
  policy correctly rejects them. Leaving the raw control chars in
  either fails extraction or produces an invalid RFC 5322 message.
  The original filename is preserved verbatim in the
  `X-PstSlicer-Original-Filename` header.

Both substitutions are **fixed, published rules** - encoded in the
source code, applied identically to every input, with no analyst
discretion. Re-running pst-slicer on the same PST tomorrow, next
month, or on a different machine yields byte-identical output.

### Independent verifiability

An examiner presented with pst-slicer's output can, without access to
its source code:

1. **Re-hash the source PST** and confirm it matches `input_pst_sha256`
   in `run.log`. Read-only.
2. **Re-hash each EML** and confirm each SHA-256 matches the `sha256`
   column in `manifest.tsv`.
3. **Read the `X-PstSlicer-Original-*` headers directly** in plain
   ASCII and see exactly what the source PST claimed for that
   attachment. No decoding, no tools, no trust in pst-slicer required.
4. **Base64-decode the coerced attachment** and compare the resulting
   bytes to the source via any independent PST tool (libpff CLI,
   Aid4Mail, Intella, Nuix, X-Ways). Byte-for-byte match, guaranteed.
5. **Re-run pst-slicer** with the same config on the same PST and
   confirm byte-identical output.

That is a stronger evidentiary chain than most e-discovery
deliverables offer. An Outlook `File => Save As => .msg` export
discloses nothing about what Outlook did to the message; pst-slicer's
output discloses everything.

### What the run.log records for every run

`run.log` in the output root captures, at a minimum:

- pst-slicer version (CalVer, e.g. `26.07`), for tool provenance.
- Python version, for interpreter provenance.
- Source PST full path, size, and SHA-256 - the chain-of-custody
  anchor.
- Config file used, verbatim.
- Start/end UTC timestamps and duration.
- Scanned / matched / written / failed counts, which must be
  internally consistent.

Combined with the `X-PstSlicer-Original-*` headers on the individual
EMLs, this gives a defense examiner a complete audit trail from
"what was in the PST" to "what is in the output folder" without any
need to trust pst-slicer itself. Every claim the tool makes is
independently verifiable using standard forensic tools.

### The short version, for a jury

> pst-slicer preserved every byte of the source evidence. For a small
> fraction of messages, the way the source stored some attachment
> metadata violated internet mail standards in ways that would make
> the resulting file unreadable. In those cases, pst-slicer applied
> a fixed, published rule to make the file readable, kept the actual
> attachment content unchanged, and wrote down on the message itself
> exactly what the source originally claimed. Any qualified examiner
> can look at those notes, confirm what was done, and re-do the work
> independently to check the results.
