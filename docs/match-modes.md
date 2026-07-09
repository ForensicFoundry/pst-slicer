# Match modes

`pst-slicer` supports five match modes. The mode is declared at the
top of the TOML config via `mode.type` and controls which sub-table
(`[mode.imid]`, `[mode.keyword]`, ...) is required.

Every mode records a `match_reason` column in the manifest of the form
`<mode>:<matched-value>[ [<detail>]]`, so provenance for each extracted
message is explicit.

- [IMID](#imid)
- [keyword](#keyword)
- [sender](#sender)
- [sender_domain](#sender_domain)
- [attachment_ext](#attachment_ext)

## IMID

Matches on `PR_INTERNET_MESSAGE_ID` (MAPI PidTag `0x1035`), falling
back to the `Message-ID:` header parsed from
`PR_TRANSPORT_MESSAGE_HEADERS` when the property is absent.

Normalization applied on both sides:
- strip leading/trailing whitespace,
- strip a single surrounding pair of angle brackets if present,
- casefold.

```toml
[mode]
type = "IMID"

[mode.imid]
list = [
    "<abc123@mail.gmail.com>",
    "def456@example.com",           # angle brackets are optional
]
# or, mutually exclusive with `list`:
# file = "imids.txt"                # newline-delimited, `#` comments allowed
```

Every IMID from the config that never fires goes into `not_found.txt`.

## keyword

Case-insensitive substring search (opt-in case-sensitive) across the
subject line and/or the body. Body search operates on `PR_BODY` plus
the HTML body stripped of tags via the stdlib `html.parser` - so
matches are against visible text rather than tag/attribute noise.

```toml
[mode]
type = "keyword"

[mode.keyword]
keywords = ["acquisition", "confidential", "wire transfer"]
fields = ["subject", "body"]        # optional; default is both
case_sensitive = false              # optional; default false
```

The `match_reason` detail records which field triggered the match
(e.g. `keyword:acquisition [subject]`). Keywords that never fire are
reported in `not_found.txt`.

## sender

Case-insensitive **exact** match against the sender's SMTP address.
The tool picks the sender address from
`PR_SENT_REPRESENTING_SMTP_ADDRESS`, then
`PR_SENDER_SMTP_ADDRESS`, then the legacy EX-format email fields, in
that order.

```toml
[mode]
type = "sender"

[mode.sender]
addresses = [
    "john.doe@example.com",
    "jane.doe@example.com",
]
```

## sender_domain

Case-insensitive match on the sender's SMTP domain. Configured
domains match themselves *and* any subdomain, so `example.com` will
match `bob@example.com`, `bob@mail.example.com`, and
`bob@corp.example.com`, but not `bob@notexample.com`.

```toml
[mode]
type = "sender_domain"

[mode.sender_domain]
domains = [
    "suspectdomain.com",
    "malicious.example",
]
```

## attachment_ext

Case-insensitive match on the extension of any attachment's filename.
Leading `.` is optional in the config.

```toml
[mode]
type = "attachment_ext"

[mode.attachment_ext]
extensions = [".pdf", ".js", "exe"]     # ".exe" also works
```

`match_reason` records the specific attachment filename that
triggered the match (e.g. `attachment_ext:.pdf [contract_v3.pdf]`).
