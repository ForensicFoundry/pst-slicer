# Testing / sample runs

The [`tests/`](../tests/) directory contains one representative config
per mode under [`tests/configs/`](../tests/configs/). Each config
carries a mix of **true positives** (values known to exist in the
sample PST) and **true negatives** (syntactically valid but absent
values). After running any of them the corresponding output goes
under `tests/runs/<mode>/`.

`tests/` is git-ignored (see [`.gitignore`](../.gitignore)); the
configs themselves are safe to commit if you want them under version
control, run artefacts will not be.

Manual invocation:

```bash
./pst-slicer tests/configs/imid.toml
./pst-slicer tests/configs/keyword.toml
./pst-slicer tests/configs/sender.toml
./pst-slicer tests/configs/sender_domain.toml
./pst-slicer tests/configs/attachment_ext.toml
```

Each run should produce, at the corresponding
`tests/runs/<mode>/`:

- one `.eml` per matched message under the mirrored PST folder tree,
- a `manifest.tsv` whose row count equals the matched count,
- a `not_found.txt` containing exactly the configured true-negative
  entries (nothing else),
- a `run.log` recording the source PST SHA-256 and per-run counts.
