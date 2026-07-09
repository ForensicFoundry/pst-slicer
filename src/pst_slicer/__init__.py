# SPDX-License-Identifier: GPL-3.0-or-later
"""pst-slicer: forensic PST message extractor.

Configuration-driven extraction of intact ``.eml`` files from PSTs,
matched (v1) by Internet Message-ID; keyword, sender, sender_domain,
and attachment-extension modes added in v2. Emits a TSV manifest and
a run log capturing tool version, source PST SHA-256, and per-message
integrity hashes.

Versioning: CalVer ``YY.MM`` (e.g. ``26.07`` = July 2026).
The value below is authoritative for CLI display and manifest/run-log
provenance. ``pyproject.toml`` carries a PEP 440-compliant twin
(without the leading zero) so ``uv`` / ``hatch`` builds succeed, but
nothing user-facing uses the metadata value.
"""

from __future__ import annotations

__version__: str = "26.07"

__all__ = ["__version__"]
