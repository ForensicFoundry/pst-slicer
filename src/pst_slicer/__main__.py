# SPDX-License-Identifier: GPL-3.0-or-later
"""Support ``python -m pst_slicer``."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
