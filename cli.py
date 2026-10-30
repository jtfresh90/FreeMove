#!/usr/bin/env python3
"""FreeMove command-line entry point (see `freemove/cli.py`)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from freemove.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
