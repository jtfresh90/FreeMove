#!/usr/bin/env python3
"""PyInstaller entry point for FreeMove.exe.

Double-clicking the executable opens the GUI; command-line arguments
run the CLI instead (attach a console / use the .exe from a terminal).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from freemove.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
