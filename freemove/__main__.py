"""Entry point: `python -m freemove` (GUI with no args, else CLI)."""

import sys

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
