# Baysöz Labs <baysozlabs@proton.me> — python -m entry point.
"""Allow ``python -m baysoz_archivebound`` entry-point execution."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
