"""Enable ``python -m soc_connectors``."""

from __future__ import annotations

import sys

from soc_connectors.cli import main

if __name__ == "__main__":
    sys.exit(main())
