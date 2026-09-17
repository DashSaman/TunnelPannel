#!/usr/bin/env python3
"""MTF engine entrypoint — runs API panel + failover engine in one process."""
import sys

sys.path.insert(0, "/opt/multitunnel/engine")

from mtf.api import main  # noqa: E402

if __name__ == "__main__":
    main()
