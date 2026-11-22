"""Launcher used by the packaged executable and for running from source.

    .venv\\Scripts\\python.exe run_sentinel.py
"""

import sys

from sentinel_test_lab.app.main import main

if __name__ == "__main__":
    sys.exit(main())
