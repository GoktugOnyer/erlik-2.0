"""Shared test setup.

`orchestrator.main` builds a FastAPI app and a Jinja2Templates(directory=
"dashboard/templates") at import time (both are cheap and side-effect free —
init_db() runs only inside the lifespan handler, not on import). The Jinja
directory is a *relative* path, so the process CWD must be the repo root for the
import to succeed. We also make sure the repo root is importable.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Import `orchestrator.*` regardless of where pytest is invoked from.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# main.py's Jinja2Templates uses a path relative to CWD; anchor it at the root.
os.chdir(ROOT)
