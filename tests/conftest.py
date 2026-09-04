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

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Import `orchestrator.*` regardless of where pytest is invoked from.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# main.py's Jinja2Templates uses a path relative to CWD; anchor it at the root.
os.chdir(ROOT)


@pytest.fixture(autouse=True)
def _no_database_global_leak():
    """A test must put `orchestrator.database`'s globals back.

    DB_PATH and DB_DIR are module-level. A test that repoints them and does not
    restore silently changes what EVERY LATER TEST sees — and the corpus-backed
    tests degrade to `skip("corpus present but empty")` rather than failing, so
    the suite stays green while nine real assertions stop running. That is this
    project's defect signature reproduced inside its own test suite, and it
    happened: tests/test_declared.py did exactly this before this guard existed.

    Verified to bite: a test that assigns DB_PATH without restoring errors here.
    """
    import orchestrator.database as _db
    before = (_db.DB_DIR, _db.DB_PATH)
    yield
    after = (_db.DB_DIR, _db.DB_PATH)
    if before != after:
        pytest.fail(
            "test leaked orchestrator.database globals — restore them in a "
            f"finally/fixture: {before} -> {after}")
