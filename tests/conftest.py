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


@pytest.fixture(autouse=True)
def _no_writes_under_data(request):
    """Fail the test that dirties the gitignored data/ tree, and name it.

    A clean clone has no data/. The suite must leave it that way: docs figures
    (REPRODUCIBILITY.md, README.md) are measured from a fresh clone, and
    test_reproducibility_doc's corpus check reads the tracked database as
    ground truth — a stray pentest.db, .secret_key or report written by a test
    makes those measurements diverge for reasons nobody wrote down. The remedy
    is always the same: point DB_PATH/DB_DIR, the secret key (ERLIK_SECRET_KEY
    or secrets.KEY_FILE) and main.REPORTS_DIR at tmp_path in the test's setup.

    This compares data/'s CONTENTS around each test, so it is inert on a
    developer machine that already holds a real corpus (data/ pre-exists and is
    unchanged); the WAL sidecars a read of that corpus may open are ignored.
    Only entries THIS test added are removed afterwards — a pre-existing corpus
    is never touched — so one leak does not cascade into failing every later
    test.
    """
    data = ROOT / "data"
    sidecars = ("-wal", "-shm", "-journal")

    def snap():
        if not data.exists():
            return set()
        return {p.relative_to(data) for p in data.rglob("*")
                if not p.name.endswith(sidecars)}

    before_exists = data.exists()
    before = snap()
    yield
    new = snap() - before
    leaked = bool(new) or (data.exists() and not before_exists)
    if not leaked:
        return
    # Undo only what this test added (deepest paths first so dirs end empty);
    # never remove anything that predated the test.
    for rel in sorted(new, key=lambda p: len(p.parts), reverse=True):
        p = data / rel
        try:
            if p.is_dir():
                if not any(p.iterdir()):
                    p.rmdir()
            else:
                p.unlink()
        except OSError:
            pass
    if not before_exists and data.exists():
        try:
            data.rmdir()
        except OSError:
            pass
    pytest.fail(
        f"{request.node.nodeid} created paths under the gitignored data/ tree: "
        f"{sorted(str(p) for p in new) or ['<empty data/ directory>']}. "
        "Redirect DB_PATH/DB_DIR, ERLIK_SECRET_KEY (or secrets.KEY_FILE) and "
        "main.REPORTS_DIR at tmp_path in this test's fixtures.")
