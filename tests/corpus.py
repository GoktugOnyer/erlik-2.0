"""The recorded corpus, or an honest skip.

`data/` is gitignored — it holds real client findings — so a fresh clone has no
database. Several tests guard on `DB.exists()` and then query, which is not the
same question: something in the suite creates an EMPTY data/pentest.db, so the
guard passes and the query fails with "no such table: findings".

The effect was that seven tests FAILED and nine ERRORED on a clean checkout,
reading as product defects to anyone who had just cloned the repo — and they
would have made CI red on its first run for a reason that is not a bug.

One definition, used by every corpus-dependent test: the corpus exists when the
schema is there AND has rows. Anything else is a skip that says which.
"""

from pathlib import Path
import sqlite3

import pytest

DB = Path(__file__).resolve().parents[1] / "data" / "pentest.db"


def rows(query: str, params: tuple = (), *, what: str = "corpus") -> list[dict]:
    """Corpus rows, or skip. Never raises for an absent/empty/schema-less DB."""
    if not DB.exists():
        pytest.skip(f"no recorded {what} in this checkout")
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        out = [dict(r) for r in con.execute(query, params)]
    except sqlite3.OperationalError as e:
        pytest.skip(f"no recorded {what} in this checkout ({e})")
    finally:
        con.close()
    if not out:
        pytest.skip(f"{what} present but empty")
    return out


def require(table: str = "findings", what: str = "corpus") -> None:
    """Skip unless `table` exists and has at least one row."""
    rows(f"SELECT 1 FROM {table} LIMIT 1", what=what)
