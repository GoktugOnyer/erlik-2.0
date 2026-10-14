"""Config-driven login provider that seeds the in-run session store.

WHAT THIS GENERALISES
The lab helper (`login-helper` in tool_executor) and the juice-shop host-bias
rewrite in `_sanitize_command` are lab-specific: they assume one application's
login shape and one set of hostnames. This provider is the product path. The
operator declares a login — which stored credential to use, and where its
material should be scoped — and the provider performs that login and writes the
harvested token/cookie into the shared `SessionStore` so later steps run
authenticated.

FLAG-GATED, OFF BY DEFAULT (runconfig `stateful_session`). With the flag off
this module is never entered: no login is performed, nothing is seeded, and
`login-helper` plus every existing auth path behave exactly as before. This is
the declare-don't-drop contract (CLAUDE.md #2) read the other way — the new
capability is added ALONGSIDE the lab helper, never in place of it.

NO PLAINTEXT CREDENTIAL EVER LIVES IN A RUN CONFIG. The login config names a
credential by id; the password stays encrypted at rest (orchestrator/secrets.py)
and is decrypted for the single instant of the login inside `login.authenticate`,
which this provider reuses rather than re-implementing. A run_config is stored
on the session and rendered in the dashboard, so a password placed there would
leak to both — exactly the sink this design removes.

VERIFIED-OR-NOTHING. `login.authenticate` only marks a session `verified` when a
probe with it actually changed the server's answer (login._verify is
differential). This provider seeds the store ONLY from a verified session: an
unverified session "supplies nothing to a sweep" everywhere else in the tree, so
seeding the agent's auth context from one would hand it a credential that does
nothing while telling it the opposite. When the login is not verified the
provider seeds nothing and says why.
"""

from __future__ import annotations

from urllib.parse import urlparse

from orchestrator import credentials as C
from orchestrator import login as L

# A sibling slice builds orchestrator/session_state.py (the shared SessionStore
# / Primitive contract). This slice must land even if that is not merged yet, so
# the import is defensive: when it is absent the provider degrades to a clear
# "store unavailable" report instead of failing at import time.
try:  # pragma: no cover - exercised both ways across the two slices
    from orchestrator.session_state import Primitive, SessionStore  # noqa: F401
    _HAVE_STORE = True
except Exception:  # noqa: BLE001
    Primitive = None  # type: ignore[assignment]
    SessionStore = None  # type: ignore[assignment]
    _HAVE_STORE = False


def _scope_host(url: str) -> str:
    """`host:port` for a URL, with the default port filled in.

    The scope host is how a primitive is pinned to one origin: the auto-attach
    path must never send a captured session to a host other than the one it was
    minted against. An empty string when nothing parses, so a caller can tell a
    missing scope from a real one rather than defaulting to a wrong host."""
    p = urlparse(url or "")
    host = (p.hostname or "").lower()
    if not host:
        return ""
    port = p.port
    if port is None:
        port = 443 if (p.scheme or "").lower() == "https" else 80
    return f"{host}:{port}"


def _cookie_name(cookie: str) -> str:
    """The first cookie's name, for a primitive label. Falls back to 'session'.

    This is a label only; the store carries the whole `name=value; ...` string
    as the primitive value, because that is what a Cookie header needs."""
    first = (cookie or "").split(";", 1)[0]
    name = first.split("=", 1)[0].strip()
    return name or "session"


def config_from_run(resolved: dict) -> dict | None:
    """The login-provider sub-config for this run, or None when it is off.

    `stateful_session` is the master switch. Returning None means the provider
    must not run — the single gate every entry point checks."""
    if not (resolved or {}).get("stateful_session"):
        return None
    cfg = resolved.get("login_provider")
    return cfg if isinstance(cfg, dict) else {}


async def seed(db, store, resolved: dict, target: str | None = None) -> dict:
    """Perform the configured login and seed `store` with its primitives.

    Returns a SECRET-FREE report (safe to log, broadcast and persist). The shape
    is stable so a caller can render it without guessing:

        ran        bool  — a verified login was performed AND primitives seeded
        enabled    bool  — the master flag `stateful_session`
        seeded     list  — primitive kinds written to the store (e.g. ['token'])
        scope_host str   — the origin the primitives were pinned to
        reason     str   — why nothing (more) happened, when ran is False
        login      dict  — login.authenticate's own secret-free report, if reached

    With the flag off this returns immediately having touched nothing, so the
    agent loop's behaviour is byte-identical to before.
    """
    report: dict = {
        "ran": False,
        "enabled": bool((resolved or {}).get("stateful_session")),
        "seeded": [],
        "scope_host": "",
        "reason": "",
    }

    cfg = config_from_run(resolved)
    if cfg is None:
        report["reason"] = "stateful_session is off"
        return report

    if not _HAVE_STORE or Primitive is None or store is None:
        report["reason"] = (
            "session store is unavailable "
            "(orchestrator.session_state not importable or no store passed)")
        return report

    credential_id = str(cfg.get("credential_id") or "").strip()
    if not credential_id:
        report["reason"] = (
            "stateful_session is on but login_provider.credential_id is not set")
        return report

    # Perform the login through the hardened, verified path. It decrypts the
    # credential for one request, persists an encrypted session, verifies it
    # differentially, and returns a report with no secret in it.
    try:
        login_report = await L.authenticate(db, credential_id)
    except KeyError:
        report["reason"] = f"credential {credential_id!r} not found"
        return report
    except Exception as e:  # noqa: BLE001 — the message must not carry a secret
        report["reason"] = f"login failed: {type(e).__name__}"
        return report
    report["login"] = login_report

    sid = login_report.get("session_id")
    status = login_report.get("status")
    if not sid or status != "verified":
        # Deliberately not seeded. An unverified session supplies nothing to a
        # sweep elsewhere; seeding the agent from one would be a credential that
        # does nothing dressed up as a working session.
        report["reason"] = (
            f"login status {status!r} — only a VERIFIED session is seeded "
            "(an unverified session authenticates nothing)")
        return report

    # Pull the verified material back out. credentials._plaintext is the single
    # sanctioned path from a stored session to its secret, and it refuses any
    # session that is not verified — so this cannot resurrect a rejected one.
    row = await (await db.execute(
        "SELECT target_key, header_name FROM engagement_sessions WHERE id = ?",
        (sid,))).fetchone()
    row = dict(row) if row else {}
    header_name = row.get("header_name") or "Authorization"

    # Scope precedence: an explicit scope_host in the config wins; otherwise the
    # session's own target_key (already host:port), and the run target only as a
    # last resort. A wrong scope would let the auto-attach path send the session
    # to the wrong origin, so it is pinned to where the credential was stored.
    scope = (str(cfg.get("scope_host") or "").strip()
             or (row.get("target_key") or "")
             or _scope_host(target or ""))

    token = await C._plaintext(db, sid, "jwt")
    cookie = await C._plaintext(db, sid, "cookie")

    added: list[str] = []
    if token:
        store.add(Primitive(
            kind="token", name=header_name, value=token,
            source=f"login_provider:{credential_id}", scope_host=scope))
        added.append("token")
    if cookie:
        store.add(Primitive(
            kind="cookie", name=_cookie_name(cookie), value=cookie,
            source=f"login_provider:{credential_id}", scope_host=scope))
        added.append("cookie")

    report["ran"] = bool(added)
    report["seeded"] = added
    report["scope_host"] = scope
    report["reason"] = (
        f"seeded {', '.join(added)} from verified session {sid}" if added
        else "verified session carried neither a token nor a cookie to seed")
    return report
