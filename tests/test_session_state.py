"""The per-session stateful primitive store.

This is the contract sibling PRs build against, so the tests pin the SHAPE of
every public method, not just that it runs: the dicts `auth_headers`,
`cookies` and `csrf_tokens` return, the ordering `get` promises, and — the part
that would leak if it broke — that `redact` actually removes a stored secret
from text handed to a log or an LLM.

`redact` is asserted against the REAL redaction authority (`orchestrator.redaction`),
never a re-implementation of the placeholder shape: a test that rebuilt the
`<kind:redacted:digest>` format itself would pass against a store that masked
with the wrong digest, which is the bug it is supposed to catch.
"""

import pytest

from orchestrator import redaction as R
from orchestrator.redaction import PLACEHOLDER_RX
from orchestrator.session_state import (
    PRIMITIVE_KINDS,
    Primitive,
    SessionStore,
    _in_scope,
    _normalize_host,
)

# A JWT-shaped secret long enough to be masked, and a short one that is not.
TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.AAAAAAAAAAAA"
COOKIE_VAL = "s%3Aabc123def456ghi789.sigvalue"
CSRF_VAL = "csrf-abcdef0123456789"


def tok(**kw):
    base = dict(kind="token", name=None, value=TOKEN,
                source="curl", scope_host="t.local")
    base.update(kw)
    return Primitive(**base)


# --------------------------------------------------------------- construction

class TestConstruction:
    def test_a_primitive_carries_its_five_fields(self):
        p = Primitive(kind="cookie", name="session", value=COOKIE_VAL,
                      source="step-3", scope_host="t.local")
        assert (p.kind, p.name, p.value, p.source, p.scope_host) == (
            "cookie", "session", COOKIE_VAL, "step-3", "t.local")

    @pytest.mark.parametrize("kind", sorted(PRIMITIVE_KINDS))
    def test_every_declared_kind_is_accepted(self, kind):
        Primitive(kind=kind, name="n", value="v", source="s", scope_host=None)

    def test_an_unknown_kind_is_rejected_at_construction(self):
        """A closed vocabulary caught at the door, not a value nothing can use
        sitting in the store until some later method trips over it."""
        with pytest.raises(ValueError) as exc:
            Primitive(kind="secret", name=None, value="x", source="s", scope_host=None)
        assert "secret" in str(exc.value)

    def test_a_fresh_store_is_empty(self):
        assert SessionStore().all() == []
        assert len(SessionStore()) == 0


# ------------------------------------------------------------- add / get / all

class TestAddGetAll:
    def test_add_returns_the_stored_primitive_and_get_finds_it(self):
        s = SessionStore()
        p = s.add(tok())
        assert s.get("token") is p
        assert s.all("token") == [p]

    def test_get_filters_by_name_when_given(self):
        s = SessionStore()
        a = s.add(Primitive("cookie", "sid", "aaaaaaaa", "s", None))
        b = s.add(Primitive("cookie", "xsrf", "bbbbbbbb", "s", None))
        assert s.get("cookie", "sid") is a
        assert s.get("cookie", "xsrf") is b
        assert s.get("cookie", "absent") is None

    def test_get_returns_the_most_recent_match(self):
        """A refreshed token supersedes the one it replaced."""
        s = SessionStore()
        s.add(tok(value="eyJold.AAAAAA.BBBBBB"))
        newer = s.add(tok(value="eyJnew.CCCCCC.DDDDDD"))
        assert s.get("token") is newer

    def test_all_preserves_insertion_order_and_filters_by_kind(self):
        s = SessionStore()
        c = s.add(Primitive("cookie", "sid", "aaaaaaaa", "s", None))
        t = s.add(tok())
        assert s.all() == [c, t]
        assert s.all("token") == [t]
        assert s.all("header") == []

    def test_an_exact_duplicate_is_collapsed(self):
        """Replaying the same tool output twice must not inflate the store."""
        s = SessionStore()
        first = s.add(tok())
        again = s.add(tok())
        assert again is first
        assert len(s) == 1

    def test_add_rejects_a_non_primitive(self):
        with pytest.raises(TypeError):
            SessionStore().add({"kind": "token", "value": TOKEN})


# ------------------------------------------------------- request-side views

class TestRequestViews:
    def test_a_token_becomes_a_bearer_authorization_header(self):
        s = SessionStore()
        s.add(tok())
        assert s.auth_headers() == {"Authorization": f"Bearer {TOKEN}"}

    def test_an_explicit_header_is_not_overwritten_by_a_scraped_token(self):
        """A header the agent set on purpose outranks a token the store scraped."""
        s = SessionStore()
        s.add(Primitive("header", "Authorization", "Bearer chosen-by-agent",
                        "agent", None))
        s.add(tok())
        assert s.auth_headers()["Authorization"] == "Bearer chosen-by-agent"

    def test_header_primitives_pass_through_as_name_value(self):
        s = SessionStore()
        s.add(Primitive("header", "X-API-Key", "k-123456", "s", None))
        assert s.auth_headers() == {"X-API-Key": "k-123456"}

    def test_cookies_are_name_value(self):
        s = SessionStore()
        s.add(Primitive("cookie", "session", COOKIE_VAL, "s", None))
        s.add(Primitive("cookie", "csrf", "cookie-csrf-val", "s", None))
        assert s.cookies() == {"session": COOKIE_VAL, "csrf": "cookie-csrf-val"}

    def test_cookies_keeps_the_newest_value_per_name(self):
        s = SessionStore()
        s.add(Primitive("cookie", "session", "old-cookie-val", "s", None))
        s.add(Primitive("cookie", "session", COOKIE_VAL, "s", None))
        assert s.cookies() == {"session": COOKIE_VAL}

    def test_csrf_tokens_are_name_value(self):
        s = SessionStore()
        s.add(Primitive("csrf", "_csrf", CSRF_VAL, "s", None))
        assert s.csrf_tokens() == {"_csrf": CSRF_VAL}

    def test_the_views_are_empty_without_matching_primitives(self):
        s = SessionStore()
        s.add(Primitive("injection_point", "q", "http://t.local/s?q=1", "s", "t.local"))
        assert s.auth_headers() == {}
        assert s.cookies() == {}
        assert s.csrf_tokens() == {}


# --------------------------------------------------------------- redaction

class TestRedact:
    def test_a_stored_secret_is_removed_from_text(self):
        s = SessionStore()
        s.add(tok())
        line = f'curl -H "Authorization: Bearer {TOKEN}" http://t.local/'
        out = s.redact(line)
        assert TOKEN not in out, "the raw secret survived redaction"
        assert PLACEHOLDER_RX.search(out), "no redaction placeholder was produced"

    def test_the_placeholder_is_the_real_redaction_authoritys_shape(self):
        """Asserted against orchestrator.redaction, not a re-built format string,
        so a wrong digest here fails rather than passing against itself."""
        s = SessionStore()
        s.add(tok())
        expected = f"<token:redacted:{R._digest(TOKEN)}>"
        assert s.redact(TOKEN) == expected

    def test_an_injection_point_value_is_not_masked(self):
        """Its value is a location the model must see in the clear."""
        s = SessionStore()
        url = "http://t.local/search?q=INJECT_HERE_LONG_ENOUGH"
        s.add(Primitive("injection_point", "q", url, "s", "t.local"))
        assert s.redact(url) == url

    def test_redact_is_none_preserving(self):
        assert SessionStore().redact(None) is None
        assert SessionStore().redact("") == ""

    def test_text_without_a_stored_secret_is_unchanged(self):
        s = SessionStore()
        s.add(tok())
        assert s.redact("nothing secret here") == "nothing secret here"

    def test_a_secret_containing_a_shorter_secret_is_masked_whole(self):
        """Longest-first: masking the inner value first would strand the outer
        one split around a placeholder, leaking its ends."""
        s = SessionStore()
        inner = "abc123def456"
        outer = inner + "GHI789jkl012"
        s.add(Primitive("csrf", "short", inner, "s", None))
        s.add(Primitive("csrf", "long", outer, "s", None))
        out = s.redact(f"token={outer}")
        assert inner not in out
        assert outer not in out


# --------------------------------------------------------------- summary_facts

class TestSummaryFacts:
    def test_a_secret_fact_hides_the_value(self):
        s = SessionStore()
        s.add(tok(name="access_token"))
        facts = s.summary_facts()
        assert len(facts) == 1
        assert TOKEN not in facts[0]
        assert "you now hold" in facts[0]
        assert "access_token" in facts[0]
        assert PLACEHOLDER_RX.search(facts[0])

    def test_an_injection_point_fact_shows_its_location(self):
        s = SessionStore()
        url = "http://t.local/search?q=INJECT_HERE_LONG_ENOUGH"
        s.add(Primitive("injection_point", "q", url, "s", "t.local"))
        facts = s.summary_facts()
        assert facts == [f"you now hold an injection_point q at {url}"]

    def test_one_fact_per_stored_primitive(self):
        s = SessionStore()
        s.add(tok())
        s.add(Primitive("cookie", "sid", COOKIE_VAL, "s", None))
        assert len(s.summary_facts()) == 2


# --------------------------------------------------------------- host scoping

class TestHostNormalization:
    @pytest.mark.parametrize("value,expected", [
        ("t.local", "t.local"),
        ("T.Local", "t.local"),                       # case-insensitive
        ("t.local:3000", "t.local"),                  # port stripped
        ("http://t.local/path?x=1", "t.local"),       # scheme + path stripped
        ("https://user@t.local:8443/a", "t.local"),   # userinfo stripped
        ("[::1]:443", "::1"),                          # IPv6 literal
        ("", ""),
        (None, ""),
    ])
    def test_normalizes_to_a_bare_lowercased_hostname(self, value, expected):
        assert _normalize_host(value) == expected


class TestInScopeRule:
    def test_no_host_filter_admits_everything(self):
        assert _in_scope(Primitive("token", None, TOKEN, "s", "a.local"), None) is True
        assert _in_scope(Primitive("token", None, TOKEN, "s", None), None) is True

    def test_a_matching_host_is_in_scope_ignoring_port_and_case(self):
        p = Primitive("cookie", "sid", "aaaaaaaa", "s", "t.local:3000")
        assert _in_scope(p, "http://T.LOCAL/x") is True

    def test_a_different_host_is_out_of_scope(self):
        p = Primitive("cookie", "sid", "aaaaaaaa", "s", "t.local")
        assert _in_scope(p, "evil.example") is False

    def test_an_unscoped_primitive_is_denied_under_a_host_filter(self):
        """Default-deny: the store will not guess that a credential with no
        recorded host is safe to send to a specific one."""
        assert _in_scope(Primitive("token", None, TOKEN, "s", None), "t.local") is False

    def test_a_host_that_normalizes_to_nothing_matches_nothing(self):
        p = Primitive("cookie", "sid", "aaaaaaaa", "s", "t.local")
        assert _in_scope(p, "://") is False


class TestHostScopedReads:
    def _two_host_store(self):
        s = SessionStore()
        s.add(Primitive("cookie", "sid", "cookie-for-a", "s", "a.local"))
        s.add(Primitive("cookie", "sid", "cookie-for-b", "s", "b.local"))
        s.add(Primitive("token", None, TOKEN, "s", "a.local"))
        s.add(Primitive("csrf", "_csrf", CSRF_VAL, "s", "b.local"))
        s.add(Primitive("header", "X-Api", "key-for-a", "s", "a.local"))
        return s

    def test_get_returns_only_the_matching_hosts_primitive(self):
        s = self._two_host_store()
        assert s.get("cookie", "sid", host="a.local").value == "cookie-for-a"
        assert s.get("cookie", "sid", host="b.local").value == "cookie-for-b"

    def test_get_excludes_a_token_scoped_to_another_host(self):
        s = self._two_host_store()
        assert s.get("token", host="a.local") is not None
        assert s.get("token", host="b.local") is None

    def test_all_filters_by_host(self):
        s = self._two_host_store()
        assert {p.value for p in s.all(host="a.local")} == {
            "cookie-for-a", TOKEN, "key-for-a"}
        assert {p.value for p in s.all("cookie", host="b.local")} == {"cookie-for-b"}

    def test_auth_headers_are_host_scoped(self):
        s = self._two_host_store()
        a = s.auth_headers(host="a.local")
        assert a == {"X-Api": "key-for-a", "Authorization": f"Bearer {TOKEN}"}
        b = s.auth_headers(host="b.local")
        assert b == {}, "a.local's header and token must not leak to b.local"

    def test_cookies_and_csrf_are_host_scoped(self):
        s = self._two_host_store()
        assert s.cookies(host="a.local") == {"sid": "cookie-for-a"}
        assert s.cookies(host="b.local") == {"sid": "cookie-for-b"}
        assert s.csrf_tokens(host="a.local") == {}
        assert s.csrf_tokens(host="b.local") == {"_csrf": CSRF_VAL}

    def test_summary_facts_are_host_scoped(self):
        s = self._two_host_store()
        assert len(s.summary_facts(host="a.local")) == 3   # cookie, token, header
        assert len(s.summary_facts(host="b.local")) == 2    # cookie, csrf

    def test_without_a_host_the_whole_session_is_returned(self):
        """Backward compatible: the no-host form is unchanged."""
        s = self._two_host_store()
        assert len(s.all()) == 5
        assert s.cookies() == {"sid": "cookie-for-b"}       # newest wins, unscoped

    def test_an_unscoped_credential_is_withheld_from_a_host_but_served_unscoped(self):
        s = SessionStore()
        s.add(Primitive("token", None, TOKEN, "s", None))
        assert s.auth_headers() == {"Authorization": f"Bearer {TOKEN}"}
        assert s.auth_headers(host="t.local") == {}
