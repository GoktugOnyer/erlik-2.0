"""A truncated companion query is a request the lane did not intend to make.

`form_endpoint` bounded the companion query with a character slice:

    query = urlencode(companions)[:MAX_COMPANION_QUERY].rstrip("&")

The bound is right — a companion VALUE is target-controlled text going into a URL
— but slicing by characters cuts the LAST PAIR MID-VALUE.

REACHABLE THROUGH THE LANE, which is worth stating because the obvious example is
not. `worker.py`'s form script slices every control value to 200 characters before
`form_endpoint` ever sees it, so one kilobyte-sized ASP.NET `__VIEWSTATE` cannot
trigger this through the browser path — an adversarial review made that point and
it is correct. **Three** ordinary 200-character hidden fields do, and measured
against the code as it was:

    1 hidden x200  query=210  submit kept=True   partial values: none
    2 hidden x200  query=414  submit kept=True   partial values: none
    3 hidden x200  query=512  submit kept=FALSE  partial values: h2 sent as 101 of 200
    4 hidden x200  query=512  submit kept=FALSE  partial values: h2 sent as 101 of 200

  1. The probe sends a PARTIAL value the application never emitted. The project
     already refuses this shape elsewhere: a parameter name containing `#` is
     rejected because it would silently truncate the probe to `?a`, and
     "reporting on a request you did not make is worse than not making it".
  2. The submit control is gone — and carrying the submit control is the entire
     reason companions are in the URL. form_endpoint's own docstring: DVWA's SQLi
     page "answers `?id=<payload>` with nothing and `?id=<payload>&Submit=Submit`
     with the rows". So the probe silently stops reaching the handler.

And the two arms get different truncated strings, which is one more way two
identities fork (reported as F4 of the fork audit).
"""
from urllib.parse import parse_qsl

from orchestrator.integrations.contracts import (form_endpoint, MAX_COMPANION_QUERY,
                                                 operation_key)


def form(*controls, action="http://app.test/p"):
    return {"method": "GET", "action": action,
            "controls": [dict(zip(("name", "type", "value"), c)) for c in controls]}


BIG = ("__VIEWSTATE", "hidden", "A" * 700)
SUBMIT = ("btn", "submit", "Go")
TEXT = ("q", "text", "")


def test_no_companion_is_ever_cut_mid_value():
    url, _ = form_endpoint(form(TEXT, BIG, SUBMIT), "http://app.test/")
    for name, value in parse_qsl(url.split("?", 1)[1] if "?" in url else ""):
        if name == "__VIEWSTATE":
            assert value == "A" * 700, (
                f"__VIEWSTATE was sent as {len(value)} of 700 bytes — a value the "
                "application never emitted")


def test_the_submit_control_survives_an_oversized_hidden_field():
    """The control the handler actually needs must not be the one that is lost."""
    url, _ = form_endpoint(form(TEXT, BIG, SUBMIT), "http://app.test/")
    assert "btn=Go" in url, (
        f"the submit control was dropped, so this probe cannot reach the handler:\n  {url}")


def test_the_query_stays_within_its_bound():
    url, _ = form_endpoint(form(TEXT, BIG, SUBMIT), "http://app.test/")
    query = url.split("?", 1)[1] if "?" in url else ""
    assert len(query) <= MAX_COMPANION_QUERY, f"{len(query)} > {MAX_COMPANION_QUERY}"


def test_two_arms_differing_only_in_an_oversized_value_do_not_fork():
    """F4 as an isolation question. Neither arm can carry the field, so neither
    does, and they agree — rather than each keeping a different fragment."""
    a, _ = form_endpoint(form(TEXT, ("__VIEWSTATE", "hidden", "A" * 700), SUBMIT), "x")
    b, _ = form_endpoint(form(TEXT, ("__VIEWSTATE", "hidden", "B" * 700), SUBMIT), "x")
    assert a == b, f"\n  {a}\n  {b}"


def test_a_companion_that_fits_is_still_carried():
    """The bound must not become an excuse to drop everything."""
    url, testable = form_endpoint(form(TEXT, ("tok", "hidden", "abc123"), SUBMIT), "x")
    assert "tok=abc123" in url and "btn=Go" in url
    assert testable == ["q"]


def test_every_companion_is_dropped_or_whole():
    """The invariant, over a range of sizes that straddles the bound."""
    for size in (1, 100, 400, 480, 500, 512, 513, 600, 2000):
        url, _ = form_endpoint(form(TEXT, ("big", "hidden", "x" * size), SUBMIT), "y")
        query = url.split("?", 1)[1] if "?" in url else ""
        assert len(query) <= MAX_COMPANION_QUERY, (size, len(query))
        for name, value in parse_qsl(query):
            if name == "big":
                assert len(value) == size, (
                    f"size={size}: `big` was sent as {len(value)} of {size} bytes")


def test_the_lane_reachable_case_keeps_its_submit_and_whole_values():
    """Three 200-character hidden fields: what the worker's own cap permits.

    This is the case that matters, because `worker.py` slices control values to
    200 characters, so it is the shape a real form actually produces. Against the
    code as it was: query=512, the submit control gone, and `h2` sent as 101 of
    its 200 bytes.
    """
    controls = [TEXT] + [(f"h{i}", "hidden", "A" * 200) for i in range(3)] + [SUBMIT]
    url, testable = form_endpoint(form(*controls), "http://app.test/")
    query = url.split("?", 1)[1]

    assert "btn=Go" in url, f"the submit control was dropped again:\n  {url}"
    assert len(query) <= MAX_COMPANION_QUERY
    for name, value in parse_qsl(query):
        if name.startswith("h"):
            assert len(value) == 200, f"{name} was sent as {len(value)} of 200 bytes"
    assert testable == ["q"]


def test_dropping_whole_pairs_is_visible_in_what_survives():
    """Not silent: the fields that did not fit are simply absent, and a reader
    comparing the URL against the form can see which."""
    controls = [TEXT] + [(f"h{i}", "hidden", "A" * 200) for i in range(4)] + [SUBMIT]
    url, _ = form_endpoint(form(*controls), "http://app.test/")
    present = {name for name, _ in parse_qsl(url.split("?", 1)[1])}
    assert "btn" in present, "the submit control must never be the one dropped"
    assert len(present & {"h0", "h1", "h2", "h3"}) < 4, "nothing was dropped, so the bound did not apply"


def test_one_field_of_urlencode_expanding_characters_is_dropped_whole():
    """The most realistic single-field route, and the one the 200-character cap
    does not protect against.

    A base64 value — which is what `__VIEWSTATE`, a signed cookie mirror or a CSRF
    token usually is — contains `+ / =`, and urlencode expands each to three
    characters. 200 source characters become roughly 600 encoded, so one field
    well inside the worker's own slice still overruns a 512-character bound.

    Measured against the code as it was: query=512, the submit control gone, and
    `__VIEWSTATE` sent as 168 of its 200 characters. A partial base64 value is not
    a weaker version of the real one — it is a different string the application
    never issued, and signed state will reject it.
    """
    value = ("/+=" * 67)[:200]
    url, _ = form_endpoint(form(TEXT, ("__VIEWSTATE", "hidden", value), SUBMIT), "x")
    query = url.split("?", 1)[1] if "?" in url else ""

    assert len(query) <= MAX_COMPANION_QUERY
    assert "btn=Go" in url, (
        "the submit control was dropped to make room for a field that did not "
        "fit, so the probe cannot reach the handler at all")
    for name, sent in parse_qsl(query):
        if name == "__VIEWSTATE":
            assert sent == value, f"sent {len(sent)} of {len(value)} characters"
