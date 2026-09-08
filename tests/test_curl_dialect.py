"""The curl argv dialect the assessment sandbox will execute.

curl_request is a security boundary: the (url, method) it returns is what the
scope check and the state-changing gate are decided on, and the argv it emits is
what actually runs in the sandbox. Every case below is a control — the positives
say the dialect is wide enough to be useful, the negatives say it is still
narrow enough to be safe, and neither is worth much without the other.

The expected -G reconstructions are NOT computed from curl_request. They were
captured from `curl -w '%{url_effective}'` running in the pinned worker image
(curl 7.88.1), so this file compares the parser against curl rather than against
itself.
"""
import pytest

from orchestrator.integrations.deterministic import curl_request
from orchestrator.integrations.inventory import (
    COLLECTOR_CASES, executable_test_cases, unfilled_fields,
)
from orchestrator.testcase.scope import ScopeViolation


# --- what the dialect must ACCEPT -------------------------------------------

ACCEPTED = [
    ('curl -s -A "Mozilla/5.0" -L --max-time 10 "https://app.test/robots.txt"',
     "GET", "https://app.test/robots.txt", "user agent, redirects and a time bound"),
    ('curl -sI -A "Mozilla/5.0" "https://app.test/"',
     "HEAD", "https://app.test/", "bundled short flags"),
    ('curl -s -o /dev/null -w "%{http_code}" "https://app.test/login"',
     "GET", "https://app.test/login", "discard the body, format the status"),
    ('curl -s -D - -o /dev/null -H "Origin: null" "https://app.test/"',
     "GET", "https://app.test/", "headers to stdout, body discarded"),
    ('curl -s -X POST -H "Content-Type: application/xml" --data-binary "<x/>" "https://app.test/x"',
     "POST", "https://app.test/x", "an xml body, still gated as state-changing"),
    ('curl -s -b "" -H "" -i "https://app.test/"',
     "GET", "https://app.test/", "identity options the lane leaves unfilled are dropped"),
    ('curl -s --connect-timeout 3 --max-redirs 3 -L "https://app.test/"',
     "GET", "https://app.test/", "connection bounds"),
    ('curl -s -w "%{http_code}:%{size_download}" "https://app.test/"',
     "GET", "https://app.test/", "variables joined by separators"),
    ('curl -s -X PUT --data "x=1" "https://app.test/"',
     "PUT", "https://app.test/", "a body is fine on a method that carries one"),
    ('curl -s -D - -o /dev/null -X OPTIONS -H "Origin: null" '
     '-H "Access-Control-Request-Method: PUT" "https://app.test/"',
     "OPTIONS", "https://app.test/", "a CORS preflight is these headers or it is nothing"),
]


@pytest.mark.parametrize("command,method,url,why", ACCEPTED)
def test_the_dialect_accepts_what_the_catalogue_actually_writes(command, method, url, why):
    argv, parsed_url, parsed_method = curl_request(command)
    assert (parsed_method, parsed_url) == (method, url), why
    assert argv[0] == "curl"


# --- what it must REFUSE ----------------------------------------------------

REFUSED = [
    # A bundled option that takes a value is handed the REST of the bundle, and
    # the next token then becomes a URL: `-As ua URL` is `-A s` plus TWO
    # destinations. Verified against curl 7.88.1.
    ('curl -As ua "https://app.test/"', "a bundle cannot smuggle a second destination"),
    ('curl -s -o /tmp/x "https://app.test/"', "-o names a real file"),
    ('curl -s -D /tmp/h "https://app.test/"', "-D names a real file"),
    ('curl -s -w @/input/ca.pem "https://app.test/"', "-w @file reads a local file"),
    ('curl -s -w "%output{/tmp/x}" "https://app.test/"', "-w %output{} writes a local file"),
    ('curl -s -G --data-urlencode "@/input/ca.pem" "https://app.test/"',
     "--data-urlencode @file reads a file into the query string"),
    ('curl -s -G --data-urlencode "n@/input/ca.pem" "https://app.test/"',
     "the name@file spelling reads a file too, and startswith('@') never saw it"),
    ('curl -s -A "x\r\nX-Injected: 1" "https://app.test/"', "-A becomes a header"),
    ('curl -s -e "x\r\nX-Injected: 1" "https://app.test/"', "-e becomes a header"),
    ('curl -s --max-time /tmp/x "https://app.test/"', "a limit is a number"),
    ('curl -s -c /tmp/jar "https://app.test/"', "--cookie-jar writes credentials to disk"),
    ('curl -s -k "https://app.test/"', "--insecure defeats the pinned CA"),
    ('curl -s -K /tmp/conf "https://app.test/"', "--config injects arbitrary options"),
    ('curl -s --trace /tmp/t "https://app.test/"', "--trace writes a file"),
    ('curl -s --proxy http://evil "https://app.test/"', "a case cannot choose its own proxy"),
    ('curl --noproxy "*" https://app.test', "a case cannot leave the proxy"),
    ('curl -s -b "sess=abc" "https://app.test/"', "a case cannot carry its own credentials"),
    ('curl -s "http://user:pw@app.test/"',
     "nor spell them into the URL, which is the same rule by another route"),
    ('curl -s "https://app.test/" "https://other.test/"', "one destination only"),
    ('curl -s --data "a=1" "https://app.test/"', "a GET carrying a body is not a GET"),
    ('curl -s -H "Host: evil.test" "https://app.test/"', "Host would repoint the destination"),
    ('curl -s -H "Authorization: Bearer x" "https://app.test/"',
     "widening the header allowlist for CORS preflight did not open it to identity"),
    ('curl -s -H "X-Forwarded-For: 127.0.0.1" "https://app.test/"',
     "the allowlist is still an allowlist"),
    ('curl -s -X OPTIONS -H "Access-Control-Request-Method: PUT\r\nX-Injected: 1" "https://app.test/"',
     "the new headers inherit the CRLF rule"),
    # curl writes -X straight into the request line without validating it, so a
    # CRLF value emits a COMPLETE extra request before the real one. Verified
    # against curl 7.88.1 with a raw socket server.
    ('curl -s -X "GET / HTTP/1.1\r\nX-Injected: yes\r\n\r\nGET" "https://app.test/"',
     "-X with CRLF is request smuggling"),
    ('curl -s -X "GET /x HTTP/1.1" "https://app.test/"', "a method has no spaces"),
    # /dev/stdout and /dev/stderr are paths resolving to /proc/self/fd/N, and
    # curl opens the target with fopen(..., "wb") — on an fd backed by a regular
    # file that TRUNCATES it. Allowing them while refusing /proc/self/fd/1 was
    # the same permission spelled two ways.
    ('curl -s -o /dev/stdout "https://app.test/"', "/dev/stdout is a path, not a stream"),
    ('curl -s -o /dev/stderr "https://app.test/"', "/dev/stderr likewise"),
    ('curl -s -o /proc/self/fd/1 "https://app.test/"', "and so is the name it resolves to"),
    ('curl -s -m 0 "https://app.test/"', "curl reads 0 as NO timeout, the opposite of a bound"),
    ('curl -s --connect-timeout 0 "https://app.test/"', "same for the connect phase"),
    # curl turns \r and \n in a -w format into REAL line breaks, so a case
    # could write a status line into the output that _http_status_ok and the
    # cors/cookie evaluators then read as a captured response.
    (r'curl -s -w "\r\nHTTP/1.1 200 OK\r\n\r\nprivate-canary" "https://app.test/"',
     "-w escapes would let a case forge the evidence it is judged on"),
    ('curl -s -w "%{stderr}x" "https://app.test/"', "-w must not move its report off the audited channel"),
    ('curl -s -w "%header{set-cookie}" "https://app.test/"', "-w must not dump server text unlabelled"),
    ('curl -s -w "%{certs}" "https://app.test/"', "nor TLS material"),
    ('curl -s -w "%{local_ip}" "https://app.test/"', "nor container-internal host state"),
    # Bundling is gated on its own set, not on "takes no value": -O takes none
    # and writes a file, -k takes none and drops certificate checks.
    ('curl -s -sO "https://app.test/"', "-O in a bundle would write a file"),
    ('curl -s -sk "https://app.test/"', "-k in a bundle would drop certificate checks"),
    # -I sets no-body, -X replaces the verb: separate state in curl, so the
    # parser cannot hold both in one variable. `-X DELETE -I` reported HEAD
    # while curl put `DELETE /u/7` on the wire — verified.
    ('curl -s -o /dev/null -X DELETE -I "https://app.test/u/7"',
     "-X and -I state two different methods"),
    ('curl -s -D - -X PATCH --head "https://app.test/u/7"', "the long spelling too"),
    ('curl -s -o /dev/null -X DELETE -sI "https://app.test/u/7"', "and through a bundle"),
    # curl sends HEAD with a Content-Length and the body; the proxy sees HEAD
    # and permits it, so BOTH gates missed this one.
    ('curl -s -X HEAD -d "id=7&confirm=true" "https://app.test/admin/delete"',
     "a body on HEAD is a mutation wearing a safe method"),
    ('curl -s -X OPTIONS -d "x=1" "https://app.test/"', "and on OPTIONS"),
    # With -o /dev/null the response body never reaches stdout, so the -w text
    # IS step_result.output and every evaluator reads what the case wrote.
    ('curl -s -o /dev/null -w "root:x:0:0:" "https://app.test/?p=1"',
     "-w would fire AUTHZ-01, INPV-07 and INPV-19 from a request that touched nothing"),
    ('curl -s -o /dev/null -w "302 http://app.test/login" "https://app.test/"',
     "-w would forge ATHN-01's finding"),
    ('curl -s -o /dev/null -w "x-erlik-blocked: true" "https://app.test/admin"',
     "-w would make a permitted request report itself as scope-refused"),
    ('curl -s -w "noop" "https://app.test/"', "any literal word at all"),
    # Measured on the pinned curl: `--max-redirs 999999999` against a
    # self-redirect loop issued 2310 requests from one argv token. Every hop is
    # policed by the proxy, so this is volume, not scope — but it is
    # target-chosen volume charged to the operator's request budget.
    ('curl -s -L --max-redirs 999999999 "https://app.test/a"', "a redirect chain is bounded"),
    ('curl -s -L --max-redirs 51 "https://app.test/a"', "and never above curl's own default of 50"),
    ('curl -s -L --max-redirs 3.5 "https://app.test/a"', "hops are whole; curl exits 2 on this"),
    ('sh -c "curl https://app.test"', "the tool is curl, not a shell"),
    ('curl -s "https://app.test/" | tee /tmp/x', "no pipelines"),
]


@pytest.mark.parametrize("command,why", REFUSED)
def test_the_dialect_refuses_what_would_break_an_invariant(command, why):
    with pytest.raises(ScopeViolation):
        curl_request(command)


# --- globbing ---------------------------------------------------------------

class TestGlobbingIsOff:
    """curl expands [1-100] and {a,b} in a URL into MANY requests, and
    http://{a,b}.test/ into requests to DIFFERENT HOSTS — all from one argv
    token. "Exactly one explicit HTTP destination" was therefore a statement
    about the text, not about the request. Discovered endpoints are substituted
    into these commands verbatim, so a target serving a link containing `[`
    chose that fan-out.
    """

    def test_globbing_is_disabled_on_every_command(self):
        argv, _, _ = curl_request('curl -s "https://app.test/"')
        assert "-g" in argv

    def test_a_globbing_url_is_accepted_but_cannot_fan_out(self):
        argv, url, _ = curl_request('curl -s "https://app.test/a[1-500]"')
        assert url == "https://app.test/a[1-500]"
        assert "-g" in argv, "without -g this is 500 requests, not one"

    def test_a_case_may_pass_g_itself_without_being_refused(self):
        argv, _, _ = curl_request('curl -s -g -i "https://app.test/a[1]"')
        assert argv.count("-g") == 1


# --- -G query reconstruction ------------------------------------------------

# Captured from `curl -o /dev/null -w '%{url_effective}'` in the pinned worker
# image. If curl ever changes how it builds these, this table is the thing that
# should fail — not a claim derived from the code under test.
CURL_EFFECTIVE_URLS = [
    ('curl -s -G "http://t/s" --data-urlencode "q=erlik\'probe"',
     "http://t/s?q=erlik%27probe"),
    ('curl -s -G "http://t/s" --data-urlencode "q=\' or \'1\'=\'1"',
     "http://t/s?q=%27+or+%271%27%3d%271"),
    ('curl -s -G "http://t/s" --data-urlencode "q=<%= 31337*7 %>"',
     "http://t/s?q=%3c%25%3d+31337%2a7+%25%3e"),
    ('curl -s -G "http://t/s?x=9" --data-urlencode "q=a b"',
     "http://t/s?x=9&q=a+b"),
    ('curl -s -G "http://t/s" --data "b=3" --data-urlencode "c=d e"',
     "http://t/s?b=3&c=d+e"),
    ('curl -s -G "http://t/s" --data-urlencode "=bare content"',
     "http://t/s?bare+content"),
    ('curl -s -G "http://t/s" --data-urlencode "noequals"',
     "http://t/s?noequals"),
]


@pytest.mark.parametrize("command,effective", CURL_EFFECTIVE_URLS)
def test_the_returned_url_is_the_url_curl_will_request(command, effective):
    """-G moves the data into the query string, so the destination the scope
    check sees has to be rebuilt or it is not the destination."""
    _, url, method = curl_request(command)
    assert url == effective
    assert method == "GET", "-G leaves the method alone"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND"])
def test_a_real_method_is_still_accepted(method):
    _, _, parsed = curl_request(f'curl -s -X {method} "https://app.test/"')
    assert parsed == method


def test_an_explicit_method_still_wins_over_G():
    _, url, method = curl_request('curl -s -G -X POST --data "b=3" "http://t/s"')
    assert method == "POST", "the state-changing gate must see POST"
    assert url == "http://t/s?b=3"


# --- the three gates agree --------------------------------------------------

class TestCapabilityIsDerivedNotDeclared:
    """What the lane can run is a property of the parser. It used to be written
    down in two other places as well, and both were stale."""

    def test_every_runnable_case_actually_parses(self):
        from orchestrator.testcase.loader import load_catalog
        from orchestrator.testcase.runner import _render
        catalog = load_catalog()
        for case_id in executable_test_cases():
            for step in catalog[case_id].steps:
                curl_request(_render(step.command, {"url": "https://app.test/", "step": {}}))

    def test_the_config_accepts_exactly_the_runnable_cases(self):
        from orchestrator.integrations.contracts import AssessmentConfig
        runnable = set(executable_test_cases()) | set(COLLECTOR_CASES)
        for case_id in sorted(runnable - {"WSTG-INPV-19"}):  # needs the interactsh stage
            AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [443]},
                             active=True, test_cases=[case_id])

    def test_a_case_the_parser_cannot_run_is_refused_at_configuration_time(self):
        from pydantic import ValidationError
        from orchestrator.integrations.contracts import AssessmentConfig
        # AUTHZ-04 runs `bash -c`; INFO-02's later steps run whatweb/wafw00f.
        for case_id in ("WSTG-AUTHZ-04", "WSTG-INFO-02", "WSTG-NOT-A-CASE"):
            with pytest.raises(ValidationError):
                AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [443]},
                                 active=True, test_cases=[case_id])

    def test_a_preflight_declaring_PUT_is_still_gated_as_an_OPTIONS_request(self):
        """Access-Control-Request-Method names a method the browser MIGHT use.
        It must not become the method the state-changing gate decides on."""
        _, _, method = curl_request(
            'curl -s -X OPTIONS -H "Access-Control-Request-Method: DELETE" "https://app.test/"')
        assert method == "OPTIONS"

    def test_a_step_that_interpolates_nothing_is_not_a_check(self):
        """WSTG-CLNT-04 lists `parameter` as optional but interpolates it into
        the query, so with nothing to substitute it probes `?=//evil/` — an
        open-redirect test against a parameter with no name."""
        assert unfilled_fields('curl "{{url}}?{{parameter}}=x"', {"url": "https://app.test/"}) == ["parameter"]
        assert unfilled_fields('curl -b "{{cookie}}" -H "{{auth_header}}" "{{url}}"',
                               {"url": "https://app.test/"}) == [], "identity is the proxy's job, not the case's"
        assert "WSTG-CLNT-04" not in executable_test_cases()


class TestAWriteOutFormatCannotForgeAFinding:
    """The sharpest failure this dialect can have is not an escape — it is a
    finding for a request that never happened. An adversarial pass found 64 of
    the catalogue's 111 regex evaluators forgeable by one grammar-legal -w
    literal, 49 of them high or critical.
    """

    @pytest.mark.parametrize("literal", [
        "root:x:0:0:", "302 http://app.test/login", "x-erlik-blocked: true",
        "HTTP/1.1 200 OK", "Set-Cookie: session=x", "uid=0(root)",
        "SQLSTATE", "<?xml", "Server: Apache/2.4.1",
    ])
    def test_no_evaluator_string_can_be_spelled_in_a_write_out_value(self, literal):
        with pytest.raises(ScopeViolation):
            curl_request(f'curl -s -o /dev/null -w "{literal}" "https://app.test/"')

    def test_the_grammar_admits_no_letter_or_digit_the_case_controls(self):
        """The property behind those cases: only curl fills in a %{variable},
        so only curl can put a word or a number in the output."""
        from orchestrator.integrations.deterministic import _WRITE_OUT
        import re
        for bad in ("a", "1", "GET", "200", "%{http_code}x", "x%{http_code}", "_"):
            assert not _WRITE_OUT.match(bad), bad
        for good in ("", "%{http_code}", "%{http_code} %{url_effective}",
                     "%{http_code}:%{size_download}", " : , ; | = / . -", "%%"):
            assert _WRITE_OUT.match(good), good

    def test_every_write_out_a_runnable_case_uses_still_parses(self):
        from orchestrator.integrations.inventory import executable_test_cases
        from orchestrator.testcase.loader import load_catalog
        from orchestrator.testcase.runner import _render
        catalog = load_catalog()
        for case_id in executable_test_cases():
            for step in catalog[case_id].steps:
                curl_request(_render(step.command, {"url": "https://app.test/", "step": {}}))


def test_a_case_cannot_author_the_budget_that_is_supposed_to_bound_it():
    """execute() appends its own --max-time so curl's last-wins ordering bounds
    a case's -m. But that value is step.timeout straight from YAML, and
    TestStep.timeout is an unbounded Optional[int] — so `timeout: 999999` had
    the case setting the bound, and one step could consume the whole stage."""
    import inspect
    from orchestrator.integrations import deterministic
    src = inspect.getsource(deterministic.CatalogueAdapter.run)
    assert "budget.stage_seconds" in src, "the appended --max-time must be clamped"
    assert "custom_timeout" in src and "min(" in src
