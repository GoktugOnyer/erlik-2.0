"""Pytest fixtures that stand a target up and run a real case against it."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import os
import subprocess
from pathlib import Path

import pytest

from tests.targets.servers import Ldap, Redirector, Tls, Web, serve


# Filled in by the `targets` fixture and read by `_native_mode`, so the CA
# only applies while a case is actually running.
_CA_BUNDLE = [""]


def _self_signed(dirpath: Path) -> tuple[str, str]:
    """A certificate for 127.0.0.1, trusted for the duration of the test.

    Generated rather than committed: a checked-in certificate expires, and a
    test that starts failing on a date nobody changed anything on is worse
    than one that generates what it needs.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cp, kp = dirpath / "cert.pem", dirpath / "key.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(cp), str(kp)


@pytest.fixture(scope="session")
def tls_cert(tmp_path_factory):
    return _self_signed(tmp_path_factory.mktemp("tls"))


def _mk(base, **attrs):
    return type(f"_{base.__name__}", (base,), attrs)


@pytest.fixture(scope="session")
def targets(tls_cert):
    """Every target, vulnerable and control, on ephemeral ports."""
    cert, key = tls_cert
    _CA_BUNDLE[0] = cert
    made = {}
    servers = []

    def up(name, handler, tls=None):
        srv, port = serve(handler, tls)
        servers.append(srv)
        scheme = "https" if tls else "http"
        made[name] = f"{scheme}://127.0.0.1:{port}"

    up("web", _mk(Web, VULNERABLE=True))
    up("web_control", _mk(Web, VULNERABLE=False))
    up("ldap", _mk(Ldap, VULNERABLE=True))
    up("ldap_control", _mk(Ldap, VULNERABLE=False))
    up("ldap_wildcard_escaped",
       _mk(Ldap, VULNERABLE=True, WILDCARD_ESCAPED=True))
    up("tls_no_hsts", _mk(Tls, HSTS=False), (cert, key))
    up("tls_hsts", _mk(Tls, HSTS=True), (cert, key))
    made_http = made["web"]
    up("tls_cleartext_action",
       _mk(Tls, FORM_ACTION=f"{made_http}/login"), (cert, key))
    up("redirect_to_tls", _mk(Redirector, LOCATION=made["tls_no_hsts"] + "/login"))
    try:
        yield made
    finally:
        for s in servers:
            s.shutdown()


@contextlib.contextmanager
def _native_mode():
    """Native execution, for the duration of ONE case run.

    The cases shell out to curl, and without native mode `execute_tool` looks
    for a Kali container CI does not have and refuses every step -- which reads
    as "the case found nothing" and would make every assertion here vacuous.

    Scoped to the call rather than the session, and that is not tidiness. As an
    autouse SESSION fixture it set ERLIK_NATIVE for the whole run and broke
    test_skills_authoring, which requires it UNSET because native mode removes
    the container boundary. That test passed alone and failed in the suite. A
    harness that changes global state for other people's tests is not a
    harness, it is a second bug.

    Also carries CURL_CA_BUNDLE, so curl accepts the generated certificate --
    without it every TLS case reports "no response" and the TLS assertions
    become vacuous. Same scoping for the same reason: adding a CA to every
    other test's environment for the whole session is not this file's business.
    """
    import orchestrator.tool_executor as TE
    saved = {k: os.environ.get(k) for k in ("ERLIK_NATIVE", "CURL_CA_BUNDLE")}
    old_flag = TE.ERLIK_NATIVE
    os.environ["ERLIK_NATIVE"] = "1"
    TE.ERLIK_NATIVE = True
    if _CA_BUNDLE[0]:
        os.environ["CURL_CA_BUNDLE"] = _CA_BUNDLE[0]
    try:
        yield
    finally:
        TE.ERLIK_NATIVE = old_flag
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def run_case(case_id: str, **target):
    """Run a real case against a target and return its RunResult.

    Goes through `run_test_case`, so the scope guard, admission control and
    evaluators are the shipped ones. A harness that bypassed them would prove
    nothing about what an operator gets.
    """
    from orchestrator.testcase import find_by_id, run_test_case

    tc = find_by_id(case_id)
    assert tc is not None, f"unknown case {case_id}"
    target.setdefault("scope", {"allow_hosts": ["127.0.0.1"]})
    with _native_mode():
        return asyncio.run(run_test_case(tc, target))


def vuln_types(result) -> set[str]:
    return {f.vuln_type for f in (result.findings or [])}


def curl_available() -> bool:
    try:
        return subprocess.run(["curl", "--version"],
                              capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False
