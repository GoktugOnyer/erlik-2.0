"""Deterministic integration entry point and operator-assisted browser login."""
import argparse
import asyncio
import json
import uuid
from pathlib import Path
from .contracts import AssessmentConfig, Identity
from .security import private_write


async def login(args):
    from playwright.async_api import async_playwright
    from .runtime import Sandbox
    from .egress_policy import EgressPolicy
    config = AssessmentConfig.model_validate_json(Path(args.config).read_text())
    identity = Identity.model_validate_json(Path(args.identity).read_text())
    from orchestrator.testcase.scope import check_url
    check_url(identity.target_origin, config.scope)
    # Login origins are control-plane destinations for this browser only. They are
    # never copied into an assessment's scan allowlist.
    origins = [identity.target_origin, *args.login_origin]
    from urllib.parse import urlsplit
    if any(urlsplit(u).scheme not in ("http", "https") or not urlsplit(u).hostname or urlsplit(u).username for u in origins):
        raise ValueError("login origins must be HTTP(S) origins")
    async with Sandbox(config, services=origins, publish=True) as sandbox:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=False, proxy={"server": sandbox.local_proxy, "bypass": "<-loopback>"},
                                              args=["--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
            context = await browser.new_context(ignore_https_errors=True)
            guard = EgressPolicy(sandbox.policy)
            async def route(request):
                allowed, _ = guard.check(request.request.url, request.request.method)
                await request.continue_() if allowed else await request.abort()
            await context.route("**/*", route)
            page = await context.new_page()
            await page.goto(identity.target_origin)
            print("Complete login in the browser, then press Enter here. Only the configured login origins are reachable.")
            await asyncio.to_thread(input)
            identity.storage_state = await context.storage_state()
            private_write(Path(args.output), identity.model_dump_json())
            await browser.close()
        from .security import redact, secret_values
        audit = sandbox.directory / "audit" / "requests.jsonl"
        if audit.exists():
            private_write(Path(args.output + ".audit.jsonl"), redact(audit.read_text(), secret_values(identity.model_dump())))


async def run(args):
    from orchestrator.database import init_db
    from . import persistence as db, service
    await init_db()
    await db.migrate()
    config = AssessmentConfig.model_validate_json(Path(args.config).read_text())
    from orchestrator.testcase import run_integrations
    print(json.dumps(await run_integrations(args.target, config.model_dump()), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("run")
    scan.add_argument("--config", required=True)
    scan.add_argument("--target", required=True)
    browser = sub.add_parser("login")
    browser.add_argument("--config", required=True)
    browser.add_argument("--identity", required=True)
    browser.add_argument("--output", required=True)
    browser.add_argument("--login-origin", action="append", default=[], help="Additional explicit IdP or login asset origin")
    args = parser.parse_args()
    asyncio.run(login(args) if args.command == "login" else run(args))


if __name__ == "__main__":
    main()
