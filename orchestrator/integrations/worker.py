"""Small JSON RPC worker. Runs only inside the isolated integration image."""
import json
import os
import sys
from pathlib import Path
import httpx


def request(spec):
    # Redirects still pass through the enforcing proxy, including schema fetches.
    with httpx.Client(timeout=20, follow_redirects=True, max_redirects=5) as client:
        response = client.request(spec.get("method", "GET"), spec["url"], json=spec.get("body"), headers=spec.get("headers"))
        return {"url": str(response.url), "status": response.status_code,
                "headers": dict(response.headers), "body": response.text,
                "blocked": response.headers.get("x-erlik-blocked") == "true"}


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    action = config["action"]
    if action == "request":
        print(json.dumps(request(config["request"])))
    elif action == "workflow":
        import subprocess
        result = {"fixtures": [], "cleanup": [], "exit_code": None}
        try:
            for spec in config["fixtures"]:
                response = request(spec)
                result["fixtures"].append(response)
                if response["status"] != spec["expected_status"] or (spec.get("body_contains") and spec["body_contains"] not in response["body"]):
                    raise RuntimeError("fixture assertion failed")
            process = subprocess.run(config["argv"], capture_output=True, text=True, timeout=config["scan_seconds"])
            result.update(exit_code=process.returncode, stdout=process.stdout, stderr=process.stderr)
        except Exception as exc:
            result["error"] = str(exc)
        finally:
            for spec in config["cleanup"]:
                try:
                    response = request(spec)
                    response["ok"] = response["status"] == spec["expected_status"] and (not spec.get("body_contains") or spec["body_contains"] in response["body"])
                    result["cleanup"].append(response)
                except Exception as exc:
                    result["cleanup"].append({"ok": False, "error": str(exc)})
        print(json.dumps(result))
    elif action == "defectdojo":
        with httpx.Client(timeout=30, follow_redirects=False) as client:
            headers = {"Authorization": "Token " + config["token"]}
            if config.get("method") in ("GET", "PATCH"):
                response = client.request(config["method"], config["url"], headers=headers,
                                          json=config.get("body"))
            else:
                response = client.post(config["url"], headers=headers, data=config["fields"],
                    files={"file": ("erlik.json", json.dumps(config["report"]), "application/json")})
            print(json.dumps({"status": response.status_code, "body": response.text}))
    elif action == "browser":
        FORM_SCRIPT = """() => Array.from(document.querySelectorAll('form')).slice(0, 25).map(f => ({
            action: f.action || '',
            method: (f.getAttribute('method') || 'GET').toUpperCase(),
            controls: Array.from(f.elements).slice(0, 40)
                .filter(e => e.name)
                .map(e => ({name: e.name,
                            type: (e.type || '').toLowerCase(),
                            value: typeof e.value === 'string' ? e.value.slice(0, 200) : ''}))}))"""
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path="/usr/bin/chromium", headless=True,
                proxy={"server": os.environ["HTTP_PROXY"], "bypass": "<-loopback>"},
                args=["--no-sandbox", "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
            context = browser.new_context(storage_state=config.get("storage_state"), ignore_https_errors=True)
            # Chromium bypasses proxy for localhost unless explicitly overridden above.
            page = context.new_page()
            observed = []
            page.on("request", lambda r: observed.append({"url": r.url, "method": r.method}))
            # `networkidle` first, because a settled page has loaded its bundles and
            # issued its XHRs — which is where the routes no crawler follows live. But
            # an application whose front end polls NEVER goes idle, and the timeout was
            # fatal: measured on Juice Shop, `Page.goto: Timeout 30000ms exceeded`, and
            # with it the whole rendered pass — the only source of form discovery.
            #
            # So idle is an optimisation, not a requirement. `domcontentloaded` is the
            # floor, and the extra wait below gives late XHRs a bounded chance to fire
            # without letting a chatty page hold the crawl open.
            try:
                page.goto(config["url"], wait_until="networkidle", timeout=20000)
            except Exception:
                page.goto(config["url"], wait_until="domcontentloaded", timeout=20000)
                try:
                    page.wait_for_timeout(3000)
                except Exception:
                    pass
            links = page.locator("a[href]").evaluate_all("nodes => nodes.map(n => n.href)")
            # Form controls, because an input the crawler cannot see is an input
            # nothing can test. `f.action` is already absolute in the DOM (the
            # browser resolves action="#" to the page URL), and f.elements covers
            # input, select, textarea and button alike. Values come along because
            # a form's OTHER fields are usually required for its handler to run
            # at all — DVWA's SQLi page returns nothing for ?id=<payload> and the
            # rows for ?id=<payload>&Submit=Submit.
            forms = page.evaluate(FORM_SCRIPT)
            # One level deeper, for FORMS only. A single-page crawl finds the
            # forms on the landing page, and applications keep their inputs one
            # click in — DVWA's menu is all links and every injectable form is
            # behind one. Bounded, same-origin, and every request still goes
            # through the proxy, which refuses anything out of scope.
            origin = page.url.split("/")[0] + "//" + page.url.split("/")[2] if "//" in page.url else ""
            seen_pages = {page.url}
            # A cap that is not reported reads as "we visited everything". This one
            # is worse than most: two arms publishing different menus truncate at
            # different places, so the cap manufactures a surface difference — and
            # when they publish the SAME menu it truncates identically and HIDES a
            # real one. Measured on DVWA, where changing only the crawl root moved
            # the boundary one link and revealed a form that exists at one security
            # level and not the other. So the count travels with the result.
            capped = 0
            for href in links:
                if len(seen_pages) > int(config.get("form_pages", 20)):
                    capped = sum(1 for u in links
                                 if u.startswith(origin) and u not in seen_pages)
                    break
                if not href.startswith(origin) or href in seen_pages:
                    continue
                seen_pages.add(href)
                try:
                    page.goto(href, wait_until="domcontentloaded", timeout=15000)
                    forms += page.evaluate(FORM_SCRIPT)
                except Exception:
                    continue                       # an unreachable link is not a failure
            print(json.dumps({"requests": observed, "links": links, "forms": forms,
                              "pages_visited": len(seen_pages),
                              "pages_not_visited": capped, "url": config["url"]}))
            browser.close()
    elif action == "baseline_browser":
        # Execute the repository's original crawler with transport-only shims:
        # reuse the pinned Playwright driver and enforce the same egress proxy.
        import hashlib
        import subprocess
        import playwright
        driver = Path(playwright.__file__).parent / "driver"
        source = Path(config["script"]).read_text()
        adjusted = source.replace('require("playwright")', "require(" + json.dumps(str(driver / "package")) + ")")
        adjusted = adjusted.replace("chromium.launch({", 'chromium.launch({proxy:{server:process.env.HTTP_PROXY,bypass:"<-loopback>"},')
        Path("/tmp/baseline.js").write_text(adjusted)
        process = subprocess.run([str(driver / "node"), "/tmp/baseline.js", config["url"]], capture_output=True, text=True, timeout=45)
        print(json.dumps({"exit_code": process.returncode, "stdout": process.stdout, "stderr": process.stderr,
                          "source_sha256": hashlib.sha256(source.encode()).hexdigest()}))
    else:
        raise ValueError("unknown worker action")


if __name__ == "__main__":
    main()
