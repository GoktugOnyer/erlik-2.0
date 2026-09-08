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
            page.goto(config["url"], wait_until="networkidle", timeout=30000)
            links = page.locator("a[href]").evaluate_all("nodes => nodes.map(n => n.href)")
            print(json.dumps({"requests": observed, "links": links, "url": page.url}))
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
