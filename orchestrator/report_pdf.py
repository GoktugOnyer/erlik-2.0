"""Render the client-ready HTML report to a PDF with headless Chromium.

The PDF is the one deliverable an operator prints and hands over, so it is not
a new rendering — it is `reporting.report_to_html` driven through Chromium's
print path. Whatever the HTML report shows, the PDF shows, which is why the two
cannot drift: there is one template.

Playwright is an OPTIONAL dependency here. The runtime install
(`requirements.txt`) stays lean; Playwright is pinned in
`requirements-browser-login.txt` and present wherever PDF export is wanted. If
it is missing, or the browser cannot launch, this raises `PdfUnavailable` and
the route answers 503 with the reason — declared and disabled, never a silent
empty file.

The browser binary is the one the container already ships
(`/opt/pw-browsers/chromium`); `playwright install` is neither needed nor run.
`--no-sandbox` is required because the server runs as root in the container,
where Chromium's sandbox refuses to start.
"""

from __future__ import annotations

import os

from orchestrator.reporting import report_to_html

# Where the container keeps the pre-installed Chromium. Overridable for a host
# that puts it elsewhere; an empty/missing path falls back to Playwright's own
# discovery via PLAYWRIGHT_BROWSERS_PATH.
_CHROMIUM = os.environ.get("ERLIK_CHROMIUM_PATH", "/opt/pw-browsers/chromium")


class PdfUnavailable(RuntimeError):
    """PDF rendering could not run — Playwright absent or the browser failed."""


async def report_to_pdf(report: dict) -> bytes:
    """A PDF of the HTML report. Raises PdfUnavailable when it cannot render.

    Async so it can be awaited directly from the FastAPI route: Playwright's
    sync API refuses to run inside a running asyncio loop, so the async driver
    is the correct one here.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as e:  # Playwright not installed in this runtime
        raise PdfUnavailable(
            "PDF export needs Playwright (pip install -r "
            "requirements-browser-login.txt)") from e

    html = report_to_html(report)

    launch_kwargs: dict = {"args": ["--no-sandbox"]}
    if _CHROMIUM and os.path.exists(_CHROMIUM):
        launch_kwargs["executable_path"] = _CHROMIUM

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(**launch_kwargs)
            try:
                page = await browser.new_page()
                # `networkidle` would hang on a self-contained document that
                # never issues a request; the HTML inlines its styling, so
                # `load` is both sufficient and bounded.
                await page.set_content(html, wait_until="load")
                pdf = await page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "16mm", "bottom": "16mm",
                            "left": "12mm", "right": "12mm"},
                )
            finally:
                await browser.close()
    except PdfUnavailable:
        raise
    except Exception as e:  # launch/render failure — browser missing, crash, …
        raise PdfUnavailable(f"Chromium could not render the report: {e}") from e

    return pdf
