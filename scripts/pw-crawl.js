#!/usr/bin/env node
// pw-crawl: Playwright-based JS-rendered page crawler
// Usage: pw-crawl <URL>
// Returns: page title, all links, all forms, JS-rendered API calls

const { chromium } = require("playwright");
const url = process.argv[2];
if (!url) {
  console.log("Usage: pw-crawl <URL>");
  process.exit(1);
}

(async () => {
  let browser;
  try {
    browser = await chromium.launch({
      executablePath: "/usr/bin/chromium",
      args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(2000); // let Angular/React render

    const data = await page.evaluate(() => {
      const links = [...new Set(
        Array.from(document.querySelectorAll("a[href], [routerlink]"))
          .map(el => el.href || el.getAttribute("routerlink"))
          .filter(Boolean)
      )];
      const forms = Array.from(document.querySelectorAll("form")).map(f => ({
        action: f.action, method: f.method,
        inputs: Array.from(f.querySelectorAll("input,textarea,select")).map(i => ({
          name: i.name, type: i.type, id: i.id
        }))
      }));
      const buttons = Array.from(document.querySelectorAll("button,[role=button]"))
        .map(b => b.textContent.trim()).filter(t => t.length > 0 && t.length < 50);
      const apiCalls = performance.getEntriesByType("resource")
        .filter(r => r.name.includes("/api/") || r.name.includes("/rest/"))
        .map(r => r.name);
      return { title: document.title, links, forms, buttons, apiCalls };
    });

    console.log("=== Page Title ===");
    console.log(data.title);
    console.log("\n=== Links Found (" + data.links.length + ") ===");
    data.links.slice(0, 30).forEach(l => console.log("  " + l));
    console.log("\n=== Forms Found (" + data.forms.length + ") ===");
    data.forms.forEach(f => {
      console.log("  Action: " + f.action + " Method: " + f.method);
      f.inputs.forEach(i => console.log("    Input: " + i.name + " (" + i.type + ")"));
    });
    if (data.buttons.length > 0) {
      console.log("\n=== Buttons (" + data.buttons.length + ") ===");
      data.buttons.slice(0, 15).forEach(b => console.log("  " + b));
    }
    if (data.apiCalls.length > 0) {
      console.log("\n=== API Calls Observed (" + data.apiCalls.length + ") ===");
      [...new Set(data.apiCalls)].slice(0, 20).forEach(a => console.log("  " + a));
    }
  } catch (e) {
    console.error("Error:", e.message);
  } finally {
    if (browser) await browser.close();
  }
})();
