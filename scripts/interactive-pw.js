#!/usr/bin/env node
// interactive-pw — scriptable Playwright recipe runner
//
// Purpose: give the LLM agent eyes and hands in the browser so it can
// drive multi-step flows (login, click, fill, screenshot) that pure
// CLI scanners cannot reach. Enables IDOR / UI / access-control probing.
//
// This script is INTENTIONALLY DUMB. It executes the recipe the LLM
// sends, prints the resulting page state, and exits. It does NOT
// classify bugs. The LLM decides what recipe to run next.
//
// Usage (two modes):
//   interactive-pw <URL>           # back-compat: behaves like pw-crawl
//   echo '<JSON recipe>' | interactive-pw --stdin
//
// JSON recipe shape:
// {
//   "url": "http://juice-shop:3000",   // optional initial URL
//   "steps": [
//     {"op": "goto",    "url": "http://juice-shop:3000"},
//     {"op": "click",   "selector": "button[aria-label='Account']"},
//     {"op": "fill",    "selector": "#email",    "value": "admin@juice-sh.op"},
//     {"op": "fill",    "selector": "#password", "value": "admin123"},
//     {"op": "click",   "selector": "#loginButton"},
//     {"op": "waitForNetworkIdle"},
//     {"op": "wait",    "ms": 2000},
//     {"op": "screenshot", "path": "/tmp/admin_home.png"},
//     {"op": "eval",    "expr": "document.cookie"},
//     {"op": "extract"}
//   ]
// }

const { chromium } = require("playwright");

const args = process.argv.slice(2);
const stdinMode = args.includes("--stdin");
const urlArg = args.find(a => !a.startsWith("--"));

function usage() {
  console.error("Usage: interactive-pw <URL>  OR  interactive-pw --stdin  (reads JSON recipe on stdin)");
  process.exit(1);
}

async function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

async function extractPageState(page) {
  return await page.evaluate(() => {
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
    return {
      title: document.title,
      url: location.href,
      links, forms, buttons, apiCalls
    };
  });
}

function printState(data, label = "Page State") {
  console.log(`=== ${label} ===`);
  console.log("URL:   " + data.url);
  console.log("Title: " + data.title);
  console.log("\n-- Links (" + data.links.length + ") --");
  data.links.slice(0, 30).forEach(l => console.log("  " + l));
  console.log("\n-- Forms (" + data.forms.length + ") --");
  data.forms.forEach(f => {
    console.log("  Action: " + f.action + " Method: " + f.method);
    f.inputs.forEach(i => console.log("    Input: " + i.name + " (" + i.type + ")"));
  });
  if (data.buttons.length > 0) {
    console.log("\n-- Buttons (" + data.buttons.length + ") --");
    data.buttons.slice(0, 15).forEach(b => console.log("  " + b));
  }
  if (data.apiCalls.length > 0) {
    console.log("\n-- API Calls (" + [...new Set(data.apiCalls)].length + " unique) --");
    [...new Set(data.apiCalls)].slice(0, 20).forEach(a => console.log("  " + a));
  }
}

(async () => {
  let recipe;
  if (stdinMode) {
    const raw = await readStdin();
    try {
      recipe = JSON.parse(raw);
    } catch (e) {
      console.error("Invalid JSON recipe on stdin: " + e.message);
      process.exit(1);
    }
    if (!recipe.steps || !Array.isArray(recipe.steps)) {
      console.error("Recipe must have a 'steps' array.");
      process.exit(1);
    }
  } else if (urlArg) {
    // back-compat: bare URL → same behaviour as pw-crawl
    recipe = { steps: [{ op: "goto", url: urlArg }, { op: "waitForNetworkIdle" }, { op: "extract" }] };
  } else {
    usage();
  }

  let browser;
  try {
    browser = await chromium.launch({
      executablePath: "/usr/bin/chromium",
      args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
    });
    const context = await browser.newContext();
    const page = await context.newPage();

    let stepIdx = 0;
    for (const step of recipe.steps) {
      stepIdx++;
      const op = step.op;
      try {
        if (op === "goto") {
          await page.goto(step.url, { waitUntil: "networkidle", timeout: 20000 });
        } else if (op === "click") {
          await page.click(step.selector, { timeout: 10000 });
        } else if (op === "fill") {
          await page.fill(step.selector, step.value, { timeout: 10000 });
        } else if (op === "type") {
          await page.type(step.selector, step.value, { timeout: 10000 });
        } else if (op === "press") {
          await page.press(step.selector || "body", step.key, { timeout: 10000 });
        } else if (op === "waitForNetworkIdle") {
          await page.waitForLoadState("networkidle", { timeout: 15000 });
        } else if (op === "waitForSelector") {
          await page.waitForSelector(step.selector, { timeout: 15000 });
        } else if (op === "wait") {
          await page.waitForTimeout(step.ms || 1000);
        } else if (op === "screenshot") {
          await page.screenshot({ path: step.path || "/tmp/interactive-pw.png", fullPage: !!step.full });
          console.log(`[step ${stepIdx}] screenshot saved: ${step.path || "/tmp/interactive-pw.png"}`);
        } else if (op === "eval") {
          const v = await page.evaluate(step.expr);
          console.log(`[step ${stepIdx}] eval "${step.expr}" => ${JSON.stringify(v)}`);
        } else if (op === "extract") {
          const data = await extractPageState(page);
          printState(data, `Page State at Step ${stepIdx}`);
        } else if (op === "cookies") {
          const cookies = await context.cookies();
          console.log(`[step ${stepIdx}] cookies: ${JSON.stringify(cookies)}`);
        } else {
          console.log(`[step ${stepIdx}] UNKNOWN op: ${op} (skipped)`);
        }
      } catch (err) {
        console.error(`[step ${stepIdx}] ${op} failed: ${err.message}`);
        // Continue executing the rest of the recipe — let the LLM decide.
      }
    }

    // If the recipe didn't explicitly extract, extract at the end.
    const hasExtract = recipe.steps.some(s => s.op === "extract");
    if (!hasExtract) {
      const data = await extractPageState(page);
      printState(data, "Final Page State");
    }
  } catch (e) {
    console.error("Fatal error: " + e.message);
    process.exit(2);
  } finally {
    if (browser) await browser.close();
  }
})();
