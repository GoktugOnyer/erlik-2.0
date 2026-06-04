"""Execute pentest tools inside the kali-tools Docker container (or natively via ERLIK_NATIVE)."""

import asyncio
import os
import re
import shutil
import subprocess
import time

ERLIK_NATIVE = bool(os.environ.get("ERLIK_NATIVE", ""))
CONTAINER_NAME = "kali-tools"

# Find docker binary — check PATH first, then well-known install locations on
# Windows / macOS / Linux. Without this, the orchestrator silently fails every
# tool execution with "kali-tools container is not running" because the
# pre-flight container check can't find `docker` to invoke at all.
_DOCKER_FALLBACK_PATHS = [
    r"C:\Program Files\Docker\Docker\resources\bin",  # Docker Desktop (Windows)
    os.path.expanduser("~/.orbstack/bin"),            # OrbStack (macOS)
    "/Applications/Docker.app/Contents/Resources/bin",  # Docker Desktop (macOS)
    "/usr/local/bin",                                  # Homebrew / Linux conventional
    "/opt/homebrew/bin",                               # Apple Silicon Homebrew
]

def _resolve_docker_bin() -> str:
    direct = shutil.which("docker")
    if direct:
        return direct
    for p in _DOCKER_FALLBACK_PATHS:
        found = shutil.which("docker", path=p)
        if found:
            return found
    return "docker"  # last-resort string; will fail loudly if invoked

DOCKER_BIN = _resolve_docker_bin()

# Legacy Docker-network service name used by the original Juice Shop lab.
# Only consulted when ERLIK_DOCKER_TARGET_HOST is explicitly set OR when a
# target_url is missing AND the legacy lab compose stack is in use.
LEGACY_DOCKER_TARGET_HOST = os.environ.get("ERLIK_DOCKER_TARGET_HOST", "")

# Tools that are safe to run and their max execution time (seconds)
TOOL_TIMEOUTS = {
    # Recon & Scanning
    "nmap": 120,
    "nuclei": 180,
    "nikto": 60,
    "whatweb": 30,
    "wafw00f": 30,
    "arjun": 90,
    "whois": 15,
    "sslyze": 60,
    "testssl": 90,
    # Fuzzing & Discovery
    "ffuf": 120,
    "gobuster": 120,
    "dirb": 120,
    "wfuzz": 120,
    # Injection & Exploitation
    "sqlmap": 180,
    "xsstrike": 120,
    "dalfox": 120,
    "commix": 120,
    "crlfuzz": 60,
    # Auth & Crypto
    "hydra": 120,
    "john": 120,
    "hashcat": 120,
    "jwt_tool": 60,
    # Browser & Automation
    "playwright": 180,
    "pw-crawl": 30,
    "interactive-pw": 180,  # scriptable Playwright recipe runner
    "zap-cli": 300,
    # Utilities
    "curl": 30,
    "netcat": 30,
    # Capability helpers (2026-04-06) — dumb, deterministic, no detection logic
    "login-helper": 15,  # generic two-user token fetcher (lab helper)
    "diff-view": 30,     # HTTP response diff viewer (NOT a detector)
}

# Commands that are never allowed
BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"mkfs",
    r"dd\s+if=",
    r"shutdown",
    r"reboot",
    r">\s*/dev/sd",
    r"chmod\s+777\s+/",
    r"wget.*\|.*sh",
    r"curl.*\|.*sh",
]


def _sanitize_command(command: str, target_url: str = None) -> str:
    """Rewrite hostname references to point at the actual target.

    Two concerns:
      1. The LLM (especially fine-tuned 7B/14B) frequently emits
         `juice-shop:3000` from training-data bias. We always rewrite that
         literal to the real target so commands work against any target.
      2. When running inside the Docker network, localhost references from
         the model must be rewritten to the in-network service name, but
         only if ERLIK_DOCKER_TARGET_HOST is configured for the current lab.
    """
    from urllib.parse import urlparse

    target_host = "localhost"
    target_port = 80
    target_hp = f"{target_host}:{target_port}"

    if target_url:
        parsed = urlparse(target_url)
        target_host = parsed.hostname or "localhost"
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_hp = f"{target_host}:{target_port}"

        # Strip LLM training-data bias toward juice-shop:3000, but only when
        # the actual target is NOT juice-shop. When it is, the rewrite would
        # duplicate path segments (e.g. /rest/products/rest/products/...).
        if "juice-shop" not in target_host:
            command = command.replace("http://juice-shop:3000", target_url.rstrip("/"))
            command = command.replace("https://juice-shop:3000", target_url.rstrip("/"))
            command = command.replace("juice-shop:3000", target_hp)
            command = re.sub(r'\bjuice-shop\b', target_host, command)

    # Legacy lab support: ERLIK_DOCKER_TARGET_HOST=juice-shop reproduces old
    # behaviour where the agent says "localhost" but means the in-network app.
    if not ERLIK_NATIVE and LEGACY_DOCKER_TARGET_HOST:
        host = LEGACY_DOCKER_TARGET_HOST
        port = target_port or 3000
        command = re.sub(r'https?://localhost:\d+', f'http://{host}:{port}', command)
        command = re.sub(r'https?://127\.0\.0\.1:\d+', f'http://{host}:{port}', command)
        command = re.sub(r'\blocalhost\b', host, command)
        command = re.sub(r'\b127\.0\.0\.1\b', host, command)

    tool_name = _extract_tool_name(command)
    if not ERLIK_NATIVE and LEGACY_DOCKER_TARGET_HOST:
        # Tools that require an explicit http:// scheme — fix bare host:port.
        TOOLS_NEEDING_SCHEME = ["gobuster", "ffuf", "nikto", "nuclei", "dalfox", "wfuzz",
                                "sqlmap", "xsstrike", "commix", "crlfuzz", "whatweb", "wafw00f",
                                "arjun", "curl", "zap-cli"]
        if tool_name in TOOLS_NEEDING_SCHEME:
            host = LEGACY_DOCKER_TARGET_HOST
            port = target_port or 3000
            command = re.sub(
                r'(?<!http://)(?<!https://)\b' + re.escape(host) + r':\d+\b',
                f'http://{host}:{port}',
                command,
            )
            command = re.sub(
                r'(?<!http://)(?<!https://)\b' + re.escape(host) + r'(?!:)\b',
                f'http://{host}:{port}',
                command,
            )

    # Coverage fix (2026-04-07): when the agent calls `nuclei` without any
    # `-tags`/`-t`/`-templates`/`-w`/`-id` selector, it ends up running just
    # the default template subset which misses A02 (crypto), A07 (auth), A08
    # (SCA/CVE), A10 (SSRF). Inject a broad tag set so the LLM doesn't have
    # to know nuclei's flag conventions to get full coverage.
    if tool_name == "nuclei":
        has_selector = bool(re.search(r'(?:^|\s)-(?:tags|t|templates|tl|id|w)\b', command))
        if not has_selector:
            command += " -tags cve,vuln,sqli,xss,ssrf,jwt,auth,exposure,misconfig,default-login"

    # Bounded brute force (2026-06): hydra against a full wordlist (rockyou is
    # ~14M entries) runs for hours and rarely finishes. A time-boxed engagement
    # tries common/default credentials, not the whole list. So we automatically:
    #   - cap the password list (-P) to its top-N entries (real bounded file)
    #   - stop on the first valid credential (-f)
    #   - use a web-friendly thread count if none was specified (-t)
    # This makes hydra complete in seconds with the realistic win (weak/default
    # creds) instead of blocking forever. Configurable via ERLIK_HYDRA_PASS_CAP
    # (number of entries); set it to 0 to disable bounding entirely.
    if tool_name == "hydra":
        try:
            cap = int(os.environ.get("ERLIK_HYDRA_PASS_CAP", "300"))
        except ValueError:
            cap = 300
        if cap > 0:
            if not re.search(r'(?:^|\s)-f\b', command):
                command += " -f"          # stop on first valid credential
            if not re.search(r'(?:^|\s)-t\s+\d+', command):
                command += " -t 8"        # sane thread count for web logins
            m = re.search(r'-P\s+(\S+)', command)
            if m and not m.group(1).startswith("/tmp/erlik_"):
                wl = m.group(1)
                bounded = "/tmp/erlik_hydra_pw.txt"
                command = command.replace(f"-P {wl}", f"-P {bounded}", 1)
                # build the bounded list first, then run hydra against it
                command = f"head -n {cap} {wl} > {bounded} 2>/dev/null; {command}"

    return command


def _validate_command(command: str) -> str | None:
    """Return error string if command is blocked, else None."""
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return f"Blocked: command matches dangerous pattern '{pattern}'"
    return None


def _extract_tool_name(command: str) -> str | None:
    """Extract the base tool name from a shell command."""
    # Strip leading env vars, sudo, timeout wrappers
    cmd = re.sub(r'^(sudo\s+|timeout\s+\d+\s+|env\s+\S+=\S+\s+)*', '', command.strip())
    parts = cmd.split()
    if not parts:
        return None
    tool = parts[0].split("/")[-1]  # handle /usr/bin/nmap -> nmap
    return tool


def _shell_quote(s: str) -> str:
    """Quote a string for safe use in a shell command on Windows or Linux."""
    # Wrap in double quotes, escape existing double quotes
    escaped = s.replace('"', '\\"')
    return f'"{escaped}"'


async def check_container_running() -> bool:
    """Check if the kali-tools container is running (or return True in native mode)."""
    if ERLIK_NATIVE:
        return True
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, _sync_check_container
        )
        return result
    except Exception as e:
        print(f"[tool_executor] container check EXCEPTION: {e}")
        return False


def _sync_check_container() -> bool:
    """Synchronous container check (runs in thread pool)."""
    try:
        r = subprocess.run(
            [DOCKER_BIN, "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() == "true"
    except Exception as e:
        print(f"[tool_executor] sync container check error: {e}")
        return False


async def execute_tool(command: str, enabled_tools: list[str], no_timeout: bool = False, target_url: str = None, tool_hint: str = None, custom_timeout: int = None) -> dict:
    """
    Execute a command in the kali-tools Docker container.

    Args:
        command: Shell command to run
        enabled_tools: List of allowed tool names
        no_timeout: If True, wait indefinitely for tool to finish (max 10 min)

    Returns dict with:
        success: bool
        output: str (stdout + stderr, truncated)
        tool: str (detected tool name)
        duration_ms: int
        error: str | None
    """
    # Validate
    error = _validate_command(command)
    if error:
        return {"success": False, "output": "", "tool": "blocked", "duration_ms": 0, "error": error}

    # Test cases (v2) declare the tool explicitly via `tool:`. Trust that
    # declaration for whitelist checking — commands like `bash -c '... curl ...'`
    # legitimately need to construct a pipeline whose first token isn't the
    # logical tool. Fall back to extraction for legacy callers.
    extracted = _extract_tool_name(command)
    tool_name = tool_hint or extracted
    if not tool_name:
        return {"success": False, "output": "", "tool": "unknown", "duration_ms": 0, "error": "Could not parse tool name"}

    # Check if tool is enabled
    # Map some tool names (e.g. ncat -> netcat, nc -> netcat)
    tool_aliases = {"nc": "netcat", "ncat": "netcat", "zap-cli": "zap-cli", "jwt_tool.py": "jwt_tool"}
    check_name = tool_aliases.get(tool_name, tool_name)
    if check_name not in enabled_tools and tool_name not in enabled_tools:
        return {"success": False, "output": "", "tool": tool_name, "duration_ms": 0,
                "error": f"Tool '{tool_name}' is not enabled for this session"}

    # Resolve timeout (seconds). Precedence:
    #   no_timeout=True       -> truly unlimited (None). Optional ERLIK_NO_TIMEOUT_CAP>0
    #                            re-imposes a cap for safety-conscious deployments.
    #   custom_timeout given  -> that exact value applies to every tool
    #   otherwise             -> per-tool default
    if no_timeout:
        _cap = int(os.environ.get("ERLIK_NO_TIMEOUT_CAP", "0"))  # 0 = truly unlimited (default)
        timeout = None if _cap <= 0 else _cap
    elif custom_timeout and int(custom_timeout) > 0:
        timeout = int(custom_timeout)
    else:
        timeout = TOOL_TIMEOUTS.get(tool_name, 60)

    # Rewrite localhost to docker network
    sanitized = _sanitize_command(command, target_url=target_url)

    # Check container is running
    if not await check_container_running():
        return {"success": False, "output": "", "tool": tool_name, "duration_ms": 0,
                "error": "kali-tools container is not running. Start it with: docker compose up -d kali-tools"}

    # Execute in docker via sync subprocess in thread pool (Windows compatible)
    start = time.time()
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _sync_docker_exec(sanitized, timeout)
        )
        duration_ms = int((time.time() - start) * 1000)

        output = result["output"]
        # Intelligent output handling: keep head + tail instead of blind truncation.
        # Many security tools put key findings/summaries at the END of their output.
        max_output = 6000
        if len(output) > max_output:
            head_size = 2500
            tail_size = 2500
            head = output[:head_size]
            tail = output[-tail_size:]
            skipped = len(output) - head_size - tail_size
            output = (
                f"{head}\n"
                f"\n[... {skipped} chars omitted ({len(output)} total) ...]\n\n"
                f"{tail}"
            )

        return {
            "success": result["returncode"] == 0,
            "output": output.strip(),
            "tool": tool_name,
            "duration_ms": duration_ms,
            "error": result.get("error"),
        }

    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        return {"success": False, "output": "", "tool": tool_name,
                "duration_ms": duration_ms, "error": str(e)}


def _sync_docker_exec(command: str, timeout: int) -> dict:
    """Run a command in the kali-tools container or natively (synchronous, for thread pool)."""
    try:
        if ERLIK_NATIVE:
            cmd = ["bash", "-c", command]
        else:
            cmd = [DOCKER_BIN, "exec", CONTAINER_NAME, "bash", "-c", command]
        r = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout,
        )
        return {
            "output": r.stdout + r.stderr,
            "returncode": r.returncode,
            "error": None if r.returncode == 0 else f"Exit code {r.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {
            "output": f"[TIMEOUT after {timeout}s]",
            "returncode": -1,
            "error": f"Command timed out after {timeout} seconds",
        }
    except Exception as e:
        return {"output": "", "returncode": -1, "error": str(e)}
