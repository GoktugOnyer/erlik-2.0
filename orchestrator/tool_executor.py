"""Execute pentest tools inside the kali-tools Docker container."""

import asyncio
import re
import shutil
import subprocess
import time

CONTAINER_NAME = "kali-tools"

# Find docker binary - check common paths if not on PATH
DOCKER_BIN = shutil.which("docker") or shutil.which("docker", path=r"C:\Program Files\Docker\Docker\resources\bin") or "docker"

# Target hostname inside Docker network (juice-shop service name)
DOCKER_TARGET_HOST = "juice-shop"

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
    "zap-cli": 300,
    # Utilities
    "curl": 30,
    "netcat": 30,
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


def _sanitize_command(command: str) -> str:
    """Rewrite localhost references to docker network hostname and fix URLs."""
    # Replace localhost/127.0.0.1 with the Docker service name
    command = re.sub(r'https?://localhost:3000', f'http://{DOCKER_TARGET_HOST}:3000', command)
    command = re.sub(r'https?://127\.0\.0\.1:3000', f'http://{DOCKER_TARGET_HOST}:3000', command)
    command = re.sub(r'localhost:3000', f'http://{DOCKER_TARGET_HOST}:3000', command)
    command = re.sub(r'127\.0\.0\.1:3000', f'http://{DOCKER_TARGET_HOST}:3000', command)
    command = re.sub(r'localhost', f'{DOCKER_TARGET_HOST}', command)

    # Tools that require http:// scheme — fix bare host:port references
    # Match tool_name ... juice-shop:3000 where there's no http:// before it
    TOOLS_NEEDING_SCHEME = ["gobuster", "ffuf", "nikto", "nuclei", "dalfox", "wfuzz",
                            "sqlmap", "xsstrike", "commix", "crlfuzz", "whatweb", "wafw00f",
                            "arjun", "curl", "zap-cli"]
    tool_name = _extract_tool_name(command)
    if tool_name in TOOLS_NEEDING_SCHEME:
        # Add http:// before bare juice-shop:3000 (not already preceded by http://)
        command = re.sub(
            r'(?<!http://)(?<!https://)\b' + re.escape(DOCKER_TARGET_HOST) + r':3000\b',
            f'http://{DOCKER_TARGET_HOST}:3000',
            command,
        )
        # Also fix bare juice-shop without port (for tools like -u juice-shop)
        command = re.sub(
            r'(?<!http://)(?<!https://)\b' + re.escape(DOCKER_TARGET_HOST) + r'(?!:)\b',
            f'http://{DOCKER_TARGET_HOST}:3000',
            command,
        )
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
    """Check if the kali-tools container is running."""
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


async def execute_tool(command: str, enabled_tools: list[str], no_timeout: bool = False) -> dict:
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

    tool_name = _extract_tool_name(command)
    if not tool_name:
        return {"success": False, "output": "", "tool": "unknown", "duration_ms": 0, "error": "Could not parse tool name"}

    # Check if tool is enabled
    # Map some tool names (e.g. ncat -> netcat, nc -> netcat)
    tool_aliases = {"nc": "netcat", "ncat": "netcat", "zap-cli": "zap-cli", "jwt_tool.py": "jwt_tool"}
    check_name = tool_aliases.get(tool_name, tool_name)
    if check_name not in enabled_tools and tool_name not in enabled_tools:
        return {"success": False, "output": "", "tool": tool_name, "duration_ms": 0,
                "error": f"Tool '{tool_name}' is not enabled for this session"}

    # Get timeout — no_timeout mode uses 10 minutes max (safety cap)
    if no_timeout:
        timeout = 600  # 10 minutes max even in no-timeout mode
    else:
        timeout = TOOL_TIMEOUTS.get(tool_name, 60)

    # Rewrite localhost to docker network
    sanitized = _sanitize_command(command)

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
    """Run a command in the kali-tools container (synchronous, for thread pool)."""
    try:
        r = subprocess.run(
            [DOCKER_BIN, "exec", CONTAINER_NAME, "bash", "-c", command],
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
