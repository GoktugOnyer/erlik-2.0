"""Short-lived Docker jobs on an internal network, behind an enforcing proxy."""
from __future__ import annotations
import asyncio
import hashlib
import json
import os
import re
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from .contracts import AssessmentConfig, StageResult
from .security import private_write, runtime_root, secret_values

IMAGES = {
    "proxy": "erlik-egress:1",
    "worker": "erlik-integrations:1",
    "zap": "ghcr.io/zaproxy/zaproxy:2.16.1",
}
# WHAT PRODUCED A FINDING, in one place rather than three.
#
# E-016 asks that a finding be packaged with its "tool/image version", so a reviewer handed
# one finding can reproduce it without being handed the lane as well. The facts existed and
# were scattered: ZAP's image here, katana's `"version": "1.2.2"` and Schemathesis's
# `"version": "4.0.14"` inlined in their adapters' stage metadata, and nothing at all on the
# finding. Three copies of one fact is the defect this codebase names about its own catalogue
# lists, and the finding — the thing that leaves the building — had none of them.
#
# The adapters read their version from here now, so a finding's provenance and its stage's
# metadata cannot disagree.
TOOL_VERSIONS = {"katana": "1.2.2", "schemathesis": "4.0.14"}

# Findings erlik's own code makes by comparing stored evidence. No container ran, so naming
# an image would be inventing one — and what a reviewer needs to reproduce these is the
# recorded evidence and the rule, both of which the finding already carries.
LANE_AUTHORED = ("cross-arm", "testcase")


def produced_by(source: str) -> str:
    """The image and tool version behind a finding from `source`.

    Every producer fills it; `test_every_producer_says_what_made_the_finding` asserts that,
    because a finding that cannot say what made it is exactly the one a reviewer cannot
    reproduce, and a new producer defaulting to empty would be silent about it.
    """
    if source in LANE_AUTHORED:
        return (f"erlik {source} evaluation over stored evidence; no scanner image ran — "
                f"reproduce from the cited evidence artifacts and the rule")
    if source == "zap":
        return IMAGES["zap"]
    if source in TOOL_VERSIONS:
        return f"{source} {TOOL_VERSIONS[source]} in {IMAGES['worker']}"
    return IMAGES["worker"]


OWNER = "erlik.owner=" + hashlib.sha256(str(Path(__file__).resolve().parents[2]).encode()).hexdigest()[:12]


async def docker(*args, timeout=60, check=True):
    proc = await asyncio.create_subprocess_exec(os.environ.get("ERLIK_DOCKER_BIN", "docker"), *map(str, args),
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except BaseException:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        raise
    if check and proc.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {stderr.decode(errors='replace')[-1000:]}")
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def availability():
    result = {}
    for name, image in IMAGES.items():
        try:
            code, out, err = await docker("image", "inspect", image, "--format", "{{.Id}}", check=False, timeout=10)
            result[name] = {"available": code == 0, "image": image, "image_id": out.strip(), "reason": err.strip()}
        except (OSError, RuntimeError, asyncio.TimeoutError) as exc:
            result[name] = {"available": False, "image": image, "reason": str(exc)}
    return result


async def recover_orphans():
    # Restrict cleanup to this workspace's integration resources, never other containers.
    try:
        _, names, _ = await docker("ps", "-aq", "--filter", f"label={OWNER}", timeout=10)
        if names.split():
            # Stop even if a crash left an unreadable artifact manifest.
            code, _, _ = await docker("stop", "-t", "1", *names.split(), check=False)
            if code:
                return False
        abandoned = []
        for directory in (runtime_root() / "jobs").glob("*"):
            if directory.is_symlink() or not re.fullmatch(r"[a-f0-9]{32}", directory.name):
                continue
            manifest_path = directory / "manifest.json"
            if not manifest_path.is_file() or manifest_path.is_symlink():
                continue
            manifest = json.loads(manifest_path.read_text())
            if manifest.get("owner") == OWNER:
                abandoned.append((directory, manifest))
        if names.split():
            # Retain attached scanner logs before removal.
            for directory, manifest in abandoned:
                for name in manifest.get("jobs", []):
                    if not re.fullmatch(r"erlik-job-[a-f0-9]{32}", name):
                        raise ValueError("invalid container name in recovery manifest")
                    code, out, err = await docker("logs", name, check=False)
                    if code == 0:
                        private_write(directory / "output" / f"{name}.stdout", out)
                        private_write(directory / "output" / f"{name}.stderr", err)
            # `-v`, NOT just `-f`. `erlik-egress:1` inherits `VOLUME
            # /home/mitmproxy/.mitmproxy` from its base image, so every proxy container
            # creates an anonymous volume — and every sandbox runs a proxy. Removing the
            # container without it leaves the volume forever.
            #
            # Measured on this machine: 3443 anonymous volumes against 12 named ones, 122
            # created on a single day of assessment runs, 15.4 GB. It is unbounded growth on
            # any long-running installation, and it is invisible: nothing fails, docker just
            # gets slower. `-v` removes ONLY anonymous volumes, so a named volume an
            # operator mounted is untouched.
            code, _, _ = await docker("rm", "-f", "-v", *names.split(), check=False)
            if code:
                return False
        _, networks, _ = await docker("network", "ls", "-q", "--filter", f"label={OWNER}")
        for network in networks.split():
            code, _, _ = await docker("network", "rm", network, check=False)
            if code:
                return False
        # A successful CLI invocation is insufficient if any scanner still exists.
        _, remaining, _ = await docker("ps", "-aq", "--filter", f"label={OWNER}", timeout=10)
        if remaining.split():
            return False
        for directory, manifest in abandoned:
            context = manifest.get("assessment_context")
            if context:
                # Credentials are already present in the private policy file; the
                # manifest contains only IDs, never another copy of those secrets.
                from . import persistence as db
                policy_path = directory / "policy" / "policy.json"
                policy = json.loads(policy_path.read_text()) if policy_path.exists() else {}
                known = secret_values(policy.get("identity") or {})
                for base in (directory / "output", directory / "audit"):
                    for path in sorted(base.rglob("*")):
                        if path.is_file() and not path.is_symlink():
                            kind = "recovered-requests" if path.name == "requests.jsonl" else "recovered-" + path.name
                            await db.evidence(context["session_id"], context["stage_id"], kind,
                                              path.read_text(errors="replace"), known)
                await db.evidence(context["session_id"], context["stage_id"], "recovery",
                                  json.dumps({"reason": "Orchestrator interrupted; scanner stopped without replay",
                                              "images": manifest.get("images", {})}))
            # Discard credential-bearing inputs only after scanners are gone and
            # available redacted evidence has been preserved successfully.
            shutil.rmtree(directory)
    except (OSError, RuntimeError, ValueError, KeyError, asyncio.TimeoutError):
        return False
    return True


@dataclass
class JobOutput:
    code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class Sandbox:
    def __init__(self, config: AssessmentConfig, identity=None, *, services=None, operation_routes=None, publish=False, control_urls=None):
        self.config = config
        self.identity = identity
        self.key = uuid.uuid4().hex
        self.network = f"erlik-int-{self.key}"
        self.proxy = f"erlik-proxy-{self.key}"
        self.jobs = set()
        self.images = {}
        self.directory = runtime_root() / "jobs" / self.key
        self.input = self.directory / "input"
        self.output = self.directory / "output"
        self.proxy_url = ""
        self.local_proxy = ""
        self.publish = publish
        self.on_close = None
        self.assessment_context = None
        self.policy = {
            "scope": config.scope.model_dump(), "identity": identity,
            "state_changing": config.state_changing, "excluded_paths": config.excluded_paths,
            "operation_routes": operation_routes or [], "requests_per_second": config.budget.requests_per_second,
            "concurrency": config.budget.concurrency,
            "max_requests": int(config.budget.stage_seconds * config.budget.requests_per_second),
            "max_urls": config.max_urls,
            "service_only": services is not None, "services": services or [],
            # Applied to every arm by the proxy, this sandbox's identity or its absence
            # notwithstanding. See contracts.ApplicationCookie.
            "application_cookies": [c.model_dump() for c in config.application_cookies],
            # ERLIK'S OWN CONTROL TRAFFIC, exempt from the URL budget. `max_urls` bounds how
            # much of the TARGET an assessment explores; a liveness probe of one declared,
            # already scope-checked URL is not exploration. Measured: with max_urls=60 a
            # katana crawl of Juice Shop consumed the budget and the CLOSING liveness check
            # became the 61st distinct URL, so it was refused and the stage was recorded as
            # an expired credential — halting the whole assessment. Still scope-checked,
            # still counted against max_requests; only the distinct-URL ceiling ignores them.
            "control_urls": sorted(control_urls or []),
        }

    # Extracted so it can be tested without a daemon. The failure it guards
    # against is invisible on macOS and only reachable through the `docker` CI
    # job, which is the worst possible place to find out.
    def _prepare_directories(self):
        """Create the bind-mount directories with modes the containers can use."""
        for path in (self.input, self.output, self.directory / "policy", self.directory / "audit"):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        # EVERY BIND MOUNT HAS TO BE REACHABLE BY A CAPABILITY-LESS ROOT.
        #
        # These containers run as root and with `--cap-drop=ALL`, which takes
        # CAP_DAC_OVERRIDE with it -- so root does NOT bypass the permission bits, and
        # a 0700 directory or a 0600 file written by the host user is simply refused.
        # `output` already carried this treatment; `policy`, `audit` and `input` were
        # missed, and the whole lane died at startup on a Linux host:
        #
        #     PermissionError: [Errno 13] Permission denied: '/policy/policy.json'
        #     RuntimeError: egress proxy did not become ready
        #
        # It has never failed on a developer machine and it never will: Docker Desktop
        # and OrbStack map bind-mount ownership to the container user, so the bits do
        # not bite on macOS. Reproduced on a Linux filesystem (a named volume) instead
        # -- root with default caps reads the file, root with --cap-drop=ALL does not.
        #
        # This costs nothing on the host. The privacy boundary is `runtime_root()`,
        # which is created 0700 and re-chmodded 0700 on every call; these directories
        # live under it, so widening them changes who can reach them by exactly
        # nothing. The bind mount is of the directory itself, so its own mode is all
        # the container ever sees.
        self.output.chmod(0o777)     # written by scanners
        (self.directory / "audit").chmod(0o777)   # written by the proxy
        (self.directory / "policy").chmod(0o755)  # read by the proxy
        self.input.chmod(0o711)      # traversable; the files carry their own 0644

    async def __aenter__(self):
        self._prepare_directories()
        self._write_manifest()
        policy_file = self.directory / "policy" / "policy.json"
        private_write(policy_file, json.dumps(self.policy))
        policy_file.chmod(0o644)
        additional_ca = os.environ.get("ERLIK_INTEGRATION_CA_FILE")
        if additional_ca:
            extra_ca = self.directory / "policy" / "extra-ca.pem"
            private_write(extra_ca, Path(additional_ca).read_bytes())
            extra_ca.chmod(0o644)
        try:
            await docker("network", "create", "--internal", "--label", OWNER, self.network)
            args = ["create", "--name", self.proxy, "--label", OWNER, "--network", self.network,
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=512m", "--pids-limit=128",
                    "-v", f"{self.directory / 'policy'}:/policy:ro", "-v", f"{self.directory / 'audit'}:/audit"]
            if self.publish:
                args += ["-p", "127.0.0.1::8080"]
            args += [IMAGES["proxy"]]
            if additional_ca:
                args += ["--set", "ssl_verify_upstream_trusted_ca=/policy/extra-ca.pem"]
            await docker(*args)
            _, digest, _ = await docker("image", "inspect", IMAGES["proxy"], "--format", "{{.Id}}")
            self.images[IMAGES["proxy"]] = digest.strip()
            # Only the proxy joins an egress network. A lab network may be supplied.
            await docker("network", "connect", os.environ.get("ERLIK_INTEGRATION_EGRESS_NETWORK", "bridge"), self.proxy)
            await docker("start", self.proxy)
            _, ip, _ = await docker("inspect", "--format", '{{range $k,$v := .NetworkSettings.Networks}}{{if eq $k "' + self.network + '"}}{{$v.IPAddress}}{{end}}{{end}}', self.proxy)
            self.proxy_url = f"http://{ip.strip()}:8080"
            # Fail before launching a scanner unless mitmproxy has actually started.
            for _ in range(50):
                code, _, _ = await docker("exec", self.proxy, "python", "-c", "import socket; socket.create_connection(('127.0.0.1',8080),1).close()", check=False, timeout=3)
                if code == 0:
                    break
                await asyncio.sleep(0.1)
            else:
                _, logs, errors = await docker("logs", self.proxy, check=False)
                raise RuntimeError("egress proxy did not become ready: " + (logs + errors)[-2000:])
            await docker("cp", f"{self.proxy}:/tmp/erlik-ca/mitmproxy-ca-cert.pem", str(self.input / "ca.pem"))
            (self.input / "ca.pem").chmod(0o644)
            if self.publish:
                _, port, _ = await docker("port", self.proxy, "8080/tcp")
                self.local_proxy = "http://" + port.strip()
            return self
        except BaseException:
            await self.close()
            shutil.rmtree(self.directory, ignore_errors=True)
            raise

    def write(self, name, value):
        if Path(name).name != name:
            raise ValueError("input must be a filename")
        path = self.input / name
        private_write(path, value if isinstance(value, (str, bytes)) else json.dumps(value))
        # Parent remains private; scanner bind-mount needs read access regardless of UID.
        path.chmod(0o644)
        return "/input/" + name

    def _write_manifest(self):
        temporary = self.directory / ".manifest.tmp"
        private_write(temporary, json.dumps({
            "owner": OWNER, "assessment_context": self.assessment_context,
            "jobs": sorted(self.jobs), "images": self.images}))
        os.replace(temporary, self.directory / "manifest.json")

    async def run(self, argv: list[str], *, image=None, timeout=None, env=None) -> JobOutput:
        name = f"erlik-job-{uuid.uuid4().hex}"
        self.jobs.add(name)
        self._write_manifest()
        args = ["create", "--name", name, "--label", OWNER, "--network", self.network,
                "--dns", "127.0.0.1", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--memory=2g", "--cpus=2", "--pids-limit=512", "--tmpfs", "/tmp:rw,nosuid,size=512m",
                "-v", f"{self.input}:/input:ro", "-v", f"{self.output}:/output",
                "--workdir", "/output"]
        # A SCANNER'S PRIVATE CACHE IS NOT EVIDENCE, and `/output` is harvested as
        # evidence: `adapters.py` rglobs every file under it and opens each one.
        #
        # The worker runs with `--workdir /output`, and Hypothesis (under Schemathesis)
        # keeps its unicode tables in `.hypothesis/` relative to the CWD — so it wrote
        # them into the artifact directory, as root, and the harvest running as the
        # host user was refused:
        #
        #     PermissionError: [Errno 13] Permission denied:
        #     '.../output/.hypothesis/unicode_data/15.0.0/charmap.json.gz'
        #
        # Seven Docker-gated tests failed on that, and none of them is about
        # Hypothesis. Pointing the cache at the container's own tmpfs fixes the
        # ownership problem by removing the file from the shared directory entirely,
        # which is the right answer regardless of who could read it: an artifact set
        # that carries a scanner's cache is one a reader has to sift.
        environment = {"HTTP_PROXY": self.proxy_url, "HTTPS_PROXY": self.proxy_url,
                       "http_proxy": self.proxy_url, "https_proxy": self.proxy_url, "NO_PROXY": "", "no_proxy": "",
                       "SSL_CERT_FILE": "/input/ca.pem", "REQUESTS_CA_BUNDLE": "/input/ca.pem",
                       "HYPOTHESIS_STORAGE_DIRECTORY": "/tmp/hypothesis"}
        environment.update(env or {})
        for key, value in environment.items():
            args += ["-e", f"{key}={value}"]
        args += ["--entrypoint", argv[0], image or IMAGES["worker"], *argv[1:]]
        try:
            await docker(*args)
            _, digest, _ = await docker("image", "inspect", image or IMAGES["worker"], "--format", "{{.Id}}")
            self.images[image or IMAGES["worker"]] = digest.strip()
            self._write_manifest()
            try:
                code, out, err = await docker("start", "-a", name, timeout=timeout or self.config.budget.stage_seconds, check=False)
                _, exit_text, _ = await docker("inspect", "--format", "{{.State.ExitCode}}", name)
                private_write(self.output / f"{name}.stdout", out)
                private_write(self.output / f"{name}.stderr", err)
                return JobOutput(int(exit_text.strip()), out, err)
            except asyncio.TimeoutError:
                await docker("stop", "-t", "1", name, check=False)
                _, out, err = await docker("logs", name, check=False)
                private_write(self.output / f"{name}.stdout", out)
                private_write(self.output / f"{name}.stderr", err)
                return JobOutput(124, out, err, True)
            except asyncio.CancelledError:
                # The attached Docker CLI was interrupted, but the scanner is
                # still alive. Stop it and retain logs before the final removal.
                await asyncio.shield(docker("stop", "-t", "1", name, check=False))
                _, out, err = await asyncio.shield(docker("logs", name, check=False))
                private_write(self.output / f"{name}.stdout", out)
                private_write(self.output / f"{name}.stderr", err)
                raise
        finally:
            # `-v` for the reason given at the reaper above: the proxy image declares a
            # VOLUME and this is the other place containers are removed.
            await asyncio.shield(docker("rm", "-f", "-v", name, check=False))
            self.jobs.discard(name)
            if self.directory.exists():
                self._write_manifest()

    async def close(self):
        for name in [*self.jobs, self.proxy]:
            try:
                # THE MAIN LEAK PATH, and the one worth naming: `self.proxy` is the
                # container whose image declares the volume, and this is where every
                # sandbox removes it. Without `-v` each assessment left one behind.
                await docker("rm", "-f", "-v", name, check=False)
            except (OSError, RuntimeError, asyncio.TimeoutError):
                pass
        try:
            await docker("network", "rm", self.network, check=False)
        except (OSError, RuntimeError, asyncio.TimeoutError):
            pass

    async def __aexit__(self, *exc):
        try:
            await asyncio.shield(self.close())
            if self.on_close:
                await self.on_close(self)
        finally:
            # Caller ingests output before leaving context. No secret-bearing raw files survive.
            shutil.rmtree(self.directory, ignore_errors=True)
