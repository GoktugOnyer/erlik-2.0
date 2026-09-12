#!/usr/bin/env python3
"""Record exactly what a release was built and tested against.

E-006 of docs/future-plan.md asks for a "pinned build manifest". The point is
narrow: a benchmark report or an acceptance run means nothing six months later
unless the images and tool versions behind it can be named. Every measurement
doc in docs/measurements/ opens with a version table for the same reason, and
those were assembled by hand.

Records only what is already public about the build — image digests, tool
versions, the commit. It reads no configuration, contacts no service, and never
touches data/ or an evidence store.

    release_manifest.py [--out build-manifest.json] [--also-image REF ...]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*argv: str) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable: {type(exc).__name__}"
    if done.returncode != 0:
        return "unavailable"
    # STDERR IS NOT A FAILURE HERE. katana, nuclei and interactsh-client print
    # their version banner to stderr and exit 0, so reading stdout alone
    # reported three present tools as "unavailable" — a manifest asserting a
    # build lacked what it in fact had.
    return (done.stdout.strip() or done.stderr.strip() or "no output")


_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VERSION = re.compile(r"v?\d+\.\d+(\.\d+)?")


def _version_line(text: str) -> str:
    """The line carrying the version, without the logo.

    katana, nuclei and interactsh-client open with multi-line ASCII art and ANSI
    colour. Taking the first non-empty line recorded a row of underscores as a
    tool version, which is worse than recording nothing: it looks like data.
    """
    for line in _ANSI.sub("", text).splitlines():
        line = line.strip()
        if line and _VERSION.search(line):
            return line
    return "unavailable"


def image(reference: str) -> dict:
    """An image's identity, or an explicit statement that it is absent.

    Absent is a real answer: a manifest that silently omits an image it could
    not find would let a release claim it was built against something it never
    had.
    """
    digest = _run("docker", "image", "inspect", "--format", "{{.Id}}", reference)
    repo_digests = _run("docker", "image", "inspect",
                        "--format", "{{join .RepoDigests \",\"}}", reference)
    created = _run("docker", "image", "inspect", "--format", "{{.Created}}", reference)
    return {"reference": reference, "id": digest, "repo_digests": repo_digests,
            "created": created, "present": digest not in ("", "unavailable")}


def worker_tools() -> dict:
    """Versions of the tools INSIDE the worker image, not on the host.

    The host's curl is not the one that issues a probe, and a manifest naming it
    would describe a machine that took no part in the assessment.
    """
    from orchestrator.integrations.runtime import IMAGES

    worker = IMAGES["worker"]
    out = {}
    for tool, argv in (("curl", ["curl", "--version"]),
                       ("katana", ["katana", "-version"]),
                       ("interactsh-client", ["interactsh-client", "-version"]),
                       ("nuclei", ["nuclei", "-version"]),
                       ("python", ["python", "--version"])):
        text = _run("docker", "run", "--rm", "--entrypoint", argv[0], worker, *argv[1:])
        out[tool] = _version_line(text)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="build-manifest.json")
    parser.add_argument("--skip-tools", action="store_true",
                        help="skip the in-image tool probe, which starts containers")
    # A JOB CAN TEST AGAINST AN IMAGE THE LANE DOES NOT SHIP. The real-Interactsh
    # acceptance runs against `erlik-interactsh-lab:1`, which is a fixture rather than a
    # lane image and so is absent from `IMAGES` — a manifest for that job without it names
    # every image except the one the acceptance was measured against.
    #
    # Recorded under its own key, NOT merged into `images`. A fixture server and a shipped
    # lane image are different claims, `images_missing` is read as "this build is
    # incomplete", and a reader who cannot tell which is which has a manifest that is worse
    # than a short one.
    parser.add_argument("--also-image", action="append", default=[], metavar="REF",
                        help="also record this image, as a test fixture rather than a lane image")
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT))
    from orchestrator.integrations.runtime import IMAGES

    manifest = {
        "commit": _run("git", "-C", str(ROOT), "rev-parse", "HEAD"),
        "commit_describe": _run("git", "-C", str(ROOT), "describe", "--always", "--dirty"),
        "python": sys.version.split()[0],
        "images": {role: image(reference) for role, reference in IMAGES.items()},
        "worker_tools": {} if args.skip_tools else worker_tools(),
        "fixture_images": {reference: image(reference) for reference in args.also_image},
    }
    missing = sorted(role for role, info in manifest["images"].items() if not info["present"])
    manifest["images_missing"] = missing
    absent_fixtures = sorted(reference for reference, info in manifest["fixture_images"].items()
                             if not info["present"])
    manifest["fixture_images_missing"] = absent_fixtures
    Path(args.out).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.out}: commit {manifest['commit_describe']}, "
          f"{len(manifest['images']) - len(missing)}/{len(manifest['images'])} images present")
    if missing:
        print("  images not on this host:", ", ".join(missing))
    if absent_fixtures:
        # NOT a failure: the caller asked for a record, and "absent" is the record. The
        # suite that needed the fixture has its own junit guard, which is the layer that
        # should fail when an acceptance run did not happen.
        print("  fixture images not on this host:", ", ".join(absent_fixtures))
    return 0


if __name__ == "__main__":
    sys.exit(main())
