"""Command-line driver for the v2 test-case runner.

Examples:
    # list catalog
    python -m orchestrator.testcase.cli list

    # run one test case
    python -m orchestrator.testcase.cli run WSTG-INPV-05 \\
        --target url=https://app.example.com/search --target parameter=q \\
        --scope app.example.com --scope '*.example.com' \\
        --provider openai --model gpt-4o

    # walk a chain
    python -m orchestrator.testcase.cli chain WSTG-INPV-05 \\
        --target url=https://app.example.com/search --target parameter=q \\
        --scope app.example.com \\
        --max-depth 3
"""

import argparse
import asyncio
import json
import sys

from orchestrator.database import init_db
from orchestrator.testcase import find_by_id, load_catalog, run_test_case, run_chain
from orchestrator.testcase.persistence import save_run, save_chain


def _parse_target(items: list[str]) -> dict:
    out: dict = {}
    for item in items or []:
        if "=" not in item:
            print(f"--target must be key=value (got {item!r})", file=sys.stderr)
            sys.exit(2)
        k, v = item.split("=", 1)
        out[k] = v
    return out


def _attach_scope(target: dict, hosts: list[str] | None, ports: list[int] | None):
    if hosts:
        target.setdefault("scope", {})
        target["scope"].setdefault("allow_hosts", []).extend(hosts)
    if ports:
        target.setdefault("scope", {})
        target["scope"].setdefault("allow_ports", []).extend(ports)


async def _cmd_list(_args):
    catalog = load_catalog()
    for tc_id in sorted(catalog):
        tc = catalog[tc_id]
        print(f"{tc_id}  [{tc.severity}]  {tc.name}")
        req = tc.target_schema.required
        opt = tc.target_schema.optional
        if req:
            print(f"    required: {', '.join(req)}")
        if opt:
            print(f"    optional: {', '.join(opt)}")


async def _cmd_run(args):
    await init_db()
    tc = find_by_id(args.test_case_id)
    if not tc:
        print(f"test case {args.test_case_id!r} not found", file=sys.stderr)
        sys.exit(2)

    target = _parse_target(args.target)
    _attach_scope(target, args.scope, args.port)

    result = await run_test_case(
        tc, target, provider=args.provider, model=args.model,
        dry_run=args.dry_run,
    )
    if not args.no_save and not args.dry_run:
        run_id = await save_run(result, provider=args.provider, model=args.model)
        print(f"saved as run_id={run_id}")
    print(json.dumps(result.model_dump(), indent=2))


async def _cmd_chain(args):
    await init_db()
    target = _parse_target(args.target)
    _attach_scope(target, args.scope, args.port)

    chain = await run_chain(
        args.root_id, target,
        provider=args.provider, model=args.model,
        max_depth=args.max_depth, max_runs=args.max_runs,
    )
    if not args.no_save:
        ids = await save_chain(chain, provider=args.provider, model=args.model)
        print(f"saved {len(ids['run_ids'])} runs, root={ids['root_run_id']}")
    print(json.dumps(chain.model_dump(), indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="erlik-tc", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List test cases in the catalog")

    def _add_target_args(sp):
        sp.add_argument("--target", action="append", default=[],
                        metavar="KEY=VAL", help="Repeatable: target field, e.g. url=https://x")
        sp.add_argument("--scope", action="append", default=[],
                        help="Repeatable: allowed host (glob OK). REQUIRED for safety.")
        sp.add_argument("--port", action="append", default=[], type=int,
                        help="Repeatable: allowed port. Default: any.")
        sp.add_argument("--provider", choices=["ollama", "openai"], default=None)
        sp.add_argument("--model", default=None)
        sp.add_argument("--no-save", action="store_true", help="Don't persist to DB")
        sp.add_argument("--dry-run", action="store_true",
                        help="Render + scope-check but do not execute. Skips DB save.")

    pr = sub.add_parser("run", help="Run a single test case")
    pr.add_argument("test_case_id")
    _add_target_args(pr)

    pc = sub.add_parser("chain", help="Run a test case and auto-follow its chain")
    pc.add_argument("root_id")
    _add_target_args(pc)
    pc.add_argument("--max-depth", type=int, default=3)
    pc.add_argument("--max-runs", type=int, default=12)

    return p


def main():
    args = build_parser().parse_args()
    handler = {
        "list": _cmd_list,
        "run": _cmd_run,
        "chain": _cmd_chain,
    }[args.cmd]
    asyncio.run(handler(args))


if __name__ == "__main__":
    main()
