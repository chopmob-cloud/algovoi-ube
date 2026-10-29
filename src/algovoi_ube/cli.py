"""Command line for the NTI-1 conformance harness.

    algovoi-ube selftest        prove the harness itself is correct
    algovoi-ube verify FILE     verify a stored audit chain
    algovoi-ube keystone        what the AlgoVoi Keystone covers, and what it does not
    algovoi-ube target URL      probe a live implementation
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .chain import verify_chain
from .keystone_mapping import FLOW, coverage, report as keystone_report


def _load(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "events" in data:
        data = data["events"]
    if not isinstance(data, list):
        raise SystemExit(f"{path} does not contain a list of events")
    return data


def cmd_verify(args: argparse.Namespace) -> int:
    events = _load(args.file)
    status = verify_chain(events)
    print(status.summary())
    if not status.ok:
        for reason in status.reasons:
            print(f"  {reason}")
        return 1
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    from . import runner

    return runner.main(["--self-test"])


def cmd_keystone(args: argparse.Namespace) -> int:
    print(keystone_report())
    print()
    print("Process flow, step by step:")
    for step in FLOW:
        print(f"  {step.name:11s} -> {step.produces}")
        print(f"              {step.keystone_call}")
    stats = coverage()
    if args.gaps_only:
        print()
        print("Gaps:")
        for gap in stats["gaps"]:
            print(f"  - {gap}")
    return 0


def cmd_target(args: argparse.Namespace) -> int:
    from . import runner

    return runner.probe_target(args.url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="algovoi-ube", description="NTI-1 conformance harness"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify an audit chain from a JSON file")
    p_verify.add_argument("file")
    p_verify.set_defaults(func=cmd_verify)

    p_self = sub.add_parser("selftest", help="prove the harness itself is correct")
    p_self.set_defaults(func=cmd_selftest)

    p_key = sub.add_parser("keystone", help="Keystone coverage against NTI-1")
    p_key.add_argument("--gaps-only", action="store_true")
    p_key.set_defaults(func=cmd_keystone)

    p_target = sub.add_parser("target", help="probe a live implementation")
    p_target.add_argument("url")
    p_target.set_defaults(func=cmd_target)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
