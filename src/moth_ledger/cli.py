"""moth-ledger CLI: verify, show, init."""
from __future__ import annotations

import argparse
import json
import sys

from .hashes import assert_pins
from .ledger import ChainBroken, Ledger


def cmd_init(args: argparse.Namespace) -> int:
    ledger = Ledger(args.ledger)
    ledger.path.touch(exist_ok=True)
    ok, _errors = ledger.verify_chain()
    print(f"initialized {ledger.path} (valid={ok})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    assert_pins()
    ledger = Ledger(args.ledger)
    ok, errors = ledger.verify_chain()
    if ok:
        print(f"OK: {ledger.path} — chain intact, {sum(1 for _ in ledger.rows())} rows")
        return 0
    for err in errors:
        print(f"BROKEN: {err}", file=sys.stderr)
    return 1


def cmd_show(args: argparse.Namespace) -> int:
    ledger = Ledger(args.ledger)
    summary = ledger.summary()
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.kind:
        for row in ledger.rows(args.kind):
            print(json.dumps(row, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="moth-ledger",
        description="MOTH findings as quilt-native receipted cells",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create an empty ledger file")
    p_init.add_argument("ledger")
    p_init.set_defaults(func=cmd_init)

    p_verify = sub.add_parser("verify", help="re-derive every hash from residue")
    p_verify.add_argument("ledger")
    p_verify.set_defaults(func=cmd_verify)

    p_show = sub.add_parser("show", help="summary (+ optional kind dump)")
    p_show.add_argument("ledger")
    p_show.add_argument("--kind", choices=["FINDING/v1", "VERDICT/v1", "REFUSAL/v1"])
    p_show.set_defaults(func=cmd_show)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ChainBroken as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
