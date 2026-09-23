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


def cmd_balance(args: argparse.Namespace) -> int:
    """Trial-balance a round: audit the books, close only if they balance."""
    from .schema import make_producer
    from .trial_balance import TrialImbalance, book_round, close_round, verify_close
    ledger = Ledger(args.ledger)
    expectations = [e.strip() for e in args.expectations.split(",") if e.strip()]
    if args.close:
        try:
            row = close_round(
                ledger, make_producer(args.tool, args.version),
                args.occurred_at, round_id=args.round_id,
                expectations=expectations,
            )
        except TrialImbalance as exc:
            for v in exc.args[0]:
                print(f"IMBALANCED: {v}", file=sys.stderr)
            return 2
        print(json.dumps({"closed": row["round_id"], "id": row["id"]}, sort_keys=True))
        return 0
    books = book_round(list(ledger.rows()), expectations)
    for v in books["violations"]:
        print(f"IMBALANCED: {v}", file=sys.stderr)
    print(json.dumps(books["closes"], indent=2, sort_keys=True))
    if args.verify_close_id:
        rows = {r["id"]: r for r in ledger.rows("ROUND_CLOSE/v1")}
        ok, errors = verify_close(ledger, rows[args.verify_close_id])
        for e in errors:
            print(f"BROKEN: {e}", file=sys.stderr)
        return 0 if ok else 1
    return 0 if not books["violations"] else 2


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
    p_show.add_argument("--kind", choices=["FINDING/v1", "VERDICT/v1", "REFUSAL/v1", "ROUND_CLOSE/v1"])
    p_show.set_defaults(func=cmd_show)

    p_bal = sub.add_parser("balance", help="trial-balance a round (audit or close)")
    p_bal.add_argument("ledger")
    p_bal.add_argument("--expectations", required=True,
                       help="comma-separated expectation ids to account")
    p_bal.add_argument("--close", action="store_true",
                       help="append ROUND_CLOSE/v1 iff the books balance")
    p_bal.add_argument("--round-id", default="round")
    p_bal.add_argument("--tool", default="moth-ledger")
    p_bal.add_argument("--version", default="0.2.0")
    p_bal.add_argument("--occurred-at", default="2026-09-23T00:00:00Z")
    p_bal.add_argument("--verify-close-id", default=None,
                       help="re-derive a close row from the rows beneath it")
    p_bal.set_defaults(func=cmd_balance)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ChainBroken as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
