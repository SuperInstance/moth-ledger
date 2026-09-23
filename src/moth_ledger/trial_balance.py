"""Trial balance — Pacioli's discipline applied to an evaluation round.

Every round of planted ground truth is a set of accounts, and every
account must close EXACTLY ONCE:

    debit   = a FINDING row naming the expectation (a catch claim)
    credit  = the CONFIRMED verdict on that finding, closing the pair
              — or, when nothing was caught, exactly one credit row:
                MISSED   (the books admit the miss) or
                REFUSED  (the hunter claims restraint, refusal preserved)

An account that closes zero times (UNCLOSED), twice (DOUBLE_CREDIT /
DOUBLE_DEBIT), or carries a debit with no confirming credit
(UNCLOSED_DEBIT) is an imbalanced book. A balanced book gets one
ROUND_CLOSE/v1 row — hash-chained like everything else, so a close that
lies about its round is itself a receipted, re-derivable lie. Imbalance
at round close IS the gamed-evaluator signal: the honest close and the
honest miss cost the same ink, so anything the books refuse to balance
was a choice.

Matching convention: rows bind an expectation through
context.expectation_id (findings) / context.close = MISSED|REFUSED with
context.expectation_id (credit rows). Rows without the binding belong
to no account and are ignored here — the trial balance only audits what
the round claims to be auditing.
"""
from __future__ import annotations

from typing import Any

from .canonical import canonical_equal
from .ledger import Ledger, LedgerError
from .schema import make_round_close


class TrialImbalance(LedgerError):
    """The books do not balance; carries the list of violations."""


def _expectation_id(row: dict) -> str | None:
    ctx = row.get("context")
    if isinstance(ctx, dict):
        exp = ctx.get("expectation_id")
        if isinstance(exp, str) and exp:
            return exp
    return None


def book_round(rows: list[dict], expectations: list[str]) -> dict:
    """Account every expectation from the raw row list.

    Returns {"closes": [...], "violations": [...]}. closes is the
    per-expectation table (CAUGHT / MISSED / REFUSED, with debit and
    credit counts); violations is empty iff the round balances.
    """
    closes: list[dict] = []
    violations: list[str] = []
    for exp in expectations:
        findings = [
            r for r in rows
            if r.get("kind") == "FINDING/v1" and _expectation_id(r) == exp
        ]
        verdicts = [
            r for r in rows
            if r.get("kind") == "VERDICT/v1"
            and r.get("finding_id") in {f["id"] for f in findings}
        ]
        credits = [
            r for r in rows
            if r.get("kind") == "REFUSAL/v1" and _expectation_id(r) == exp
            and isinstance(r.get("context"), dict)
            and r["context"].get("close") in ("MISSED", "REFUSED")
        ]
        debits = len(findings)
        n_credits = len(credits)
        confirmed = [v for v in verdicts if v.get("verdict") == "CONFIRMED"]

        if debits == 0 and n_credits == 0:
            violations.append(f"expectation {exp}: UNCLOSED — no catch, no credit row")
            closes.append({"expectation_id": exp, "close": "MISSED",
                           "debits": 0, "credits": 0, "violations": ["UNCLOSED"]})
            continue
        if debits > 1:
            violations.append(f"expectation {exp}: DOUBLE_DEBIT — {debits} findings")
        if n_credits > 1:
            modes = sorted({c["context"].get("close") for c in credits})
            violations.append(
                f"expectation {exp}: DOUBLE_CREDIT — {n_credits} credit rows {modes}"
            )
        if debits == 1 and not confirmed:
            violations.append(
                f"expectation {exp}: UNCLOSED_DEBIT — finding without CONFIRMED verdict"
            )
        if debits == 0 and n_credits == 1:
            close = credits[0]["context"]["close"]
        else:
            close = "CAUGHT"
        entry: dict[str, Any] = {
            "expectation_id": exp,
            "close": close,
            "debits": debits,
            "credits": n_credits,
        }
        if debits == 1 and confirmed:
            entry["confirmed_by"] = confirmed[-1]["id"]
        closes.append(entry)
    return {"closes": closes, "violations": violations}


def close_round(ledger: Ledger, producer: dict, occurred_at: str, *,
                round_id: str, expectations: list[str]) -> dict:
    """Book the round's trial balance; append ROUND_CLOSE/v1 iff balanced.

    Raises TrialImbalance (writing nothing) when the books don't balance —
    an imbalanced close is never receipted as if it were honest.
    """
    if not expectations:
        raise TrialImbalance(["no expectations given — nothing to close"])
    books = book_round(list(ledger.rows()), expectations)
    if books["violations"]:
        raise TrialImbalance(books["violations"])
    return ledger.append(make_round_close(
        producer, occurred_at, round_id=round_id, closes=books["closes"],
    ))


def verify_close(ledger: Ledger, close_row: dict) -> tuple[bool, list[str]]:
    """Re-derive the balance under a ROUND_CLOSE row from rows beneath it.

    The close row is a CLAIM; the rows before it are the residue. Tamper
    with (or insert/delete) any accounted row and re-derivation disagrees
    with what was booked. Returns (ok, errors).
    """
    errors: list[str] = []
    if close_row.get("kind") != "ROUND_CLOSE/v1":
        return False, ["not a ROUND_CLOSE/v1 row"]
    rows = list(ledger.rows())
    try:
        idx = next(i for i, r in enumerate(rows) if r.get("id") == close_row["id"])
    except StopIteration:
        return False, ["close row not present in ledger"]
    expectations = [c["expectation_id"] for c in close_row["closes"]]
    derived = book_round(rows[:idx], expectations)
    booked_by_exp = {c["expectation_id"]: c for c in close_row["closes"]}
    for entry in derived["closes"]:
        booked = booked_by_exp[entry["expectation_id"]]
        if not canonical_equal(
            {k: entry[k] for k in ("expectation_id", "close", "debits", "credits")},
            {k: booked[k] for k in ("expectation_id", "close", "debits", "credits")},
        ):
            errors.append(
                f"expectation {entry['expectation_id']}: booked "
                f"{booked} but rows re-derive {entry}"
            )
    for err in derived["violations"]:
        errors.append(f"re-derived violation: {err}")
    for later in rows[idx + 1:]:
        if later.get("kind") == "ROUND_CLOSE/v1" \
                and later.get("round_id") == close_row.get("round_id"):
            errors.append(
                f"round {close_row['round_id']} closed twice "
                f"(rows {close_row['id']} and {later['id']})"
            )
    return not errors, errors
