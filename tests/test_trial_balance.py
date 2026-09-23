"""Trial balance: every account closes exactly once (Pacioli canary).

Canary semantics (scout pick): CAUGHT debit / MISSED credit / REFUSED
credit — imbalance at round close IS the gamed-evaluator signal. The
honest close and the honest miss cost the same ink; a book that will
not balance was a choice.
"""
import pytest

from moth_ledger import (
    GENESIS,
    Ledger,
    Q16,
    SchemaError,
    TrialImbalance,
    book_round,
    close_round,
    make_producer,
    make_refusal,
    make_round_close,
    canonical_dumps,
    fnv1a_64_hex,
    row_digest,
    sha256_hex,
    verify_close,
)

PRODUCER = make_producer("moth-honest", "0.1.0")
NOW = "2026-09-23T05:30:00Z"
REPRO = sha256_hex(b"repro bytes")
EXP = ["exp_alpha", "exp_beta", "exp_gamma"]


def _catch(ledger, exp, commit="abc1234"):
    row = ledger.append_finding(
        PRODUCER, NOW, target_repo="SuperInstance/demo",
        target_commit=commit, surface_id="src/p.c:10", cwe="CWE-787",
        severity=Q16.from_float(0.75), repro_hash=REPRO,
        extra={"expectation_id": exp},
    )
    ledger.append_verdict(
        PRODUCER, NOW, finding_id=row["id"], verdict="CONFIRMED",
    )
    return row


def _credit(ledger, exp, mode, reason):
    return ledger.append_refusal(
        PRODUCER, NOW, reason=reason,
        extra={"expectation_id": exp, "close": mode},
    )


def _balanced_ledger(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _catch(ledger, "exp_alpha")
    _credit(ledger, "exp_beta", "MISSED", "hunter walked past the surface")
    _credit(ledger, "exp_gamma", "REFUSED", "evidence below the declared floor")
    return ledger


def test_balanced_round_closes_once(tmp_path):
    ledger = _balanced_ledger(tmp_path)
    row = close_round(ledger, PRODUCER, NOW,
                      round_id="round-1", expectations=EXP)
    assert row["kind"] == "ROUND_CLOSE/v1"
    by_exp = {c["expectation_id"]: c["close"] for c in row["closes"]}
    assert by_exp == {"exp_alpha": "CAUGHT", "exp_beta": "MISSED",
                      "exp_gamma": "REFUSED"}
    ok, errors = ledger.verify_chain()
    assert ok, errors


def test_unclosed_expectation_refuses_close(tmp_path):
    ledger = _balanced_ledger(tmp_path)
    ledger.append_finding(
        PRODUCER, NOW, target_repo="SuperInstance/demo",
        target_commit="ddd4444", surface_id="src/q.c:3", cwe="CWE-79",
        severity=Q16.from_float(0.5), repro_hash=REPRO,
        extra={"expectation_id": "exp_delta"},
    )  # caught but never judged — and exp_delta itself never accounted
    with pytest.raises(TrialImbalance) as exc:
        close_round(ledger, PRODUCER, NOW,
                    round_id="round-1", expectations=EXP + ["exp_delta"])
    assert any("UNCLOSED" in v for v in exc.value.args[0])
    assert not list(ledger.rows("ROUND_CLOSE/v1"))  # nothing was written


def test_pending_finding_is_unclosed_debit(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    ledger.append_finding(
        PRODUCER, NOW, target_repo="SuperInstance/demo",
        target_commit="eee5555", surface_id="src/r.c:7", cwe="CWE-787",
        severity=Q16.from_float(0.75), repro_hash=REPRO,
        extra={"expectation_id": "exp_alpha"},
    )  # no verdict — claimed, not confirmed
    books = book_round(list(ledger.rows()), EXP)
    assert any("UNCLOSED_DEBIT" in v for v in books["violations"])


def test_double_close_caught(tmp_path):
    ledger = _balanced_ledger(tmp_path)
    _credit(ledger, "exp_beta", "REFUSED", "restraint re-claimed after miss")
    books = book_round(list(ledger.rows()), EXP)
    assert any("DOUBLE_CREDIT" in v and "exp_beta" in v
               for v in books["violations"])


def test_double_debit_caught(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _catch(ledger, "exp_alpha", commit="aaa1111")
    _catch(ledger, "exp_alpha", commit="bbb2222")  # same catch counted twice
    books = book_round(list(ledger.rows()), EXP)
    assert any("DOUBLE_DEBIT" in v for v in books["violations"])


def test_forged_credit_row_breaks_close(tmp_path):
    """The gamed-evaluator seam: the MISSED row rewritten as REFUSED,
    hashes re-chained by a forger who owns the ledger. Chain law alone is
    blind (every hash re-derives); the trial balance is not — the close
    claims MISSED, the residue says REFUSED."""
    ledger = _balanced_ledger(tmp_path)
    close = close_round(ledger, PRODUCER, NOW,
                        round_id="round-1", expectations=EXP)
    rows = list(ledger.rows())
    forged = []
    for r in rows:
        ctx = r.get("context")
        if isinstance(ctx, dict) and ctx.get("close") == "MISSED":
            r = dict(r)
            r["context"] = {"close": "REFUSED",
                            "expectation_id": ctx["expectation_id"]}
        forged.append(r)
    prev = GENESIS
    for i, r in enumerate(forged):
        body = {k: v for k, v in r.items() if k not in ("row_hash", "chain_hash")}
        rh = row_digest(body)
        ch = fnv1a_64_hex(bytes.fromhex(prev) + bytes.fromhex(rh))
        forged[i] = dict(body, row_hash=rh, chain_hash=ch)
        prev = ch
    ledger.path.write_text(
        "".join(canonical_dumps(r).decode("utf-8") + "\n" for r in forged),
        encoding="utf-8",
    )
    # chain law passes: the forger re-chained everything correctly...
    ok, _ = ledger.verify_chain()
    assert ok
    # ...but the close no longer matches its residue
    ok, errors = verify_close(ledger, close)
    assert not ok
    assert any("exp_beta" in e for e in errors)


def test_double_close_row_refused_by_verify(tmp_path):
    ledger = _balanced_ledger(tmp_path)
    first = close_round(ledger, PRODUCER, NOW,
                        round_id="round-1", expectations=EXP)
    ledger.append(make_round_close(
        PRODUCER, NOW, round_id="round-1",
        closes=[{"expectation_id": e, "close": "CAUGHT",
                 "debits": 1, "credits": 1} for e in EXP],
    ))  # forged second close, same round
    ok, errors = verify_close(ledger, first)
    assert not ok
    assert any("closed twice" in e for e in errors)


def test_close_schema_rejects_bad_modes(tmp_path):
    with pytest.raises(SchemaError):
        make_round_close(PRODUCER, NOW, round_id="r",
                         closes=[{"expectation_id": "e", "close": "WON"}])


def test_empty_expectations_refused(tmp_path):
    ledger = _balanced_ledger(tmp_path)
    with pytest.raises(TrialImbalance):
        close_round(ledger, PRODUCER, NOW, round_id="round-1", expectations=[])
