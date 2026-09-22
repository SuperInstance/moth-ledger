"""Ledger chain semantics: append, verify, roundtrip."""
import json

from moth_ledger import (
    GENESIS,
    Ledger,
    Q16,
    make_producer,
    sha256_hex,
)

PRODUCER = make_producer("moth-runner", "0.1.0")
NOW = "2026-09-23T04:30:00Z"
REPRO = sha256_hex(b"evidence bytes")


def _append_finding(ledger, commit="abc1234", sev=0.75):
    return ledger.append_finding(
        PRODUCER, NOW,
        target_repo="SuperInstance/demo", target_commit=commit,
        surface_id="src/p.c:10", cwe="CWE-787",
        severity=Q16.from_float(sev), repro_hash=REPRO,
    )


def test_empty_ledger_verifies(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    ok, errors = ledger.verify_chain()
    assert ok and errors == []


def test_genesis_chain(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    row = _append_finding(ledger)
    assert row["chain_hash"] != GENESIS
    ok, _ = ledger.verify_chain()
    assert ok


def test_append_and_roundtrip(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _append_finding(ledger, commit="aaaaaaa")
    _append_finding(ledger, commit="bbbbbbb", sev=0.5)
    assert len(list(ledger.findings())) == 2
    ok, errors = ledger.verify_chain()
    assert ok, errors


def test_verdict_updates_status(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    f = _append_finding(ledger)
    assert ledger.status_of(f["id"]) == "PENDING"
    ledger.append_verdict(PRODUCER, NOW, finding_id=f["id"], verdict="CONFIRMED")
    assert ledger.status_of(f["id"]) == "CONFIRMED"
    ok, _ = ledger.verify_chain()
    assert ok


def test_refusal_never_deleted(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    ledger.append_refusal(PRODUCER, NOW, reason="budget_exhausted")
    _append_finding(ledger)
    refusals = list(ledger.refusals())
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "budget_exhausted"
    ok, _ = ledger.verify_chain()
    assert ok


def test_summary(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _append_finding(ledger)
    ledger.append_refusal(PRODUCER, NOW, reason="cap")
    s = ledger.summary()
    assert s["rows"] == 2
    assert s["by_kind"]["FINDING/v1"] == 1
    assert s["by_kind"]["REFUSAL/v1"] == 1
    assert s["valid"] is True


def test_occurred_vs_recorded_preserved(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    row = _append_finding(ledger)
    raw = json.loads((tmp_path / "l.jsonl").read_text().splitlines()[0])
    assert raw["occurred_at"] == NOW
    assert row["recorded_at"] == NOW


def test_producer_context_fields_bound(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _append_finding(ledger)
    raw = json.loads((tmp_path / "l.jsonl").read_text().splitlines()[0])
    assert raw["producer"]["tool"] == "moth-runner"
    assert raw["producer"]["version"] == "0.1.0"
