"""Tamper-evidence: any byte flip, insertion, or reorder breaks the chain."""
import json

import pytest

from moth_ledger import Q16, ChainBroken, Ledger, make_producer, sha256_hex

PRODUCER = make_producer("moth-runner", "0.1.0")
NOW = "2026-09-23T04:30:00Z"
REPRO = sha256_hex(b"evidence")


def _build(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    ledger.append_finding(
        PRODUCER, NOW, target_repo="SuperInstance/demo",
        target_commit="abc1234", surface_id="s:1", cwe="CWE-787",
        severity=Q16.from_float(0.5), repro_hash=REPRO,
    )
    ledger.append_refusal(PRODUCER, NOW, reason="cap")
    return ledger


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_flip_payload_byte_detected(tmp_path):
    ledger = _build(tmp_path)
    lines = _lines(ledger.path)
    row = json.loads(lines[0])
    row["cwe"] = "CWE-119"  # tamper
    lines[0] = json.dumps(row, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n")
    ok, errors = ledger.verify_chain()
    assert not ok
    assert any("row_hash mismatch" in e for e in errors)


def test_flip_stored_hash_detected(tmp_path):
    ledger = _build(tmp_path)
    lines = _lines(ledger.path)
    row = json.loads(lines[0])
    row["row_hash"] = "0" * 16
    lines[0] = json.dumps(row, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n")
    ok, _errors = ledger.verify_chain()
    assert not ok


def test_inserted_row_detected(tmp_path):
    ledger = _build(tmp_path)
    lines = _lines(ledger.path)
    forged = json.loads(lines[0])
    forged["id"] = "finding_forged"  # attacker copies the original hashes
    lines.insert(1, json.dumps(forged, sort_keys=True))
    ledger.path.write_text("\n".join(lines) + "\n")
    ok, _errors = ledger.verify_chain()
    assert not ok
    # copied hashes fail at the forged row (payload mismatch) and the
    # original row after it (chain mismatch — both honest diagnoses)
    ok, errors = ledger.verify_chain()
    assert not ok
    assert any("row_hash mismatch" in e for e in errors)
    assert any("chain_hash mismatch" in e for e in errors)


def test_reorder_detected(tmp_path):
    ledger = _build(tmp_path)
    lines = _lines(ledger.path)
    lines.reverse()
    ledger.path.write_text("\n".join(lines) + "\n")
    ok, _errors = ledger.verify_chain()
    assert not ok


def test_require_valid_raises(tmp_path):
    ledger = _build(tmp_path)
    raw = ledger.path.read_text()
    ledger.path.write_text(raw.replace("CWE-787", "CWE-119"))
    with pytest.raises(ChainBroken):
        ledger.require_valid()
