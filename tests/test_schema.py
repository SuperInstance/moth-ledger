"""Envelope schema validation."""
import pytest

from moth_ledger import (
    Q16,
    SchemaError,
    make_finding,
    make_producer,
    make_refusal,
    make_verdict,
    sha256_hex,
)

PRODUCER = make_producer("moth-runner", "0.1.0")
NOW = "2026-09-23T04:30:00Z"
REPRO = sha256_hex(b"repro bytes")


def _finding(**over):
    fields = {
        "producer": PRODUCER, "occurred_at": NOW,
        "target_repo": "SuperInstance/moth-ledger", "target_commit": "abc1234",
        "surface_id": "src/x.c:42", "cwe": "CWE-787",
        "severity": Q16.from_float(0.75), "repro_hash": REPRO,
    }
    fields.update(over)
    return make_finding(**fields)


def test_finding_shape():
    f = _finding()
    assert f["kind"] == "FINDING/v1"
    assert f["status"] == "PENDING"
    assert f["target"]["commit"] == "abc1234"
    assert f["severity"] == {"num": "49152", "den": "65536"}


def test_occurred_recorded_split():
    f = _finding(recorded_at="2026-09-23T05:00:00Z")
    assert f["occurred_at"] == NOW
    assert f["recorded_at"] == "2026-09-23T05:00:00Z"


def test_bad_repo_refused():
    with pytest.raises(SchemaError):
        _finding(target_repo="no-slash")


def test_bad_commit_refused():
    with pytest.raises(SchemaError):
        _finding(target_commit="nothex!!")


def test_bad_repro_hash_refused():
    with pytest.raises(SchemaError):
        _finding(repro_hash="deadbeef")


def test_severity_must_be_q16():
    with pytest.raises(SchemaError):
        _finding(severity=0.75)


def test_producer_tool_namespacing():
    with pytest.raises(SchemaError):
        make_producer("BAD TOOL!", "1.0")


def test_verdict_roundtrip():
    v = make_verdict(PRODUCER, NOW, finding_id="f_abc", verdict="CONFIRMED")
    assert v["verdict"] == "CONFIRMED"
    with pytest.raises(SchemaError):
        make_verdict(PRODUCER, NOW, finding_id="f_abc", verdict="MAYBE")


def test_refusal_preserved_shape():
    r = make_refusal(PRODUCER, NOW, reason="budget_exhausted", campaign_id="c1")
    assert r["kind"] == "REFUSAL/v1"
    assert r["reason"] == "budget_exhausted"
