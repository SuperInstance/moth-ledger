"""v2 envelopes: FINDING/v2 (replay binding) + REFUSAL/v2 (polarity)."""
import pytest

from moth_ledger.ledger import Ledger
from moth_ledger.q16 import Q16
from moth_ledger.schema import (
    SchemaError,
    make_finding_v2,
    make_refusal_v2,
    make_producer,
)

PRODUCER = make_producer("moth-cells", "0.1.0")
PRODUCER2 = make_producer("moth-runner", "0.1.0")
NOW = "2026-09-23T06:00:00Z"
REPRO = "ab" * 32

V2_FIELDS = dict(target_repo="SuperInstance/demo", target_commit="e95c786",
                 surface_id="src/parse.c::parse", cwe="CWE-787",
                 severity=Q16(49152), repro_hash=REPRO)


def _ledger(tmp_path):
    return Ledger(tmp_path / "campaign.jsonl")


def test_finding_v2_roundtrip_and_chain(tmp_path):
    lg = _ledger(tmp_path)
    f1 = lg.append_finding(PRODUCER, NOW, **V2_FIELDS)
    f2 = lg.append_finding_v2(PRODUCER, NOW, genome_hash="ab12cd34ef56aa10",
                              dice_seed=0xB1, walk={"ticks": 30,
                                                    "terrain_hash": "ff" * 16},
                              **V2_FIELDS)
    v = lg.append_verdict(PRODUCER2, NOW, finding_id=f2["id"],
                          verdict="CONFIRMED")
    r1 = lg.append_refusal(PRODUCER, NOW, reason="budget_exhausted")
    r2 = lg.append_refusal_v2(PRODUCER, NOW, polarity="positive",
                              exercise_id="parse",
                              reason="decoy_resisted")
    ok, errors = lg.verify_chain()
    assert ok, errors
    assert f1["kind"] == "FINDING/v1" and f2["kind"] == "FINDING/v2"
    assert r1["kind"] == "REFUSAL/v1" and r2["kind"] == "REFUSAL/v2"
    assert lg.status_of(f2["id"]) == "CONFIRMED"


def test_v2_envelope_fields_validated(tmp_path):
    lg = _ledger(tmp_path)
    f = lg.append_finding_v2(PRODUCER, NOW, genome_hash="ab" * 8,
                             dice_seed=1, **V2_FIELDS)
    assert f["genome_hash"] == "ab" * 8
    assert f["walk"]["ticks"] == 30 if "walk" in f else True
    with pytest.raises(SchemaError):
        make_finding_v2(PRODUCER, NOW, genome_hash="not-hex-enough!!",
                        dice_seed=1, **V2_FIELDS)
    with pytest.raises(SchemaError):
        make_finding_v2(PRODUCER, NOW, genome_hash="ab" * 8,
                        dice_seed=-1, **V2_FIELDS)
    with pytest.raises(SchemaError):
        make_finding_v2(PRODUCER, NOW, genome_hash="ab" * 8,
                        dice_seed=True, **V2_FIELDS)  # bool is not an int


def test_refusal_v2_polarity_contract(tmp_path):
    lg = _ledger(tmp_path)
    r = lg.append_refusal_v2(PRODUCER, NOW, polarity="negative",
                             reason="starvation")
    assert r["polarity"] == "negative"
    with pytest.raises(SchemaError):
        make_refusal_v2(PRODUCER, NOW, polarity="sometimes",
                        reason="ambiguous")
    with pytest.raises(SchemaError):
        make_refusal_v2(PRODUCER, NOW, polarity="POSITIVE",
                        reason="wrong case")  # polarity is exact


def test_family_filters_see_lineage(tmp_path):
    lg = _ledger(tmp_path)
    lg.append_finding(PRODUCER, NOW, **V2_FIELDS)
    lg.append_finding_v2(PRODUCER, NOW, genome_hash="cd" * 8, dice_seed=2,
                         **V2_FIELDS)
    lg.append_refusal(PRODUCER, NOW, reason="dormancy")
    lg.append_refusal_v2(PRODUCER, NOW, polarity="positive",
                         reason="window_full")
    assert len(list(lg.findings())) == 1
    assert len(list(lg.findings_v2())) == 1
    assert len(list(lg.findings_all())) == 2
    assert len(list(lg.refusals_all())) == 2
    assert len(list(lg.positive_refusals())) == 1  # restraint only


def test_v1_consumers_untouched(tmp_path):
    """Backward compat: v1 rows and v1 filters behave exactly as before."""
    lg = _ledger(tmp_path)
    f = lg.append_finding(PRODUCER, NOW, **V2_FIELDS)
    r = lg.append_refusal(PRODUCER, NOW, reason="cap_hit")
    ok, errors = lg.verify_chain()
    assert ok, errors
    assert list(lg.findings())[0]["id"] == f["id"]
    assert list(lg.refusals())[0]["reason"] == "cap_hit"
    assert lg.summary()["by_kind"] == {"FINDING/v1": 1, "REFUSAL/v1": 1}
