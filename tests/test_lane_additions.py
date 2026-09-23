"""Lane additions: signatures, causality edges, Merkle membership."""
import pytest

from moth_ledger import signatures
from moth_ledger.hashes import assert_pins
from moth_ledger.ledger import Ledger
from moth_ledger.merkle import inclusion_proof, merkle_root, verify_proof
from moth_ledger.q16 import Q16
from moth_ledger.schema import make_producer

PROD = {"tool": "lane-test", "version": "0.1"}
NOW = "2026-09-24T04:20:00Z"
REPRO = "a" * 64


def _finding_kwargs():
    return dict(target_repo="o/r", target_commit="b" * 40, surface_id="s1",
                cwe="CWE-20", severity=Q16.from_parts(1, 2), repro_hash=REPRO)


def test_mac_sign_and_verify():
    signer = signatures.KeyedMacSigner(b"lane-key")
    ledger = Ledger("/tmp/lane-mac.jsonl")
    row = ledger.append_finding(PROD, NOW, **_finding_kwargs())
    signed = signatures.sign_row(row, signer)
    assert signed["sig_backend"] == "hmac-sha256-demo"  # confession stays visible
    assert signatures.verify_row_sig(signed, signer)
    tampered = dict(signed)
    tampered["cwe"] = "CWE-79"
    assert not signatures.verify_row_sig(tampered, signer)


def test_mac_fails_with_wrong_key():
    row = signatures.KeyedMacSigner(b"k1").sign(
        {"kind": "FINDING/v1", "id": "f_1"})
    assert not signatures.KeyedMacSigner(b"k2").verify(row)


def test_bytes_law_still_pins():
    assert_pins()  # lane changes must not disturb the port vectors


# ------------------------------------------------------------- causality
def test_causes_edges_and_descendants():
    ledger = Ledger("/tmp/lane-cause.jsonl")
    f = ledger.append_finding(PROD, NOW, **_finding_kwargs())
    v1 = ledger.append_verdict(PROD, NOW, finding_id=f["id"], verdict="CONFIRMED")
    # v2 overturns v1 AND cites the finding as cause
    v2 = ledger.append_verdict(PROD, NOW, finding_id=f["id"], verdict="REFUTED",
                               causes=[v1["id"], f["id"]])
    assert ledger.causes_of(v2["id"]) == [v1["id"], f["id"]]
    desc_f = ledger.descendants(f["id"])
    assert v2["id"] in desc_f
    assert ledger.descendants(v1["id"]) == [v2["id"]]
    assert ledger.verify_chain()[0]


def test_causes_validation():
    from moth_ledger.schema import make_verdict, SchemaError
    with pytest.raises(SchemaError):
        make_verdict(PROD, NOW, finding_id="f_1", verdict="PENDING", causes=[])


# ------------------------------------------------------------- merkle
def test_merkle_membership_proofs():
    ledger = Ledger("/tmp/lane-merkle.jsonl")
    hashes = []
    for i in range(9):
        row = ledger.append_finding(PROD, NOW, **_finding_kwargs())
        hashes.append(row["row_hash"])
    root = merkle_root(hashes)
    for i, h in enumerate(hashes):
        proof = inclusion_proof(hashes, i)
        assert verify_proof(h, proof, root)
    assert not verify_proof("0" * 16, inclusion_proof(hashes, 0), root)


def test_merkle_empty_and_deterministic():
    assert merkle_root([]) == merkle_root([])
    ledger = Ledger("/tmp/lane-merkle2.jsonl")
    r = ledger.append_finding(PROD, NOW, **_finding_kwargs())
    assert merkle_root([r["row_hash"]]) == merkle_root([r["row_hash"]])
    with pytest.raises(IndexError):
        inclusion_proof([], 0)
