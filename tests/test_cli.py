"""CLI roundtrip: init, verify, show."""
from moth_ledger import Q16, Ledger, make_producer, sha256_hex
from moth_ledger.cli import main

PRODUCER = make_producer("moth-runner", "0.1.0")
NOW = "2026-09-23T04:30:00Z"
REPRO = sha256_hex(b"evidence")


def test_init_verify_show(tmp_path, capsys):
    path = str(tmp_path / "l.jsonl")
    assert main(["init", path]) == 0
    ledger = Ledger(path)
    ledger.append_finding(
        PRODUCER, NOW, target_repo="SuperInstance/demo",
        target_commit="abc1234", surface_id="s:1", cwe="CWE-787",
        severity=Q16.from_float(0.5), repro_hash=REPRO,
    )
    assert main(["verify", path]) == 0
    assert main(["show", path]) == 0
    out = capsys.readouterr().out
    assert '"FINDING/v1": 1' in out


def test_verify_broken_returns_1(tmp_path, capsys):
    path = tmp_path / "l.jsonl"
    path.write_text('{"kind":"FINDING/v1","garbage":true}\n')
    assert main(["verify", str(path)]) == 1
    err = capsys.readouterr().err
    assert "BROKEN" in err
