"""moth-ledger v2 envelopes: seal a mixed v1+v2 campaign and verify it."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from moth_ledger.ledger import Ledger
from moth_ledger.q16 import Q16
from moth_ledger.schema import make_producer

NOW = "2026-09-23T06:00:00Z"
REPRO = "cd" * 32

FIELDS = dict(target_repo="SuperInstance/demo", target_commit="e95c786",
              surface_id="src/route.c::route", cwe="CWE-306",
              severity=Q16(32768), repro_hash=REPRO)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="moth-ledger-v2-demo-"))
    ledger = Ledger(tmp / "campaign.jsonl")
    cells = make_producer("moth-cells", "0.1.0")
    runner = make_producer("moth-runner", "0.1.0")

    f1 = ledger.append_finding(cells, NOW, **FIELDS)                       # v1
    f2 = ledger.append_finding_v2(cells, NOW, genome_hash="ef" * 8,
                                  dice_seed=0xB1,
                                  walk={"ticks": 30,
                                          "terrain_hash": "aa" * 16},
                                  **FIELDS)                                # v2
    ledger.append_verdict(runner, NOW, finding_id=f2["id"], verdict="CONFIRMED")
    ledger.append_refusal(cells, NOW, reason="budget_exhausted")           # v1
    ledger.append_refusal_v2(cells, NOW, polarity="positive",
                             exercise_id="route", reason="decoy_resisted")  # v2

    ok, errors = ledger.verify_chain()
    assert ok, errors
    print(json.dumps({
        "demo_ledger": str(ledger.path),
        "summary": ledger.summary(),
        "positive_refusals": sum(1 for _ in ledger.positive_refusals()),
        "status_of_v2_finding": ledger.status_of(f2["id"]),
        "v1_finding_kind": f1["kind"], "v2_finding_kind": f2["kind"],
        "chain": "verified",
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
