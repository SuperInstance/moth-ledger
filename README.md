# moth-ledger

**MOTH findings as quilt-native receipted cells.** The receipt spine of the
[moth family](https://github.com/SuperInstance) — no finding, verdict,
refusal, or gift exists unless it is a cell in this ledger.

MOTH (moth.so) is autonomous AI vulnerability hunting for critical open
source. This repo does not call MOTH. It is the substrate hunts land in:
append-only, hash-chained, canonical-JSON rows that any host can re-verify
without trusting us.

## Why

- **A confirmed finding is a quilt cell or it doesn't exist.** Prose claims
  are not findings; receipted rows are.
- **Refusals are preserved forever.** A hunt that failed is data, never
  deleted, never mutated.
- **Verify re-derives from residue.** `verify_chain()` recomputes every
  hash from the row content — stored hashes are evidence, not truth
  (the law the jev-quilt PR #3 caught lie made first-class).
- **Measured fields are exact.** Severity is ℚ₁₆ (`n/65536`,
  refuse-never-round) — we never round a measurement into existence.

## Envelopes

| kind | meaning |
|------|---------|
| `FINDING/v1` | a hunt claim: target repo/commit/surface, CWE, ℚ₁₆ severity, `repro_hash` binding evidence bytes by sha256 (never copied) |
| `VERDICT/v1` | status transition: CONFIRMED / REFUTED / DUPLICATE / PENDING |
| `REFUSAL/v1` | hunt failure: budget exhausted, tool refused, cap hit |
| `FINDING/v2` | v1 + replay binding: `genome_hash` (16-hex hunter identity), `dice_seed`, optional `walk{ticks,terrain_hash,...}` — a finding you cannot replay is a rumor |
| `REFUSAL/v2` | v1 + `polarity`: `positive` = restraint (had means, refused: decoy_resisted, window_full) — the honesty signal; `negative` = abstention (lacked means: starvation, dormancy) — capacity testimony, not honesty credit |

v2 envelopes are supersets of v1: every v1 field keeps its name and
meaning, `verify_chain` is byte-compatible, and v1 producers are
untouched. Family filters (`findings_all()`, `refusals_all()`,
`positive_refusals()`) see a whole lineage across versions; exact-kind
filters (`findings()`, `refusals()`) are unchanged for v1 consumers.

Every row carries: `schema_version`, `kind`, `id`,
`producer{tool,version}`, `occurred_at` (when the event happened) vs
`recorded_at` (when the row was written), plus `row_hash` and
`chain_hash`.

```
row_hash   = fnv1a64(canonical(row_without_hashes))
chain_hash = fnv1a64(prev_chain_hash_bytes || row_hash_bytes)   # GENESIS = "0"*16
```

Canonical JSON: sorted keys, minimal separators, UTF-8 — the recipe both
independent durability stacks (evintunador's annals family and the 4quilt
family) converged on. Bytes-law pin: fnv1a-64 of the UTF-8 bytes of
`café Δ 日本语`... precisely `café Δ 日本語` → `0x24a555471370b18d`
(integer-equal to the spec's `0x024a555471370b18d`; the canonical string
form is the 64-bit zero-padded one). **Bytes, not characters.**

## Use

```python
from moth_ledger import Ledger, Q16, make_producer, sha256_hex

ledger = Ledger("campaign-2026-09-23.jsonl")
producer = make_producer("moth-runner", "0.1.0")

finding = ledger.append_finding(
    producer, "2026-09-23T04:00:00Z",
    target_repo="SuperInstance/moth-ledger",
    target_commit="abc1234",
    surface_id="src/parse.c:88",
    cwe="CWE-787",
    severity=Q16.from_float(0.75),          # exact; 0.1 would be REFUSED
    repro_hash=sha256_hex(open("repro.c","rb").read()),
)

ledger.append_verdict(producer, "2026-09-23T05:00:00Z",
                      finding_id=finding["id"], verdict="CONFIRMED")

ok, errors = ledger.verify_chain()          # re-derive everything
```

CLI:

```
moth-ledger init campaign.jsonl
moth-ledger verify campaign.jsonl           # exit 1 + BROKEN lines on tamper
moth-ledger show campaign.jsonl [--kind FINDING/v1]
```

## Status — honest

- ✅ Envelope core (FINDING/VERDICT/REFUSAL), ℚ₁₆ floor, bytes-law pins,
  tamper-evident chain, refusal preservation, occurred/recorded split,
  producer (tool, kind) namespacing. 40 tests green.
- ⏳ The MOTH API client is a **seam**, not a coupling: the real endpoint
  is undiscovered (~40 probes failed; docs live behind Casey's onboarding).
  The day it surfaces, an adapter writes rows here. Until then, mock hunts
  are the contract.
- ⏳ `moth-honest` (the evaluator that re-derives MOTH's self-reported
  78.2% at honest cost before any reliance) is the next repo in the
  family — this ledger is row zero of its ground truth.

## Doctrine

Numbers are re-derived, never trusted. Findings are receipted, never
claimed. Refusals are visible. Verification is plural — any host, any
substrate, same bytes.

MIT. Fleet node of the Cocapn Fleet.
