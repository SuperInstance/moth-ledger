"""The ledger: append-only, hash-chained, refusal-preserving.

Row shape on disk (one canonical JSON object per line):
    { ...envelope + context..., "row_hash": h, "chain_hash": c }

    row_hash  = fnv1a64(canonical(row_without_hashes))
    chain_hash = fnv1a64(prev_chain_hash_bytes || row_hash_bytes)

verify_chain() re-derives every row_hash and chain_hash from residue.
Tampering with any byte of any row breaks verification at that row — the
law the jev-quilt PR #3 caught lie made first-class: verify re-derives
payload hashes from retained residue, it does not trust stored ones.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from .canonical import canonical_dumps
from .hashes import fnv1a_64_hex
from .schema import (
    make_finding,
    make_finding_v2,
    make_refusal,
    make_refusal_v2,
    make_verdict,
    row_digest,
    validate_core,
)

GENESIS = "0" * 16


class LedgerError(ValueError):
    """Raised on ledger invariant violations."""


class ChainBroken(LedgerError):
    """verify_chain found a break; carries row index and reason."""


class Ledger:
    """An append-only receipt chain stored as canonical-JSON lines."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def _read_rows(self) -> list[dict]:
        if not self.path.exists():
            return []
        rows = []
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ChainBroken(lineno - 1, f"invalid json line {lineno}: {exc}") from exc
        return rows

    def _tail_chain(self, rows: list[dict]) -> str:
        return rows[-1]["chain_hash"] if rows else GENESIS

    # ------------------------------------------------------------------
    def append(self, envelope: dict) -> dict:
        """Append a validated envelope; returns the stored row."""
        validate_core(envelope)
        rows = self._read_rows()
        body = {k: v for k, v in envelope.items()}
        row_hash = row_digest(body)
        prev = self._tail_chain(rows)
        chain_hash = fnv1a_64_hex(
            bytes.fromhex(prev) + bytes.fromhex(row_hash)
        )
        stored = dict(body)
        stored["row_hash"] = row_hash
        stored["chain_hash"] = chain_hash
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_dumps(stored).decode("utf-8") + "\n")
        return stored

    # convenience appenders ------------------------------------------------
    def append_finding(self, producer: dict, occurred_at: str, **fields) -> dict:
        return self.append(make_finding(producer, occurred_at, **fields))

    def append_verdict(self, producer: dict, occurred_at: str, **fields) -> dict:
        return self.append(make_verdict(producer, occurred_at, **fields))

    def append_refusal(self, producer: dict, occurred_at: str, **fields) -> dict:
        return self.append(make_refusal(producer, occurred_at, **fields))

    def append_finding_v2(self, producer: dict, occurred_at: str, **fields) -> dict:
        return self.append(make_finding_v2(producer, occurred_at, **fields))

    def append_refusal_v2(self, producer: dict, occurred_at: str, **fields) -> dict:
        return self.append(make_refusal_v2(producer, occurred_at, **fields))

    # ------------------------------------------------------------------
    def verify_chain(self) -> tuple[bool, list[str]]:
        """Re-derive every hash from residue. Returns (ok, errors)."""
        errors: list[str] = []
        rows = self._read_rows()
        prev = GENESIS
        for idx, row in enumerate(rows):
            try:
                row_hash = row.pop("row_hash")
                chain_hash = row.pop("chain_hash")
            except KeyError as exc:
                errors.append(f"row {idx}: missing {exc}")
                break
            expected_row = row_digest(row)
            if row_hash != expected_row:
                errors.append(
                    f"row {idx}: row_hash mismatch — stored {row_hash}, "
                    f"re-derived {expected_row} (payload tampered?)"
                )
            expected_chain = fnv1a_64_hex(bytes.fromhex(prev) + bytes.fromhex(expected_row))
            if chain_hash != expected_chain:
                errors.append(
                    f"row {idx}: chain_hash mismatch — stored {chain_hash}, "
                    f"expected {expected_chain} (row inserted/reordered?)"
                )
            prev = chain_hash
        return (not errors), errors

    def require_valid(self) -> None:
        ok, errors = self.verify_chain()
        if not ok:
            raise ChainBroken(-1, "; ".join(errors))

    # ------------------------------------------------------------------
    def rows(self, kind: str | None = None, *, family: str | None = None) -> Iterator[dict]:
        """family="FINDING" matches FINDING/v1 AND FINDING/v2; kind stays
        exact. Filtering by family is how cross-version consumers (bench,
        runner scoring) see a whole lineage without listing versions."""

        for row in self._read_rows():
            if kind is None and family is None or kind is not None and row.get("kind") == kind or kind is None and family is not None and \
                    str(row.get("kind", "")).split("/")[0] == family:
                yield row

    def findings(self) -> Iterator[dict]:
        return self.rows("FINDING/v1")

    def findings_v2(self) -> Iterator[dict]:
        return self.rows("FINDING/v2")

    def findings_all(self) -> Iterator[dict]:
        return self.rows(family="FINDING")

    def refusals(self) -> Iterator[dict]:
        return self.rows("REFUSAL/v1")

    def refusals_v2(self) -> Iterator[dict]:
        return self.rows("REFUSAL/v2")

    def refusals_all(self) -> Iterator[dict]:
        return self.rows(family="REFUSAL")

    def verdicts(self) -> Iterator[dict]:
        return self.rows("VERDICT/v1")

    def positive_refusals(self) -> Iterator[dict]:
        """Restraint testimony only — the honesty signal the bench gates
        on. Negative refusals (starvation, dormancy) are capacity, not
        honesty; counting them is how a hungry hunter fakes a virtuous one."""
        for row in self.refusals_all():
            if row.get("polarity") == "positive":
                yield row

    def status_of(self, finding_id: str) -> str:
        """Current status = latest verdict on that finding, else its own.
        Matches FINDING/v1 and FINDING/v2 — status is a lineage property,
        not a version property."""
        status = "PENDING"
        for row in self.rows():
            if str(row.get("kind", "")).split("/")[0] == "FINDING" \
                    and row.get("id") == finding_id:
                status = row.get("status", "PENDING")
            elif row.get("kind") == "VERDICT/v1" and row.get("finding_id") == finding_id:
                status = row["verdict"]
        return status

    # ------------------------------------------------------------------
    # Causality graph (lane recs 4+5): the ledger stays the spine; the
    # graph is DERIVED on query — git storage, GitHub experience. Edges
    # come only from explicit `causes` fields; sequence implies nothing.

    def causes_of(self, row_id: str) -> list[str]:
        for row in self.rows():
            if row.get("id") == row_id:
                return list(row.get("causes", []))
        return []

    def descendants(self, row_id: str) -> list[str]:
        """All rows that transitively cite row_id as a cause — impact
        tracing without a graph database."""
        seen: set[str] = set()
        frontier = [row_id]
        while frontier:
            cur = frontier.pop()
            for row in self.rows():
                rid = row.get("id")
                if rid in seen:
                    continue
                if cur in row.get("causes", []):
                    seen.add(rid)
                    frontier.append(rid)
        return sorted(seen)

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for row in self.rows():
            counts[row["kind"]] = counts.get(row["kind"], 0) + 1
        return {
            "path": str(self.path),
            "rows": sum(counts.values()),
            "by_kind": counts,
            "valid": self.verify_chain()[0],
        }
