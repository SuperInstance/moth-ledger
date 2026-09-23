"""Envelope schemas for the moth family.

Every finding, verdict, and refusal is a quilt-native cell:
- producer pair (tool, kind) namespacing: producer.tool names WHO made the
  row, kind names WHAT the row is. Storage never interprets content.
- occurred_at vs recorded_at split: when the event happened vs when the
  row was written. Confusing them is how ledgers lie about freshness.
- status lives in the payload; status TRANSITIONS are new rows (VERDICT),
  never mutations. A refusal row is preserved forever — never deleted.

Envelope core is family-owned: schema_version, kind, id, producer,
occurred_at, recorded_at. Producers add context fields (target, cwe,
severity, repro_hash) — but row_hash binds every field present.
"""
from __future__ import annotations

import re
import uuid
from typing import Any

from .canonical import canonical_dumps
from .hashes import fnv1a_64_hex
from .q16 import Q16

SCHEMA_VERSION = "1.0"
VALID_KINDS = ("FINDING/v1", "FINDING/v2", "VERDICT/v1", "VERDICT/v2", "REFUSAL/v1", "REFUSAL/v2", "ROUND_CLOSE/v1")
VALID_VERDICTS = ("CONFIRMED", "REFUTED", "DUPLICATE", "PENDING")
VALID_POLARITY = ("positive", "negative")
CLOSE_MODES = ("CAUGHT", "MISSED", "REFUSED")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


class SchemaError(ValueError):
    """Raised when an envelope violates the family contract."""


def _require_str(obj: dict, key: str, where: str) -> str:
    val = obj.get(key)
    if not isinstance(val, str) or not val:
        raise SchemaError(f"{where}: missing or non-string field '{key}'")
    return val


def _require_iso(obj: dict, key: str, where: str) -> str:
    val = _require_str(obj, key, where)
    # ISO-8601 sanity: YYYY-MM-DD[T ]hh:mm(:ss)? — full Z/offset check left to callers
    if len(val) < 10 or not val[0:4].isdigit() or val[4] != "-":
        raise SchemaError(f"{where}: '{key}' not ISO-8601 shaped: {val!r}")
    return val


def new_id(prefix: str) -> str:
    """Deterministic-shape, unique id: <prefix>_<32hex>."""
    return f"{prefix}_{uuid.uuid4().hex}"


def make_producer(tool: str, version: str) -> dict:
    if not _ID_RE.match(tool):
        raise SchemaError(f"producer.tool invalid: {tool!r}")
    if not version:
        raise SchemaError("producer.version must be non-empty")
    return {"tool": tool, "version": version}


def _base_envelope(kind: str, producer: dict, occurred_at: str,
                   recorded_at: str | None, row_id: str | None) -> dict:
    if kind not in VALID_KINDS:
        raise SchemaError(f"unknown kind: {kind!r}")
    prefix = kind.split("/", 1)[0].lower()
    env = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "id": row_id or new_id(prefix),
        "producer": producer,
        "occurred_at": occurred_at,
        "recorded_at": recorded_at or occurred_at,
    }
    validate_core(env)
    return env


def validate_core(env: dict) -> None:
    where = "envelope core"
    if env.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(f"{where}: schema_version must be {SCHEMA_VERSION}")
    if env.get("kind") not in VALID_KINDS:
        raise SchemaError(f"{where}: kind must be one of {VALID_KINDS}")
    _require_str(env, "id", where)
    producer = env.get("producer")
    if not isinstance(producer, dict):
        raise SchemaError(f"{where}: producer must be an object")
    _require_str(producer, "tool", f"{where}.producer")
    _require_str(producer, "version", f"{where}.producer")
    _require_iso(env, "occurred_at", where)
    _require_iso(env, "recorded_at", where)


def make_finding(producer: dict, occurred_at: str, *, target_repo: str,
                 target_commit: str, surface_id: str, cwe: str,
                 severity: Q16, repro_hash: str,
                 recorded_at: str | None = None,
                 row_id: str | None = None,
                 extra: dict | None = None) -> dict:
    """A FINDING/v1 cell. severity is ℚ₁₆ exact; repro_hash binds evidence
    by hash — evidence bytes are never copied into the ledger."""
    if not isinstance(severity, Q16):
        raise SchemaError("severity must be a Q16 (refuse-never-round)")
    env = _base_envelope("FINDING/v1", producer, occurred_at, recorded_at, row_id)
    env["target"] = {
        "repo": _require_repo(target_repo),
        "commit": _require_commit(target_commit),
        "surface_id": _require_str({"surface_id": surface_id}, "surface_id", "finding.target"),
    }
    env["cwe"] = _require_str({"cwe": cwe}, "cwe", "finding")
    env["severity"] = severity.to_json()
    env["repro_hash"] = _require_hash(repro_hash, "repro_hash")
    env["status"] = "PENDING"
    if extra:
        env["context"] = dict(extra)
    validate_finding(env)
    return env


def make_verdict(producer: dict, occurred_at: str, *, finding_id: str,
                 verdict: str, rationale_hash: str | None = None,
                 causes: list | None = None,
                 recorded_at: str | None = None,
                 row_id: str | None = None) -> dict:
    if verdict not in VALID_VERDICTS:
        raise SchemaError(f"verdict must be one of {VALID_VERDICTS}")
    env = _base_envelope("VERDICT/v1", producer, occurred_at, recorded_at, row_id)
    env["finding_id"] = _require_str({"finding_id": finding_id}, "finding_id", "verdict")
    env["verdict"] = verdict
    if rationale_hash is not None:
        env["rationale_hash"] = _require_hash(rationale_hash, "rationale_hash")
    if causes is not None:
        # Causality (lane rec 5): order is not causation. A verdict that
        # overturns a prior verdict says so; impact tracing descends these
        # edges. Optional and byte-compatible: row_hash binds fields present.
        if not isinstance(causes, list) or not causes:
            raise SchemaError("verdict: causes must be a non-empty list of row ids")
        for cid in causes:
            if not isinstance(cid, str) or not cid:
                raise SchemaError(f"verdict: cause id must be non-empty string: {cid!r}")
        env["causes"] = list(causes)
    return env


def make_refusal(producer: dict, occurred_at: str, *, reason: str,
                 campaign_id: str | None = None, detail: str | None = None,
                 recorded_at: str | None = None,
                 row_id: str | None = None,
                 extra: dict | None = None) -> dict:
    """A REFUSAL/v1 cell — preserved forever, never deleted, never mutated."""
    env = _base_envelope("REFUSAL/v1", producer, occurred_at, recorded_at, row_id)
    env["reason"] = _require_str({"reason": reason}, "reason", "refusal")
    if campaign_id is not None:
        env["campaign_id"] = campaign_id
    if detail is not None:
        env["detail"] = detail
    if extra:
        env["context"] = dict(extra)
    return env


def make_round_close(producer: dict, occurred_at: str, *, round_id: str,
                     closes: list, recorded_at: str | None = None,
                     row_id: str | None = None) -> dict:
    """A ROUND_CLOSE/v1 cell — the trial balance, booked exactly once.

    closes is the per-expectation account table from trial_balance.book_round:
    [{"expectation_id": ..., "close": CAUGHT|MISSED|REFUSED, "debits": n,
      "credits": n}, ...]. Writing this row is the only legal way to close
    a round; the balance is re-derivable from the rows beneath it, so a
    gamed close is itself a receipted lie.
    """
    env = _base_envelope("ROUND_CLOSE/v1", producer, occurred_at, recorded_at, row_id)
    env["round_id"] = _require_str({"round_id": round_id}, "round_id", "round_close")
    if not isinstance(closes, list) or not closes:
        raise SchemaError("round_close: closes must be a non-empty list")
    for entry in closes:
        if not isinstance(entry, dict):
            raise SchemaError("round_close: each close entry must be an object")
        _require_str(entry, "expectation_id", "round_close.closes")
        if entry.get("close") not in CLOSE_MODES:
            raise SchemaError(
                f"round_close: close must be one of {CLOSE_MODES}"
            )
    env["closes"] = [dict(c) for c in closes]
    return env


# ---------------------------------------------------------------- v2
# Contract gaps surfaced by the cellular ideator (B) and closed here:
#   #2  FINDING rows need genome_hash + dice_seed slots for replayable
#       evolution — a finding you cannot replay is a rumor.
#   #7  REFUSAL rows need a polarity field — silence and restraint are
#       not the same testimony.
# v2 envelopes are SUPERSETS of v1: every v1 field keeps its name and
# meaning; verify_chain is byte-compatible (canonical binds every field
# present). v1 producers keep working untouched.


def make_finding_v2(producer: dict, occurred_at: str, *,
                    genome_hash: str, dice_seed: int,
                    walk: dict | None = None,
                    **v1_fields) -> dict:
    """A FINDING/v2 cell: v1 envelope + replay binding.

    genome_hash: 16-hex identity of the hunter genome that produced the
    finding (floats never touch identity — the genome is named by hash).
    dice_seed: the deterministic seed the walk was driven with; together
    with walk context {ticks, start_pos, terrain_hash} the finding is
    re-executable: re-run the kernel, re-derive the claim, compare.
    A finding you cannot replay is a rumor."""
    env = make_finding(producer, occurred_at, **v1_fields)
    env["kind"] = "FINDING/v2"
    env["genome_hash"] = _require_genome_hash(genome_hash)
    env["dice_seed"] = _require_dice_seed(dice_seed)
    if walk is not None:
        if not isinstance(walk, dict):
            raise SchemaError("finding_v2: walk must be an object")
        env["walk"] = dict(walk)
    validate_finding_v2(env)
    return env


def make_refusal_v2(producer: dict, occurred_at: str, *,
                    polarity: str, exercise_id: str | None = None,
                    **v1_fields) -> dict:
    """A REFUSAL/v2 cell: v1 envelope + polarity testimony.

    polarity = why the refusal happened:
      positive — restraint: the hunter HAD the means and refused to act
                 (decoy_resisted, low_confidence_suppressed, window_full).
                 Positive refusals are the honesty signal the bench gates
                 on: decoys_resisted counts nothing but these.
      negative — abstention: the hunter LACKED the means (starvation,
                 no_energy, dormancy, budget_exhausted). Negative
                 refusals are capacity testimony, not honesty credit.
    Confusing them inflates an honest-hunter metric with a hungry one."""
    if polarity not in VALID_POLARITY:
        raise SchemaError(
            f"polarity must be one of {VALID_POLARITY}: {polarity!r}")
    env = make_refusal(producer, occurred_at, **v1_fields)
    env["kind"] = "REFUSAL/v2"
    env["polarity"] = polarity
    if exercise_id is not None:
        env["exercise_id"] = exercise_id
    validate_refusal_v2(env)
    return env


def validate_finding_v2(row: dict) -> None:
    validate_finding(row)  # v1 contract first: target/cwe/severity/repro
    if row.get("kind") != "FINDING/v2":
        raise SchemaError("finding_v2: kind must be FINDING/v2")
    _require_genome_hash(row.get("genome_hash"))
    _require_dice_seed(row.get("dice_seed"))
    walk = row.get("walk")
    if walk is not None and not isinstance(walk, dict):
        raise SchemaError("finding_v2: walk must be an object")


def validate_refusal_v2(row: dict) -> None:
    validate_core(row)
    if row.get("kind") != "REFUSAL/v2":
        raise SchemaError("refusal_v2: kind must be REFUSAL/v2")
    _require_str(row, "reason", "refusal_v2")
    if row.get("polarity") not in VALID_POLARITY:
        raise SchemaError(
            f"refusal_v2: polarity must be one of {VALID_POLARITY}")


def _require_genome_hash(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value):
        raise SchemaError(f"genome_hash must be 16-hex: {value!r}")
    return value


def _require_dice_seed(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SchemaError(f"dice_seed must be a non-negative int: {value!r}")
    return value


def validate_finding(row: dict) -> None:
    validate_core(row)
    target = row.get("target")
    if not isinstance(target, dict):
        raise SchemaError("finding: target must be an object")
    _require_str(target, "repo", "finding.target")
    _require_str(target, "commit", "finding.target")
    _require_str(target, "surface_id", "finding.target")
    _require_str(row, "cwe", "finding")
    if "severity" not in row:
        raise SchemaError("finding: missing severity")
    Q16.from_json(row["severity"])  # raises on violation
    _require_hash(row.get("repro_hash"), "repro_hash")
    if row.get("status") not in ("PENDING", "CONFIRMED", "REFUTED"):
        raise SchemaError("finding: status must be PENDING/CONFIRMED/REFUTED")


def _require_repo(name: str) -> str:
    if not isinstance(name, str) or "/" not in name:
        raise SchemaError(f"target.repo must look like owner/name: {name!r}")
    return name


def _require_commit(commit: str) -> str:
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{7,64}", commit):
        raise SchemaError(f"target.commit must be a hex commit: {commit!r}")
    return commit


def _require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SchemaError(f"{field} must be a 64-hex sha256: {value!r}")
    return value


def row_digest(row: dict) -> str:
    """fnv1a-64 over the canonical row (pre-hash fields excluded by caller)."""
    return fnv1a_64_hex(canonical_dumps(row))
