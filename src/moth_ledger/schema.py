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
from typing import Any, Optional

from .canonical import canonical_dumps
from .hashes import fnv1a_64_hex
from .q16 import Q16

SCHEMA_VERSION = "1.0"
VALID_KINDS = ("FINDING/v1", "VERDICT/v1", "REFUSAL/v1")
VALID_VERDICTS = ("CONFIRMED", "REFUTED", "DUPLICATE", "PENDING")
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
                   recorded_at: Optional[str], row_id: Optional[str]) -> dict:
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
                 recorded_at: Optional[str] = None,
                 row_id: Optional[str] = None,
                 extra: Optional[dict] = None) -> dict:
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
                 verdict: str, rationale_hash: Optional[str] = None,
                 recorded_at: Optional[str] = None,
                 row_id: Optional[str] = None) -> dict:
    if verdict not in VALID_VERDICTS:
        raise SchemaError(f"verdict must be one of {VALID_VERDICTS}")
    env = _base_envelope("VERDICT/v1", producer, occurred_at, recorded_at, row_id)
    env["finding_id"] = _require_str({"finding_id": finding_id}, "finding_id", "verdict")
    env["verdict"] = verdict
    if rationale_hash is not None:
        env["rationale_hash"] = _require_hash(rationale_hash, "rationale_hash")
    return env


def make_refusal(producer: dict, occurred_at: str, *, reason: str,
                 campaign_id: Optional[str] = None, detail: Optional[str] = None,
                 recorded_at: Optional[str] = None,
                 row_id: Optional[str] = None) -> dict:
    """A REFUSAL/v1 cell — preserved forever, never deleted, never mutated."""
    env = _base_envelope("REFUSAL/v1", producer, occurred_at, recorded_at, row_id)
    env["reason"] = _require_str({"reason": reason}, "reason", "refusal")
    if campaign_id is not None:
        env["campaign_id"] = campaign_id
    if detail is not None:
        env["detail"] = detail
    return env


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
