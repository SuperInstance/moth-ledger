"""Canonical JSON — the attractor recipe.

Both independent durability stacks (evintunador's annals family and the
4quilt family) converged on this exact serialization: sorted keys, minimal
separators, UTF-8 bytes, no whitespace. A durable system's integrity is
proportional to the precision of its refusals — this module refuses
non-canonical input rather than silently re-canonicalizing.
"""
from __future__ import annotations

import json
from typing import Any


class CanonicalError(ValueError):
    """Raised when a value cannot be represented canonically."""


def canonical_dumps(obj: Any) -> bytes:
    """Serialize to canonical JSON bytes (sorted keys, minimal separators)."""
    try:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CanonicalError(f"not canonically serializable: {exc}") from exc


def canonical_equal(a: Any, b: Any) -> bool:
    """Byte-equality under canonical serialization."""
    return canonical_dumps(a) == canonical_dumps(b)
