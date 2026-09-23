"""Merkle layer over the receipt spine: prove a row is in the ledger
without replaying everything.

The chain verifies ORDER (O(n) from genesis). The Merkle root verifies
MEMBERSHIP (O(log n) per proof). Think certificate transparency: the
ledger stays the source of sequence; the root is the portable summary
a verifier checks a single row against.

Leaves are sha256 of the row_hash hex strings (chain content, not
ordering). Duplicate row_hashes pair with themselves on promotion —
Bitcoin's rule, because duplicated evidence dedups to one object but
the tree must not confuse repetition with position.
"""
from __future__ import annotations

import hashlib


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _parent(left: str, right: str) -> str:
    return _sha(bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(leaves: list[str]) -> str:
    """Root over sha256 leaf digests. Empty ledger -> sha256 of empty."""
    if not leaves:
        return _sha(b"")
    level = [_sha(bytes.fromhex(leaf)) for leaf in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_parent(level[i], level[i + 1]))
            else:
                nxt.append(_parent(level[i], level[i]))  # duplicate last
        level = nxt
    return level[0]


def inclusion_proof(leaves: list[str], index: int) -> list[dict]:
    """Sibling path for leaves[index]. Each step: {side, hash}."""
    if index < 0 or index >= len(leaves):
        raise IndexError(f"leaf index {index} out of range (n={len(leaves)})")
    level = [_sha(bytes.fromhex(leaf)) for leaf in leaves]
    idx = index
    proof: list[dict] = []
    while len(level) > 1:
        sib = idx ^ 1
        if sib >= len(level):
            sib = idx  # duplicated tail pairs with itself
        proof.append({"side": "left" if sib < idx else "right",
                      "hash": level[sib]})
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_parent(level[i], level[i + 1]))
            else:
                nxt.append(_parent(level[i], level[i]))
        idx //= 2
        level = nxt
    return proof


def verify_proof(leaf: str, proof: list[dict], root: str) -> bool:
    """Recompute the root from the leaf and path; constant-ish work."""
    node = _sha(bytes.fromhex(leaf))
    for step in proof:
        sib = step["hash"]
        if step["side"] == "left":
            node = _parent(sib, node)
        else:
            node = _parent(node, sib)
    return node == root
