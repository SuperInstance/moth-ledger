"""Row signatures: authenticity (WHO produced it) on top of integrity
(Was it altered?). The chain already answers the second question; only
the first lives here.

Two questions, two mechanisms — never confuse them.

Backends:
- Ed25519Signer: real asymmetric signatures (needs `cryptography`).
  The upgrade path the lane review ordered: hashes -> hashes+signatures
  -> multi-signer receipts -> trust network.
- KeyedMacSigner: sha256(key || canonical_bytes). Stdlib-only fallback,
  HONESTLY LABELED backend="hmac-sha256-demo": shared-key authenticity,
  not non-repudiation. A MAC chain where the verifier holds the key is
  a confession, not an alibi — the label keeps that visible.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac

from .canonical import canonical_dumps

SIG_FIELDS = ("sig", "sig_backend")


def sig_payload(row: dict) -> bytes:
    """Canonical bytes of the row minus the signature fields themselves."""
    body = {k: v for k, v in row.items() if k not in SIG_FIELDS}
    return canonical_dumps(body)


class SignatureError(ValueError):
    pass


class KeyedMacSigner:
    """Stdlib fallback. backend label keeps the confession visible."""

    backend = "hmac-sha256-demo"

    def __init__(self, key: bytes):
        if not key:
            raise SignatureError("key must be non-empty")
        self._key = key

    def sign(self, row: dict) -> dict:
        mac = _hmac.new(self._key, sig_payload(row), hashlib.sha256).hexdigest()
        out = dict(row)
        out["sig"] = mac
        out["sig_backend"] = self.backend
        return out

    def verify(self, row: dict) -> bool:
        if row.get("sig_backend") != self.backend or "sig" not in row:
            return False
        expect = _hmac.new(self._key, sig_payload(row), hashlib.sha256).hexdigest()
        return _hmac.compare_digest(expect, row["sig"])


class Ed25519Signer:
    """Real asymmetric signatures via `cryptography` (optional dep)."""

    backend = "ed25519"

    def __init__(self, private_key=None, public_key=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        self._priv = private_key or Ed25519PrivateKey.generate()
        self._pub = public_key or self._priv.public_key()

    def sign(self, row: dict) -> dict:
        sig = self._priv.sign(sig_payload(row)).hex()
        out = dict(row)
        out["sig"] = sig
        out["sig_backend"] = self.backend
        return out

    def verify(self, row: dict) -> bool:
        if row.get("sig_backend") != self.backend or "sig" not in row:
            return False
        from cryptography.exceptions import InvalidSignature
        try:
            self._pub.verify(bytes.fromhex(row["sig"]), sig_payload(row))
            return True
        except (InvalidSignature, ValueError):
            return False


def best_signer(key: bytes | None = None) -> object:
    """Ed25519 when available, else the labeled MAC fallback."""
    try:
        return Ed25519Signer()
    except ImportError:
        if key is None:
            raise SignatureError(
                "no ed25519 backend and no fallback key provided")
        return KeyedMacSigner(key)


def sign_row(row: dict, signer) -> dict:
    """Attach a signature; the signature binds every field present."""
    return signer.sign(row)


def verify_row_sig(row: dict, signer) -> bool:
    """Re-derive from residue — same law as verify_chain."""
    return signer.verify(row)
