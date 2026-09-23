"""moth-ledger — MOTH findings as quilt-native receipted cells.

The receipt spine of the moth family: every finding, verdict, and refusal
is a cell in an append-only, hash-chained, canonical-JSON ledger.
"""
from .canonical import CanonicalError, canonical_dumps, canonical_equal
from .hashes import PINNED_VECTORS, assert_pins, fnv1a_64, fnv1a_64_hex, sha256_hex
from .ledger import GENESIS, ChainBroken, Ledger, LedgerError
from .q16 import DENOMINATOR as Q16_DENOMINATOR
from .q16 import Q16, Q16Refusal
from .schema import (
    SCHEMA_VERSION,
    VALID_KINDS,
    VALID_VERDICTS,
    SchemaError,
    make_finding,
    make_producer,
    make_refusal,
    make_verdict,
    new_id,
    row_digest,
)

__version__ = "0.1.0"

__all__ = [
    "GENESIS",
    "PINNED_VECTORS",
    "Q16",
    "Q16_DENOMINATOR",
    "SCHEMA_VERSION",
    "VALID_KINDS",
    "VALID_VERDICTS",
    "CanonicalError",
    "ChainBroken",
    "Ledger",
    "LedgerError",
    "Q16Refusal",
    "SchemaError",
    "__version__",
    "assert_pins",
    "canonical_dumps",
    "canonical_equal",
    "fnv1a_64",
    "fnv1a_64_hex",
    "make_finding",
    "make_producer",
    "make_refusal",
    "make_verdict",
    "new_id",
    "row_digest",
    "sha256_hex",
]
