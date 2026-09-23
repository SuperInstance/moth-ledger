"""Bytes-law hashing: fnv1a-64 over UTF-8 bytes, never characters.

Pinned vector (JEV-SPEC, jev-quilt PR #4): the UTF-8 byte sequence of
"café Δ 日本語" hashes to 0x024a555471370b18d. Ports in TS/Rust/WASM must
reproduce this byte-for-byte. Bytes, not characters — the Ê in café, the
Greek Delta, and the CJK run exist to catch engines that hash code points.
"""
from __future__ import annotations

import hashlib

FNV1A64_OFFSET = 0xCBF29CE484222325
FNV1A64_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF

# Pinned test vectors: (utf8_bytes, expected_fnv1a64)
PINNED_VECTORS = [
    (b"", 0xCBF29CE484222325),
    # JEV-SPEC bytes-law pin. Integer-equal to the spec's 0x024a555471370b18d
    # (memory recorded a spurious leading zero; integers compare equal —
    # canonical string form here is the 64-bit zero-padded 16-digit form).
    ("café Δ 日本語".encode(), 0x24A555471370B18D),
    (b"a", 0xAF63DC4C8601EC8C),
    (b"hello", 0xA430D84680Aabd0B),
]


def fnv1a_64(data: bytes | bytearray | memoryview) -> int:
    """FNV-1a 64-bit hash over raw bytes."""
    h = FNV1A64_OFFSET
    for byte in bytes(data):
        h ^= byte
        h = (h * FNV1A64_PRIME) & MASK64
    return h


def fnv1a_64_hex(data: bytes | bytearray | memoryview) -> str:
    return f"{fnv1a_64(data):016x}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_pins() -> None:
    """Verify every pinned vector; raise if any drifted."""
    for raw, expected in PINNED_VECTORS:
        got = fnv1a_64(raw)
        if got != expected:
            raise AssertionError(
                f"bytes-law pin broken: {raw[:24]!r} -> {got:#018x}, "
                f"expected {expected:#018x}"
            )
