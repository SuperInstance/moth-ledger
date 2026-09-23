"""Bytes-law pins: fnv1a-64 over UTF-8 bytes, never characters."""
from moth_ledger import assert_pins, fnv1a_64, fnv1a_64_hex, sha256_hex


def test_pinned_vectors():
    assert_pins()  # raises if any drifted


def test_cafe_delta_nihongo_pin():
    raw = "café Δ 日本語".encode()
    assert fnv1a_64(raw) == 0x024A555471370B18D
    assert fnv1a_64_hex(raw) == "24a555471370b18d"


def test_bytes_not_characters():
    # Hashing the str's code points would give a different value.
    raw = "café".encode()
    assert fnv1a_64(raw) != fnv1a_64("café".encode("utf-16-le"))


def test_empty_vector():
    assert fnv1a_64(b"") == 0xCBF29CE484222325


def test_sha256():
    assert sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
