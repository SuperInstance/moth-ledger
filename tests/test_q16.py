"""ℚ₁₆ refuse-never-round floor."""
import pytest

from moth_ledger import Q16, Q16Refusal


def test_exact_float_accepted():
    assert Q16.from_float(0.5).numerator == 32768
    assert Q16.from_float(0.0).numerator == 0
    assert Q16.from_float(1.0).numerator == 65536


def test_inexact_float_refused():
    with pytest.raises(Q16Refusal):
        Q16.from_float(0.1)  # 0.1 is not n/65536


def test_from_parts_exact():
    q = Q16.from_parts(1, 2)
    assert q.numerator == 32768
    assert q.denominator == 65536


def test_from_parts_refused():
    with pytest.raises(Q16Refusal):
        Q16.from_parts(1, 3)


def test_json_roundtrip():
    q = Q16.from_float(0.25)
    assert Q16.from_json(q.to_json()) == q


def test_json_wrong_denominator_refused():
    with pytest.raises(Q16Refusal):
        Q16.from_json({"num": "1", "den": "1000"})


def test_out_of_domain_refused():
    with pytest.raises(Q16Refusal):
        Q16(65537)
    with pytest.raises(Q16Refusal):
        Q16(-1)


def test_arithmetic():
    a = Q16.from_float(0.25)
    b = Q16.from_float(0.5)
    assert a + b == Q16.from_float(0.75)
    assert b - a == Q16.from_float(0.25)


def test_arithmetic_overflow_refused():
    a = Q16.from_float(0.75)
    b = Q16.from_float(0.5)
    with pytest.raises(Q16Refusal):
        a + b  # 1.25 outside [0,1]


def test_comparison():
    assert Q16.from_float(0.25) < Q16.from_float(0.5)
    assert Q16.from_float(0.5) <= Q16.from_float(0.5)


def test_lossy_view_marked():
    q = Q16.from_float(0.5)
    assert q.to_float_lossy() == 0.5
