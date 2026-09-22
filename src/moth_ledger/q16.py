"""ℚ₁₆ — the refuse-never-round exact floor for measured fields.

Severity (and any measured quantity in a moth envelope) is stored as an
exact rational n/65536. Conversion from float REFUSES when the value is not
exactly representable — we never round a measurement into existence.
Use q16_from_parts(num, den) when you mean an exact ratio.
"""
from __future__ import annotations

from fractions import Fraction

DENOMINATOR = 65536
MAX_NUM = DENOMINATOR  # severity domain [0, 1]


class Q16Refusal(ValueError):
    """Raised when a value cannot be represented in ℚ₁₆ exactly."""


class Q16:
    """Exact rational with denominator 65536, enforced at construction."""

    __slots__ = ("_num",)

    def __init__(self, num: int):
        if not isinstance(num, int):
            raise Q16Refusal(f"Q16 numerator must be int, got {type(num).__name__}")
        if not (0 <= num <= MAX_NUM):
            raise Q16Refusal(f"Q16 value {num}/{DENOMINATOR} outside [0, 1]")
        self._num = num

    @classmethod
    def from_float(cls, x: float) -> "Q16":
        frac = Fraction(x)  # exact binary fraction
        scaled = frac * DENOMINATOR
        if scaled.denominator != 1:
            raise Q16Refusal(
                f"refuse-never-round: {x!r} is not exactly n/{DENOMINATOR}"
            )
        return cls(int(scaled))

    @classmethod
    def from_parts(cls, num: int, den: int) -> "Q16":
        if den <= 0:
            raise Q16Refusal("denominator must be positive")
        scaled_num = num * DENOMINATOR
        if scaled_num % den != 0:
            raise Q16Refusal(f"refuse-never-round: {num}/{den} not in ℚ₁₆")
        return cls(scaled_num // den)

    @property
    def numerator(self) -> int:
        return self._num

    @property
    def denominator(self) -> int:
        return DENOMINATOR

    def to_json(self) -> dict:
        return {"num": str(self._num), "den": str(DENOMINATOR)}

    @classmethod
    def from_json(cls, obj: dict) -> "Q16":
        if set(obj.keys()) != {"num", "den"}:
            raise Q16Refusal("Q16 json must have exactly {num, den}")
        if obj["den"] != str(DENOMINATOR):
            raise Q16Refusal(f"Q16 denominator must be {DENOMINATOR}")
        return cls(int(obj["num"]))

    def _coerce(self, other: "Q16") -> "Q16":
        if not isinstance(other, Q16):
            raise Q16Refusal(f"expected Q16, got {type(other).__name__}")
        return other

    def __add__(self, other: "Q16") -> "Q16":
        other = self._coerce(other)
        return Q16(self._num + other._num)

    def __sub__(self, other: "Q16") -> "Q16":
        other = self._coerce(other)
        return Q16(self._num - other._num)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Q16) and self._num == other._num

    def __lt__(self, other: "Q16") -> bool:
        other = self._coerce(other)
        return self._num < other._num

    def __le__(self, other: "Q16") -> bool:
        other = self._coerce(other)
        return self._num <= other._num

    def __hash__(self) -> int:
        return hash(("Q16", self._num))

    def __repr__(self) -> str:
        return f"Q16({self._num}/{DENOMINATOR})"

    def to_float_lossy(self) -> float:
        """Lossy view for humans only; never serialize this."""
        return self._num / DENOMINATOR
