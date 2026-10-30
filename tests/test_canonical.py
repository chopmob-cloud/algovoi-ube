"""RFC 8785 conformance tests.

The number vectors are the IEEE 754 bit patterns from the ECMAScript
Number::toString test set that RFC 8785 adopts in Appendix B. Testing against
those is the difference between "our canonicaliser agrees with itself" and "our
canonicaliser agrees with every other JCS implementation".
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.canonical import CanonicalizationError, canonicalize  # noqa: E402

# IEEE 754 double bit pattern -> ECMAScript string, from RFC 8785 Appendix B.
NUMBER_VECTORS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),  # negative zero
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("3eb0c6f7a0b5ed8e", "0.0000010000000000000002"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def _from_bits(bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(bits))[0]


@pytest.mark.parametrize("bits,expected", NUMBER_VECTORS)
def test_ecmascript_number_serialisation(bits, expected):
    value = _from_bits(bits)
    assert canonicalize(value) == expected, f"{bits} -> {value!r}"


def test_integers_are_not_forced_through_the_float_path():
    assert canonicalize(0) == "0"
    assert canonicalize(-1) == "-1"
    assert canonicalize(10**20) == "100000000000000000000"


def test_nan_and_infinity_are_refused():
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalizationError):
            canonicalize(value)


def test_booleans_are_not_numbers():
    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"


def test_keys_sort_by_utf16_code_units_not_code_points():
    """U+10000 is D800 DC00 in UTF-16, so it sorts before U+E000.

    Python's default string ordering is by code point and would put U+E000
    first, which is the mismatch that makes two JCS implementations disagree
    without either reporting an error.
    """
    value = {"\ue000": 1, "\U00010000": 2}
    assert canonicalize(value) == '{"\U00010000":2,"\ue000":1}'


def test_ascii_keys_sort_as_expected():
    assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_strings_escape_only_what_is_required():
    assert canonicalize('quote " backslash \\') == '"quote \\" backslash \\\\"'
    assert canonicalize("\n\t\r\b\f") == '"\\n\\t\\r\\b\\f"'
    assert canonicalize("\x00\x1f") == '"\\u0000\\u001f"'


def test_non_ascii_is_emitted_literally_not_escaped():
    """ensure_ascii=True would produce \\u00e9; JCS emits the UTF-8 bytes."""
    assert canonicalize("caf\u00e9") == '"caf\u00e9"'
    assert "\\u00e9" not in canonicalize("caf\u00e9")


def test_lone_surrogate_is_refused():
    with pytest.raises(CanonicalizationError):
        canonicalize("\ud800")


def test_nested_structures_round_out():
    value = {"b": [1, {"z": None, "a": True}], "a": "x"}
    assert canonicalize(value) == '{"a":"x","b":[1,{"a":true,"z":null}]}'


def test_no_whitespace_is_emitted():
    assert " " not in canonicalize({"a": [1, 2], "b": {"c": 3}})


def test_unsupported_types_are_refused():
    with pytest.raises(CanonicalizationError):
        canonicalize({"a": object()})
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "non-string key"})


def test_canonical_form_is_stable_across_key_insertion_order():
    one = {"z": 1, "a": 2, "m": 3}
    two = {"a": 2, "m": 3, "z": 1}
    assert canonicalize(one) == canonicalize(two)
