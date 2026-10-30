"""RFC 8785 JSON Canonicalization Scheme.

Signing needs deterministic bytes: the same receipt must serialise identically
on the issuer's machine and the verifier's, or the signature verifies nowhere.
Python's ``json.dumps(sort_keys=True, separators=(",", ":"))`` is close to that
and is not it. Three differences matter, and each one produces a silent
mismatch rather than an error:

  numbers      RFC 8785 requires ECMAScript Number::toString, which is not
               Python's repr. ``1e-07`` becomes ``1e-7``, ``1e+21`` stays
               exponential while ``1e+20`` does not, and ``-0`` becomes ``0``.
  key order    Keys sort by UTF-16 code units, so a non-BMP character sorts
               before U+E000 rather than after it, which is the opposite of
               Python's code point order.
  strings      Only quote, backslash and control characters are escaped.
               ``ensure_ascii=True`` would escape every non-ASCII character as
               ``\\uXXXX``, which is valid JSON and is not JCS.

This module implements the three rules and refuses the inputs the scheme
forbids rather than guessing at them.
"""

from __future__ import annotations

import math
from typing import Any

__all__ = ["canonicalize", "CanonicalizationError"]


class CanonicalizationError(ValueError):
    """The value cannot be represented in RFC 8785 canonical form."""


_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(value: str) -> str:
    """Escape only what RFC 8785 section 3.2.2.2 requires."""
    out = ['"']
    for char in value:
        if char in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[char])
        elif char < "\x20":
            out.append(f"\\u{ord(char):04x}")
        elif char == "\x7f":
            # Not required to be escaped, and JCS leaves it literal.
            out.append(char)
        else:
            code = ord(char)
            if 0xD800 <= code <= 0xDFFF:
                raise CanonicalizationError(
                    "lone surrogate in a string cannot be serialised: "
                    "RFC 8785 requires valid Unicode"
                )
            out.append(char)
    out.append('"')
    return "".join(out)


def _format_number(value: float | int) -> str:
    """ECMAScript Number::toString, per RFC 8785 section 3.2.2.3.

    Python's repr already gives the shortest string that round-trips, which is
    the same digits the ECMAScript algorithm picks. What differs is how those
    digits are laid out around the decimal point and when the exponential form
    is used, so the digits are extracted and re-laid out here.
    """
    if isinstance(value, bool):  # bool is an int subclass; JCS wants true/false
        raise CanonicalizationError("booleans are not numbers")
    if isinstance(value, int):
        if value == 0:
            return "0"
        return str(value)
    if not math.isfinite(value):
        raise CanonicalizationError(
            "NaN and Infinity have no canonical form: RFC 8785 forbids them"
        )
    if value == 0:
        return "0"  # covers -0.0, which JCS serialises as 0

    sign = "-" if value < 0 else ""
    text = repr(abs(value))

    if "e" in text or "E" in text:
        mantissa, _, exponent_text = text.replace("E", "e").partition("e")
        exponent = int(exponent_text)
    else:
        mantissa, exponent = text, 0

    if "." in mantissa:
        integer_part, fraction_part = mantissa.split(".")
    else:
        integer_part, fraction_part = mantissa, ""

    if integer_part.strip("0"):
        digits = (integer_part + fraction_part).lstrip("0")
        n = len(integer_part) + exponent
    else:
        leading_zeros = len(fraction_part) - len(fraction_part.lstrip("0"))
        digits = fraction_part.lstrip("0")
        n = -leading_zeros + exponent

    digits = digits.rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        exponent_value = n - 1
        tail = "." + digits[1:] if k > 1 else ""
        body = (
            digits[0]
            + tail
            + "e"
            + ("+" if exponent_value >= 0 else "-")
            + str(abs(exponent_value))
        )
    return sign + body


def _key_order(key: str) -> bytes:
    """Sort keys by UTF-16 code units, as RFC 8785 section 3.2.3 requires."""
    return key.encode("utf-16-be", "surrogatepass")


def canonicalize(value: Any) -> str:
    """Return the RFC 8785 canonical JSON string for ``value``."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, (int, float)):
        return _format_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
        parts = []
        for key in sorted(value, key=_key_order):
            parts.append(_escape_string(key) + ":" + canonicalize(value[key]))
        return "{" + ",".join(parts) + "}"
    raise CanonicalizationError(
        f"{type(value).__name__} has no canonical JSON form"
    )
