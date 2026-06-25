"""Acceptance criterion 1: scanner redacts each registered secret value AND its
base64 / hex (both cases) encodings, replacing them with the literal marker
``[REDACTED]``. A secret never survives in any tool result, model-facing text,
or run log.
"""

from __future__ import annotations

import base64

from defense.scanner import REDACTED, OutputScanner


def test_scanner_redacts_plain_value():
    s = OutputScanner()
    s.register("sk-secret-123")
    out = s.scan("payload contains sk-secret-123 in body").redacted
    assert "sk-secret-123" not in out
    assert REDACTED in out


def test_scanner_redacts_base64_encoding():
    s = OutputScanner()
    s.register("sk-secret-123")
    encoded = base64.b64encode(b"sk-secret-123").decode("ascii")
    out = s.scan(f"smuggled as {encoded} in body").redacted
    assert encoded not in out
    assert REDACTED in out


def test_scanner_redacts_hex_lowercase():
    s = OutputScanner()
    s.register("sk-secret-123")
    hex_lower = b"sk-secret-123".hex()
    out = s.scan(f"hex form {hex_lower} appears").redacted
    assert hex_lower not in out
    assert REDACTED in out


def test_scanner_redacts_hex_uppercase():
    s = OutputScanner()
    s.register("sk-secret-123")
    hex_upper = b"sk-secret-123".hex().upper()
    out = s.scan(f"hex form {hex_upper} appears").redacted
    assert hex_upper not in out
    assert REDACTED in out


def test_scanner_supports_multiple_registered_values():
    s = OutputScanner()
    s.register("AAAAAAAA-token", "BBBBBBBB-token")
    out = s.scan("first AAAAAAAA-token then BBBBBBBB-token end").redacted
    assert "AAAAAAAA-token" not in out
    assert "BBBBBBBB-token" not in out
    assert out.count(REDACTED) == 2


def test_scanner_detections_never_contain_secret_value():
    s = OutputScanner()
    s.register("sk-secret-123")
    result = s.scan("body sk-secret-123 body")
    for label in result.detections:
        assert "sk-secret-123" not in label
        # Detections are category labels, not preview values.
        assert label == "registered-secret"


def test_scanner_accepts_new_values_after_construction():
    """The broker calls register() at runtime when it issues new tokens; the
    scanner must accept new values at any time."""
    s = OutputScanner()
    s.register("first-secret-value")
    out_before = s.scan("contains later-secret-value untouched").redacted
    assert "later-secret-value" in out_before
    s.register("later-secret-value")
    out_after = s.scan("contains later-secret-value redacted").redacted
    assert "later-secret-value" not in out_after
    assert REDACTED in out_after


def test_scanner_handles_empty_input_safely():
    s = OutputScanner()
    s.register("anything")
    assert s.scan("").redacted == ""
    assert s.scan(None).redacted == ""
