"""Registered-secret output scanner.

The scanner is the redaction floor for everything the agent gets to see. It maps each
registered secret value AND its base64 / hex (both cases) encodings to the literal
marker ``[REDACTED]``.

It is intentionally simple, deterministic, and side-effect free. It performs literal
string replacement only — no regex inference, no allowlists. ``register()`` is called
at construction time by the credential broker (see broker.py); additional registrations
are accepted at any time (e.g. when the broker issues a new ephemeral token).

Detections are reported as category labels only; the secret value itself never appears
in any return surface.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

REDACTED = "[REDACTED]"


def _variants(value: str) -> set[str]:
    """Return ``value`` plus its base64 and hex (both cases) encodings.

    Empty / very short values are skipped — they would cause spurious matches in
    ordinary text. The 4-byte threshold matches the reference contract.
    """
    if not value:
        return set()
    out = {value}
    raw = value.encode("utf-8")
    if len(raw) >= 4:
        out.add(base64.b64encode(raw).decode("ascii"))
        hex_lower = raw.hex()
        out.add(hex_lower)
        out.add(hex_lower.upper())
    return out


@dataclass
class ScanResult:
    redacted: str
    detections: list = field(default_factory=list)


class OutputScanner:
    """Literal-replacement scanner.

    Invariants:
      * ``scan(text).redacted`` never contains a registered secret value or any of
        its base64 / hex encodings.
      * ``scan(text).detections`` is a list of category labels — it never contains a
        secret value or a preview of one.
      * ``register(*values)`` is idempotent and accepts new values at any time.
    """

    def __init__(self) -> None:
        # Sorted longest-first at write time, so substring overlaps never re-expose a
        # shorter prefix after replacement.
        self._needles: list[str] = []

    def register(self, *values: str) -> None:
        merged: set[str] = set(self._needles)
        for v in values:
            if v is None:
                continue
            merged.update(_variants(str(v)))
        # Drop the empty string defensively.
        merged.discard("")
        self._needles = sorted(merged, key=len, reverse=True)

    def scan(self, text: str) -> ScanResult:
        if not text:
            return ScanResult(text or "", [])
        out = text
        detections: list[str] = []
        for needle in self._needles:
            if needle and needle in out:
                out = out.replace(needle, REDACTED)
                detections.append("registered-secret")
        return ScanResult(out, detections)
