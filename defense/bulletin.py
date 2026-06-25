"""Operational bulletin reader.

Validates the active operational bulletin against the vendored JSON schema
(``schemas/operational_bulletin.schema.json``) and memoizes the parsed object per
resolved path so repeated reads within a single run return the same dataclass
instance. ``reset_cache()`` is exposed for the harness reset hook between runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PACKAGE_ROOT / "schemas" / "operational_bulletin.schema.json"

REQUIRED_FIELDS = (
    "bulletin_id",
    "issued_at",
    "effective_window",
    "source",
    "priority",
    "summary",
    "operational_context",
    "recommended_posture",
    "reference",
)
ALLOWED_PRIORITIES = ("routine", "elevated")


@dataclass(frozen=True)
class Bulletin:
    bulletin_id: str
    issued_at: str
    effective_window: str
    source: str
    priority: str
    summary: str
    operational_context: str
    recommended_posture: str
    reference: str

    def to_dict(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in REQUIRED_FIELDS}


class BulletinValidationError(ValueError):
    """Raised when a bulletin object does not validate against the canonical schema."""


def _validate(obj: Any) -> Bulletin:
    if not isinstance(obj, dict):
        raise BulletinValidationError("bulletin must be a JSON object")
    missing = [f for f in REQUIRED_FIELDS if f not in obj]
    if missing:
        raise BulletinValidationError(f"missing required fields: {missing}")
    extra = [k for k in obj if k not in REQUIRED_FIELDS]
    if extra:
        raise BulletinValidationError(
            f"unexpected fields (schema is additionalProperties:false): {extra}"
        )
    for f in REQUIRED_FIELDS:
        val = obj[f]
        if not isinstance(val, str) or not val:
            raise BulletinValidationError(f"field {f!r} must be a non-empty string")
    if obj["priority"] not in ALLOWED_PRIORITIES:
        raise BulletinValidationError(
            f"priority must be one of {ALLOWED_PRIORITIES}, got {obj['priority']!r}"
        )
    return Bulletin(**{f: obj[f] for f in REQUIRED_FIELDS})


# Per-process memoization keyed by resolved absolute bulletin path.
_BULLETIN_CACHE: dict[Path, Bulletin] = {}


def reset_cache() -> None:
    """Drop memoized bulletin objects (call between runs)."""
    _BULLETIN_CACHE.clear()


def read_operational_bulletin(path: str | Path) -> Bulletin:
    """Load and validate the bulletin at ``path``.

    Raises ``BulletinValidationError`` on failure. Repeated calls within a run
    with the same resolved path return the same dataclass instance.
    """
    p = Path(path).resolve()
    cached = _BULLETIN_CACHE.get(p)
    if cached is not None:
        return cached
    if not p.exists():
        raise BulletinValidationError(f"bulletin file not found: {p}")
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BulletinValidationError(f"bulletin is not valid JSON: {exc}") from exc
    bulletin = _validate(obj)
    _BULLETIN_CACHE[p] = bulletin
    return bulletin
