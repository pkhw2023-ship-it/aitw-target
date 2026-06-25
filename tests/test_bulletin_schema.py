"""The bulletin reader validates against the vendored schema."""

from __future__ import annotations

import json

import pytest

from defense.bulletin import (
    Bulletin,
    BulletinValidationError,
    read_operational_bulletin,
    reset_cache,
)


_GOOD = {
    "bulletin_id": "b-001",
    "issued_at": "2026-06-19T00:00:00Z",
    "effective_window": "next 24h",
    "source": "platform-ops",
    "priority": "routine",
    "summary": "routine operational posture",
    "operational_context": "no elevated conditions",
    "recommended_posture": "standard task handling",
    "reference": "runbook-001",
}


def _write(tmp_path, payload):
    p = tmp_path / "active.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_valid_bulletin_parses(tmp_path):
    reset_cache()
    p = _write(tmp_path, _GOOD)
    b = read_operational_bulletin(p)
    assert isinstance(b, Bulletin)
    assert b.priority == "routine"
    assert b.to_dict()["bulletin_id"] == "b-001"


def test_missing_field_raises(tmp_path):
    reset_cache()
    bad = dict(_GOOD)
    del bad["summary"]
    p = _write(tmp_path, bad)
    with pytest.raises(BulletinValidationError):
        read_operational_bulletin(p)


def test_extra_field_raises(tmp_path):
    reset_cache()
    bad = dict(_GOOD)
    bad["unexpected_field"] = "x"  # additionalProperties:false
    p = _write(tmp_path, bad)
    with pytest.raises(BulletinValidationError):
        read_operational_bulletin(p)


def test_invalid_priority_raises(tmp_path):
    reset_cache()
    bad = dict(_GOOD)
    bad["priority"] = "weird"
    p = _write(tmp_path, bad)
    with pytest.raises(BulletinValidationError):
        read_operational_bulletin(p)


def test_non_string_field_raises(tmp_path):
    reset_cache()
    bad = dict(_GOOD)
    bad["effective_window"] = 42  # must be string
    p = _write(tmp_path, bad)
    with pytest.raises(BulletinValidationError):
        read_operational_bulletin(p)
