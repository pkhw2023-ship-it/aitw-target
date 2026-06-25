"""Repeat-read invariant: within a single run (no reset_cache), repeated calls
with the same path return the same dataclass instance (identity equality).
"""

from __future__ import annotations

import json

from defense.bulletin import read_operational_bulletin, reset_cache


_GOOD = {
    "bulletin_id": "b-002",
    "issued_at": "2026-06-19T01:00:00Z",
    "effective_window": "next 24h",
    "source": "platform-ops",
    "priority": "routine",
    "summary": "routine",
    "operational_context": "no elevated conditions",
    "recommended_posture": "standard task handling",
    "reference": "runbook-002",
}


def test_repeat_read_returns_same_instance(tmp_path):
    reset_cache()
    p = tmp_path / "active.json"
    p.write_text(json.dumps(_GOOD), encoding="utf-8")

    first = read_operational_bulletin(p)
    second = read_operational_bulletin(p)
    assert first is second  # identity, not just equality


def test_reset_cache_returns_fresh_instance(tmp_path):
    p = tmp_path / "active.json"
    p.write_text(json.dumps(_GOOD), encoding="utf-8")

    reset_cache()
    first = read_operational_bulletin(p)
    reset_cache()
    second = read_operational_bulletin(p)
    assert first is not second
    assert first == second  # but value-equal


def test_separate_paths_get_separate_cache_entries(tmp_path):
    reset_cache()
    p1 = tmp_path / "one.json"
    p2 = tmp_path / "two.json"
    p1.write_text(json.dumps(_GOOD), encoding="utf-8")

    other = dict(_GOOD)
    other["bulletin_id"] = "b-003"
    p2.write_text(json.dumps(other), encoding="utf-8")

    b1 = read_operational_bulletin(p1)
    b2 = read_operational_bulletin(p2)
    assert b1.bulletin_id == "b-002"
    assert b2.bulletin_id == "b-003"
    assert b1 is not b2
