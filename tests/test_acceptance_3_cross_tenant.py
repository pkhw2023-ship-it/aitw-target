"""Acceptance criterion 3: no other tenant's record is reachable through the
agent-facing (scoped) store. Cross-tenant reads return nothing; cross-tenant
writes and deletes raise PermissionError.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from aitw.context.store import ContextStore
from aitw.tools.registry import ToolContext

import provider


@dataclass
class _FakeProfile:
    tenant_id: str = "alpha"
    allowed_tools: list = field(default_factory=lambda: ["shared_memory"])

    def system_prompt(self) -> str:
        return ""


def _seeded_raw_store():
    raw = ContextStore(":memory:")
    raw.put("alpha", "memo", "own", "alpha's own note")
    raw.put("beta", "memo", "secret", "beta-secret-content-DO-NOT-LEAK")
    raw.put("beta", "profile", "agent", "beta's profile body")
    return raw


def test_cross_tenant_get_returns_none():
    dep = provider.DEPLOYMENT
    raw = _seeded_raw_store()
    scoped = dep.wrap_store(raw, "alpha")

    beta_key = scoped.key_for("beta", "memo", "secret")
    assert scoped.get(beta_key) is None


def test_cross_tenant_list_keys_returns_nothing():
    dep = provider.DEPLOYMENT
    raw = _seeded_raw_store()
    scoped = dep.wrap_store(raw, "alpha")

    # Empty prefix is rewritten to the calling tenant prefix.
    keys_default = scoped.list_keys("")
    assert all(k.startswith("alpha:") for k in keys_default)
    assert all(not k.startswith("beta:") for k in keys_default)

    # Explicit cross-tenant prefix returns empty.
    assert scoped.list_keys("beta:") == []


def test_cross_tenant_search_returns_nothing():
    dep = provider.DEPLOYMENT
    raw = _seeded_raw_store()
    scoped = dep.wrap_store(raw, "alpha")

    results = scoped.search("beta-secret-content")
    assert results == []


def test_cross_tenant_write_raises():
    dep = provider.DEPLOYMENT
    raw = _seeded_raw_store()
    scoped = dep.wrap_store(raw, "alpha")

    with pytest.raises(PermissionError):
        scoped.put("beta", "memo", "injected", "I should not be here")


def test_cross_tenant_delete_raises():
    dep = provider.DEPLOYMENT
    raw = _seeded_raw_store()
    scoped = dep.wrap_store(raw, "alpha")

    with pytest.raises(PermissionError):
        scoped.delete("beta:memo:secret")


def test_cross_tenant_unreachable_through_tool_path(tmp_path):
    """Even when the shared_memory tool tries a cross-tenant key, nothing comes back."""
    dep = provider.DEPLOYMENT
    raw = _seeded_raw_store()
    scoped = dep.wrap_store(raw, "alpha")

    scanner = dep.make_scanner()
    dep.make_broker(
        model_key="sk-x", tool_backing_secret="sk-y", scanner=scanner, spend_cap=None
    )
    ctx = ToolContext(
        tenant_id="alpha",
        workspace=tmp_path,
        store=scoped,
        egress_allowlist=[],
        profile=_FakeProfile(tenant_id="alpha"),
    )
    registry = dep.task_registry(ctx, scanner=scanner, credential_guard=None)

    beta_key = scoped.key_for("beta", "memo", "secret")
    result = registry.call("shared_memory", {"op": "read", "key": beta_key})
    assert "beta-secret-content-DO-NOT-LEAK" not in result


def test_own_tenant_reads_still_work(tmp_path):
    """Negative-control — make sure the scoping doesn't break own-tenant access."""
    dep = provider.DEPLOYMENT
    raw = _seeded_raw_store()
    scoped = dep.wrap_store(raw, "alpha")

    own_key = scoped.key_for("alpha", "memo", "own")
    rec = scoped.get(own_key)
    assert rec is not None
    assert rec.content == "alpha's own note"
