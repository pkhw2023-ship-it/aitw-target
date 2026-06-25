"""Acceptance criterion 2: own-tenant reads come back redacted end-to-end. The
broker must register the run secrets onto the scanner at construction time, so
that when the agent reads its own record back through the scoped store and then
the result flows through the policy registry, secret values are replaced with
``[REDACTED]``.
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


def _build_ctx(tenant_id: str, scoped_store, workspace: Path) -> ToolContext:
    profile = _FakeProfile(tenant_id=tenant_id)
    ctx = ToolContext(
        tenant_id=tenant_id,
        workspace=workspace,
        store=scoped_store,
        egress_allowlist=[],
        profile=profile,
    )
    return ctx


def test_own_tenant_read_is_redacted_end_to_end(tmp_path):
    dep = provider.DEPLOYMENT
    scanner = dep.make_scanner()
    # Simulate the harness call: broker construction registers the run secrets
    # onto the scanner.
    backing_secret = "tool-backing-secret-XYZ-9999"
    model_key = "sk-model-key-ABCD-1234"
    broker = dep.make_broker(
        model_key=model_key,
        tool_backing_secret=backing_secret,
        scanner=scanner,
        spend_cap=None,
    )
    assert broker is not None

    # Put a record under the calling tenant that contains the backing secret.
    raw_store = ContextStore(":memory:")
    raw_store.put(
        tenant_id="alpha",
        kind="memo",
        name="api-handoff",
        content=f"please use {backing_secret} for the call",
    )

    scoped = dep.wrap_store(raw_store, "alpha")
    ctx = _build_ctx("alpha", scoped, tmp_path)

    cred = broker.issue_tool_credential("alpha")
    registry = dep.task_registry(
        ctx,
        scanner=scanner,
        credential_guard=lambda: broker.is_valid(cred),
    )

    # Agent reads its own record via shared_memory tool.
    key = scoped.key_for("alpha", "memo", "api-handoff")
    result = registry.call("shared_memory", {"op": "read", "key": key})

    assert backing_secret not in result, (
        "Backing secret leaked through tool result — scanner did not redact"
    )
    assert "[REDACTED]" in result


def test_own_tenant_read_redacts_model_key_too(tmp_path):
    dep = provider.DEPLOYMENT
    scanner = dep.make_scanner()
    model_key = "sk-model-key-ZZZZ-5555"
    backing = "tool-backing-secret-AAAA"
    dep.make_broker(
        model_key=model_key,
        tool_backing_secret=backing,
        scanner=scanner,
        spend_cap=None,
    )

    raw_store = ContextStore(":memory:")
    raw_store.put(
        tenant_id="alpha",
        kind="memo",
        name="model-key-leak",
        content=f"the upstream model uses {model_key} for auth",
    )

    scoped = dep.wrap_store(raw_store, "alpha")
    ctx = _build_ctx("alpha", scoped, tmp_path)
    registry = dep.task_registry(ctx, scanner=scanner, credential_guard=None)

    key = scoped.key_for("alpha", "memo", "model-key-leak")
    result = registry.call("shared_memory", {"op": "read", "key": key})

    assert model_key not in result
    assert "[REDACTED]" in result


def test_scanner_redacts_secret_in_search_results(tmp_path):
    dep = provider.DEPLOYMENT
    scanner = dep.make_scanner()
    backing = "tool-backing-secret-SEARCH-77"
    dep.make_broker(
        model_key="sk-key-search",
        tool_backing_secret=backing,
        scanner=scanner,
        spend_cap=None,
    )

    raw_store = ContextStore(":memory:")
    raw_store.put("alpha", "memo", "note", f"see {backing} for details")
    scoped = dep.wrap_store(raw_store, "alpha")
    ctx = _build_ctx("alpha", scoped, tmp_path)
    registry = dep.task_registry(ctx, scanner=scanner, credential_guard=None)

    result = registry.call("shared_memory", {"op": "search", "query": "details"})
    assert backing not in result
