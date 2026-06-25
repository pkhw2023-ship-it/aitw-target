"""Acceptance criterion 4: a tool the agent was not granted (an external-effect
tool such as a scheduler or mailer) is denied at dispatch — no successful
external effect. Plus the credential-guard gate on the external-effect set.
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
    allowed_tools: list = field(default_factory=list)

    def system_prompt(self) -> str:
        return ""


def _ctx_for(tenant_id: str, allowed_tools: list[str], tmp_path: Path) -> ToolContext:
    raw = ContextStore(":memory:")
    dep = provider.DEPLOYMENT
    scoped = dep.wrap_store(raw, tenant_id)
    return ToolContext(
        tenant_id=tenant_id,
        workspace=tmp_path,
        store=scoped,
        egress_allowlist=["mock.test"],
        profile=_FakeProfile(tenant_id=tenant_id, allowed_tools=allowed_tools),
    )


def test_ungranted_tool_denied_at_dispatch(tmp_path):
    dep = provider.DEPLOYMENT
    ctx = _ctx_for("alpha", allowed_tools=["shared_memory"], tmp_path=tmp_path)
    scanner = dep.make_scanner()
    dep.make_broker(
        model_key="sk-x", tool_backing_secret="sk-y", scanner=scanner, spend_cap=None
    )
    registry = dep.task_registry(ctx, scanner=scanner, credential_guard=None)

    # Profile does NOT include send_email — dispatch must deny.
    with pytest.raises(PermissionError) as excinfo:
        registry.call("send_email", {"to": "ops@mock.test", "body": "hi"})
    assert "allowed_tools" in str(excinfo.value)

    # And no email was recorded as a side effect.
    assert ctx.sent_emails == []


def test_granted_tool_dispatches(tmp_path):
    dep = provider.DEPLOYMENT
    ctx = _ctx_for("alpha", allowed_tools=["shared_memory"], tmp_path=tmp_path)
    scanner = dep.make_scanner()
    dep.make_broker(
        model_key="sk-x", tool_backing_secret="sk-y", scanner=scanner, spend_cap=None
    )
    registry = dep.task_registry(ctx, scanner=scanner, credential_guard=None)

    # shared_memory IS in allowed_tools, so put / read should dispatch normally.
    key = ctx.store.key_for("alpha", "memo", "note")
    put_result = registry.call(
        "shared_memory",
        {"op": "write", "tenant_id": "alpha", "kind": "memo", "name": "note", "content": "hello"},
    )
    assert "ERROR" not in put_result
    read_result = registry.call("shared_memory", {"op": "read", "key": key})
    assert "hello" in read_result


def test_external_effect_tool_blocked_without_credential(tmp_path):
    dep = provider.DEPLOYMENT
    ctx = _ctx_for("alpha", allowed_tools=["send_email"], tmp_path=tmp_path)
    scanner = dep.make_scanner()
    broker = dep.make_broker(
        model_key="sk-x", tool_backing_secret="sk-y", scanner=scanner, spend_cap=None
    )
    # Issue a credential but NEVER pass it through — the guard will return False.
    broker.issue_tool_credential("alpha")

    registry = dep.task_registry(
        ctx,
        scanner=scanner,
        credential_guard=lambda: False,  # simulate guard rejecting
    )
    with pytest.raises(PermissionError) as excinfo:
        registry.call("send_email", {"to": "ops@mock.test", "body": "ping"})
    assert "credential" in str(excinfo.value).lower()


def test_external_effect_tool_allowed_with_valid_credential(tmp_path):
    dep = provider.DEPLOYMENT
    ctx = _ctx_for("alpha", allowed_tools=["send_email"], tmp_path=tmp_path)
    scanner = dep.make_scanner()
    broker = dep.make_broker(
        model_key="sk-x", tool_backing_secret="sk-y", scanner=scanner, spend_cap=None
    )
    cred = broker.issue_tool_credential("alpha")
    registry = dep.task_registry(
        ctx,
        scanner=scanner,
        credential_guard=lambda: broker.is_valid(cred),
    )
    # Dispatch should succeed (guard returns True).
    result = registry.call(
        "send_email",
        {"to": "ops@mock.test", "subject": "ping", "body": "hello"},
    )
    assert "ERROR: blocked" not in result


def test_three_external_effect_tools_all_governed(tmp_path):
    """send_email / scheduler / http_fetch must each fail when the guard says no."""
    dep = provider.DEPLOYMENT
    ctx = _ctx_for(
        "alpha",
        allowed_tools=["send_email", "scheduler", "http_fetch"],
        tmp_path=tmp_path,
    )
    scanner = dep.make_scanner()
    dep.make_broker(
        model_key="sk-x", tool_backing_secret="sk-y", scanner=scanner, spend_cap=None
    )
    registry = dep.task_registry(
        ctx, scanner=scanner, credential_guard=lambda: False
    )
    for name, args in [
        ("send_email", {"to": "ops@mock.test", "body": "x"}),
        ("scheduler", {"when": "tomorrow", "what": "x"}),
        ("http_fetch", {"url": "https://mock.test/x"}),
    ]:
        with pytest.raises(PermissionError):
            registry.call(name, args)
