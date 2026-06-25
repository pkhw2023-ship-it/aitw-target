"""Deployment provider — defense-layer entrypoint.

This module sits at the artifact root. The manifest (``deployment.yaml``) points the
host at ``provider:DEPLOYMENT``; the host then calls the hooks below.

The provider is a thin composition layer. The actual security logic lives in
``defense/``:

  * ``defense.scanner.OutputScanner``      — registered-secret + encoding redaction
  * ``defense.broker.CredentialBroker``    — loads secrets into the scanner; issues
                                              per-tenant ephemeral credentials
  * ``defense.scoped_store.ScopedStore``    — per-tenant isolation wrapper
  * ``defense.policy_registry.PolicyToolRegistry`` — allowlist + scan + credential guard

Imports from the host runtime are limited to the published stock symbols:
``aitw.tools.registry`` and ``aitw.context.store``. There is no dependence on any
fork-only symbol.
"""

from __future__ import annotations

from defense.broker import CredentialBroker
from defense.policy_registry import PolicyToolRegistry, register_stock_task_tools
from defense.scanner import OutputScanner
from defense.scoped_store import ScopedStore


class Deployment:
    """Defense-layer deployment provider.

    Implements the 5-hook ``DeploymentProvider`` contract structurally (duck typed).
    """

    # Neutral profile id; becomes the run-report ``deployment`` field. Not a
    # reserved built-in id, no version or condition labels.
    name = "harish-exhibition-defense"

    # ---- required hooks ---------------------------------------------------

    def wrap_store(self, raw_store, tenant_id: str) -> ScopedStore:
        """Return the per-tenant scoped store the agent's tools will call against."""
        return ScopedStore(raw_store, tenant_id)

    def make_scanner(self) -> OutputScanner:
        """Return a fresh scanner. The broker registers the run's secrets onto it."""
        return OutputScanner()

    def make_broker(
        self,
        *,
        model_key,
        tool_backing_secret,
        scanner,
        spend_cap,
    ) -> CredentialBroker:
        """Construct the credential broker.

        On construction the broker registers ``model_key`` and ``tool_backing_secret``
        onto ``scanner``, which is what lets ``OutputScanner.scan()`` redact secret
        values in any tool result.
        """
        return CredentialBroker(
            model_key=model_key,
            tool_backing_secret=tool_backing_secret,
            scanner=scanner,
            spend_cap=spend_cap,
        )

    def task_registry(
        self,
        ctx,
        *,
        scanner=None,
        credential_guard=None,
    ) -> PolicyToolRegistry:
        """Return the task-turn registry.

        Enforces the agent's allowed-tools list at dispatch, runs every tool result
        through the registered-secret scanner, and gates external-effect tools
        (send_email / scheduler / http_fetch) on ``credential_guard()``.
        """
        registry = PolicyToolRegistry(
            ctx,
            scanner=scanner,
            credential_guard=credential_guard,
        )
        return register_stock_task_tools(registry)

    # ---- optional hooks (omitted by design) -------------------------------
    #
    # ``posture_registry`` is intentionally NOT defined. When this hook is absent the
    # host derives a posture surface from ``task_registry(scanner=None)`` and supplies
    # the neutral bulletin / hardening tools itself. The harness owns bulletin CONTENT
    # on every run; we only ship the surface and the deterministic scanner that
    # protects the task turn.


DEPLOYMENT = Deployment()

__all__ = ["DEPLOYMENT", "Deployment"]
