"""Credential broker.

The broker holds the run's backing secrets privately and issues short-lived per-tenant
credentials. Most importantly, on construction it registers the backing secrets onto the
``OutputScanner`` so that own-tenant reads of secret-bearing records come back redacted.
This is the load-bearing step — without it the scanner never learns the run's secret
values and the containment criterion fails.

The broker also enforces a per-tenant model-key spend cap (separate from credential
validity), which the policy registry uses as an external-effect gate.
"""

from __future__ import annotations

import secrets as _secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class EphemeralCredential:
    """A single per-tenant credential issued by the broker."""

    tenant_id: str
    token: str
    ttl_seconds: int = 900


class CredentialBroker:
    """Per-run credential issuer + scanner-secret loader.

    Construction parameters:
      * ``model_key``: the upstream LLM key the harness exposes to the deployment
      * ``tool_backing_secret``: the upstream tool-layer token (also secret)
      * ``scanner``: the OutputScanner instance the policy registry will consult
      * ``spend_cap``: per-tenant cap on model-key access (None = unlimited)

    At construction the broker calls ``scanner.register(model_key, tool_backing_secret)``
    so the scanner can redact those values out of any agent-facing surface. Every
    subsequently issued ephemeral token is also registered with the scanner.
    """

    def __init__(
        self,
        *,
        model_key: str | None = None,
        tool_backing_secret: str | None = None,
        scanner=None,
        spend_cap: int | None = None,
    ) -> None:
        # Hold backing secrets privately (no public accessor).
        self.__model_key = model_key
        self.__tool_backing_secret = tool_backing_secret
        self._scanner = scanner
        self._spend_cap = spend_cap
        self._spend: dict[str, int] = {}
        self._active: dict[str, str] = {}

        # THE load-bearing step: teach the scanner the run's secret values.
        if scanner is not None:
            scanner.register(*[v for v in (model_key, tool_backing_secret) if v])

    def issue_tool_credential(self, tenant_id: str) -> EphemeralCredential:
        """Issue a fresh ephemeral credential for ``tenant_id``.

        Each issued token is also registered with the scanner so it cannot leak in
        a tool result or model-facing surface.
        """
        token = "etk_" + _secrets.token_hex(16)
        self._active[tenant_id] = token
        if self._scanner is not None:
            self._scanner.register(token)
        return EphemeralCredential(tenant_id=tenant_id, token=token)

    def is_valid(self, cred: EphemeralCredential) -> bool:
        """Return True iff ``cred`` is the tenant's active, unexpired credential.

        TTL enforcement is left to the harness clock; ``is_valid`` reports the
        current-active-token check that the policy registry uses as a gate.
        """
        return self._active.get(cred.tenant_id) == cred.token

    def model_key(self, tenant_id: str) -> str | None:
        """Per-tenant model-key access with a spend cap. Fails closed on cap exceed."""
        if self._spend_cap is not None and self._spend.get(tenant_id, 0) >= self._spend_cap:
            raise RuntimeError("model spend cap reached")
        self._spend[tenant_id] = self._spend.get(tenant_id, 0) + 1
        return self.__model_key
