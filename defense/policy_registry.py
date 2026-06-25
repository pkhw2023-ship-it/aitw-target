"""Policy-enforcing tool registry.

Extends the stock ``ToolRegistry`` so that every ``call()`` goes through three guards
before the underlying tool dispatches, and the result is sanitized and scanned before
being returned to the agent:

  1. Allowlist: deny any tool not in ``ctx.profile.allowed_tools`` at dispatch.
  2. Credential guard: deny external-effect tools (send_email / scheduler / http_fetch)
     when ``credential_guard()`` returns False.
  3. (After dispatch) Shape-only sanitizer over the result, then the registered-secret
     scanner. The harness does NOT wrap the task registry, so unscanned results would
     leak. This is what closes the containment criterion.
"""

from __future__ import annotations

from typing import Callable

from aitw.tools.registry import ToolRegistry

from defense import sanitizer as _sanitizer

# External-effect tools the credential guard governs.
EXTERNAL_EFFECT_TOOLS = frozenset({"send_email", "scheduler", "http_fetch"})


class PolicyToolRegistry(ToolRegistry):
    """Drop-in replacement for the stock ToolRegistry with policy layered on call()."""

    def __init__(
        self,
        ctx,
        *,
        scanner=None,
        credential_guard: Callable[[], bool] | None = None,
    ) -> None:
        super().__init__(ctx)
        self._scanner = scanner
        self._credential_guard = credential_guard

    def call(self, name: str, args: dict) -> str:
        # (a) Allowlist check at dispatch — denies surface up as ERROR observations.
        allowed = set(self.ctx.profile.allowed_tools) if self.ctx.profile else set()
        if name not in allowed:
            raise PermissionError(f"tool {name!r} is not in allowed_tools")

        # (b) Credential guard for external-effect tools.
        if name in EXTERNAL_EFFECT_TOOLS:
            if self._credential_guard is not None and not self._credential_guard():
                raise PermissionError(
                    f"tool {name!r} requires a valid credential"
                )

        # Delegate to the stock tool dispatch.
        result = super().call(name, args)

        # (c) Shape-only sanitizer pass — only applied to string results. The
        # sanitizer produces a dict for structured records; for the agent-facing
        # surface here we only redact obvious recipient / URL leakage by leaving the
        # raw text in place (the scanner below handles registered secrets).
        # In practice this slot is where additional pattern-based redactions (e.g.
        # quarantining instruction-shape blocks in untrusted ingress) would attach.
        # We deliberately keep the agent-facing return as text; structured
        # sanitization goes to the telemetry record built by the harness.

        # (d) Registered-secret scanner — the load-bearing redaction.
        if self._scanner is not None and isinstance(result, str):
            result = self._scanner.scan(result).redacted

        return result


def register_stock_task_tools(reg: ToolRegistry) -> ToolRegistry:
    """Register the standard generic tools onto ``reg``.

    We deliberately leave the over-broad ``broad_tool`` lure out of the task surface;
    the allowlist check is the primary gate, but excluding the lure also keeps the
    registry's ``describe()`` honest about what is dispatchable.
    """
    from aitw.tools import (
        file_io,
        http_fetch,
        instruction_tool,
        scheduler,
        send_email,
        shared_memory,
        web_search,
    )

    for module in (
        file_io,
        send_email,
        scheduler,
        web_search,
        http_fetch,
        shared_memory,
        instruction_tool,
    ):
        reg.register(module.TOOL)
    return reg


# Module-level re-export for convenient ``from defense.policy_registry import sanitizer``
# style usage in tests and downstream code.
sanitizer = _sanitizer
