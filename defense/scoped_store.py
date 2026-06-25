"""Per-tenant scoped store.

Wraps the raw ``ContextStore`` the host hands to ``wrap_store(raw_store, tenant_id)``.
Reads / list / search are constrained to the caller's own tenant prefix; cross-tenant
writes and deletes raise ``PermissionError`` (the agent loop surfaces this as an ERROR
observation, which the harness records).

The shared_memory tool calls ``put / get / list_keys(prefix) / search / key_for``
against this object. The contract is duck-typed: this class exposes the same surface as
the raw store, but constrained.
"""

from __future__ import annotations


class ScopedStore:
    """Per-tenant wrapper. Same surface as ``aitw.context.store.ContextStore``."""

    def __init__(self, inner, tenant_id: str) -> None:
        self._inner = inner
        self._tenant = tenant_id
        self._prefix = f"{tenant_id}:"

    @staticmethod
    def key_for(tenant_id: str, kind: str, name: str) -> str:
        # Static helper — same shape as the raw store.
        return f"{tenant_id}:{kind}:{name}"

    def _owns(self, key: str) -> bool:
        return isinstance(key, str) and key.startswith(self._prefix)

    # ---- reads -----------------------------------------------------------

    def get(self, key: str):
        """Return the Record for ``key`` only if it belongs to the calling tenant."""
        if not self._owns(key):
            return None
        return self._inner.get(key)

    def get_value(self, tenant_id: str, kind: str, name: str):
        """Tenant-scoped value lookup. Cross-tenant returns None."""
        if tenant_id != self._tenant:
            return None
        return self._inner.get_value(tenant_id, kind, name)

    def list_keys(self, prefix: str = ""):
        """Return only keys owned by this tenant.

        Empty prefix is rewritten to the tenant prefix so naive enumeration cannot
        leak other tenants' key names. A non-empty prefix that does not start with
        the tenant prefix returns an empty list.
        """
        if prefix == "":
            scoped = self._prefix
        elif prefix.startswith(self._prefix):
            scoped = prefix
        else:
            return []
        return [k for k in self._inner.list_keys(scoped) if self._owns(k)]

    def search(self, substring: str):
        """Tenant-filtered substring search across record contents."""
        return [r for r in self._inner.search(substring) if self._owns(r.key)]

    def all_records(self):
        """Only the calling tenant's records. (Convenience for diagnostics.)"""
        return [r for r in self._inner.all_records() if self._owns(r.key)]

    # ---- writes ----------------------------------------------------------

    def put(self, tenant_id: str, kind: str, name: str, content: str) -> str:
        if tenant_id != self._tenant:
            raise PermissionError("cross-tenant write denied")
        return self._inner.put(tenant_id, kind, name, content)

    def delete(self, key: str) -> bool:
        if not self._owns(key):
            raise PermissionError("cross-tenant delete denied")
        return self._inner.delete(key)
