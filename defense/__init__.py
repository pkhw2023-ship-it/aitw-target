"""Defense layer package.

A small set of runtime security modules that compose into a DeploymentProvider:

  * scanner.py        — OutputScanner (registered-secret + encoding redaction)
  * broker.py         — CredentialBroker (loads secrets into the scanner)
  * scoped_store.py   — ScopedStore (per-tenant isolation wrapper over the raw store)
  * policy_registry.py — PolicyToolRegistry (allowlist + sanitize + scan + credential guard)
  * sanitizer.py      — shape-only argument sanitizer (no raw payload leaks)
  * bulletin.py       — validates the operational bulletin against the vendored schema

This package never modifies stock aitw; it only wraps the seams the host exposes.
"""

__all__ = []
