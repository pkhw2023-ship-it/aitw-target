"""Shape-only argument sanitizer.

Used as a second pass on tool results before the registered-secret scanner runs. The
sanitizer treats every string as sensitive and returns only shape metadata (length,
sha256 prefix, recipient domain counts, URL authority). This prevents raw payloads,
addresses, URLs, or canary values from surviving in agent-facing surfaces even when
they would not match a registered secret.

Stable sha256 PREFIX (first 16 hex chars) is used for cross-referencing without
leaking content. The sanitizer is deterministic and side-effect free.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Conservative email regex — anything x@y.tld.
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+")

# Argument names that semantically hold recipient lists.
_RECIPIENT_FIELDS = {"to", "cc", "bcc", "recipient", "recipients", "destination"}

# Argument names whose value is structurally a URL.
_URL_FIELDS = {"url", "endpoint", "href", "link"}

# Internal-domain suffix for has_external classification (mock harness uses *.test).
_INTERNAL_TLDS = (".test",)


def _sha256_prefix(value: str, n: int = 16) -> str:
    """Stable hex prefix of sha256(value)."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:n]


def redact_payload(payload: str | None, *, method: str | None = None) -> dict:
    if payload is None:
        return {"payload_length": 0, "payload_hash": None, "method": method}
    s = str(payload)
    return {
        "payload_length": len(s),
        "payload_hash": f"sha256:{_sha256_prefix(s)}",
        "method": method,
    }


def redact_thought(thought: str | None) -> dict:
    if thought is None:
        return {"length": 0, "sha256_prefix": None}
    s = str(thought)
    return {"length": len(s), "sha256_prefix": _sha256_prefix(s)}


def redact_final(final: str | None) -> dict:
    return redact_thought(final)


def redact_sink_content(content: str | None) -> dict:
    return redact_thought(content)


def _redact_recipients(value: Any) -> dict:
    if value is None:
        return {"domain_count": 0, "has_external": False, "recipient_count": 0}
    text = value if isinstance(value, str) else ", ".join(str(v) for v in value)
    addrs = _EMAIL_RE.findall(text)
    if not addrs:
        return {
            "domain_count": 0,
            "has_external": False,
            "recipient_count": 0,
            "value_length": len(text),
            "value_sha256_prefix": _sha256_prefix(text) if text else None,
        }
    domains = {a.rsplit("@", 1)[-1].lower() for a in addrs}
    has_external = any(not d.endswith(_INTERNAL_TLDS) for d in domains)
    return {
        "domain_count": len(domains),
        "has_external": has_external,
        "recipient_count": len(addrs),
    }


def _redact_url(value: Any) -> dict:
    if not value:
        return {"authority": None}
    s = str(value)
    try:
        from urllib.parse import urlparse
        p = urlparse(s)
        authority = f"{p.scheme}://{p.netloc}" if p.scheme else p.netloc
        return {"authority": authority or None, "url_length": len(s)}
    except Exception:
        return {"url_length": len(s), "sha256_prefix": _sha256_prefix(s)}


def _redact_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    s = str(value)
    return {"len": len(s), "sha256_prefix": _sha256_prefix(s)}


def redact_args(args: dict | None) -> dict:
    """Redact a tool-args dict to shape metadata only.

    Keys are preserved, values are reduced to {len, sha256_prefix} (with specialized
    handling for recipient lists and URLs).
    """
    if not args:
        return {}
    out: dict = {}
    for key, value in args.items():
        k = str(key).lower()
        if k in _RECIPIENT_FIELDS:
            out[key] = _redact_recipients(value)
        elif k in _URL_FIELDS:
            out[key] = _redact_url(value)
        elif isinstance(value, dict):
            out[key] = redact_args(value)
        elif isinstance(value, (list, tuple, set)):
            out[key] = {
                "list_len": len(value),
                "sha256_prefix": _sha256_prefix("\n".join(str(v) for v in value)),
            }
        else:
            out[key] = _redact_scalar(value)
    return out


def redact_result(result: str | None) -> dict:
    """Shape-only redaction for telemetry records (not for agent-facing surfaces)."""
    return redact_thought(result)


def alert_metadata(
    *,
    sink: str,
    step_no: int | None,
    severity: str = "alert",
    token_name: str | None = None,
) -> dict:
    record: dict = {
        "signal_fidelity_alert": f"sentinel_in_{sink}",
        "sink": sink,
        "step_no": step_no,
        "severity": severity,
    }
    if token_name:
        record["token_name"] = token_name
    return record
