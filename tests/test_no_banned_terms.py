"""Banned-term sweep over the artifact. Catches any methodology language that
slipped into the production-style package.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

BANNED_TERMS = [
    "prong",
    r"\bsurprise\b",
    "forewarn",
    "forewarned",
    r"\btreatment\b",
    r"\bbenchmark\b",
    r"\bexperiment\b",
    r"\bches\b",
    r"\bchess\b",
    "hardened arm",
    "attack notice",
    "warning mode",
    "scored arm",
    "test arm",
    r"\bred team\b",
    r"\bblue team\b",
]

# Files / directories we never scan (the .venv, build outputs, the test file
# itself which legitimately contains the banned-term list).
SKIP_PATHS = {
    ".venv",
    ".git",
    "__pycache__",
    "build",
    "dist",
    "tests/test_no_banned_terms.py",
    "harish_exhibition_defense.egg-info",
}


def _files_to_scan():
    out = []
    for p in REPO_ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO_ROOT)
        rel_str = str(rel)
        if any(part in SKIP_PATHS for part in rel.parts) or rel_str in SKIP_PATHS:
            continue
        if p.suffix in {".py", ".md", ".yaml", ".yml", ".json", ".toml", ".txt"}:
            out.append(p)
    return out


def test_no_banned_terms_in_artifact():
    offenders = []
    for path in _files_to_scan():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for term in BANNED_TERMS:
            for m in re.finditer(term, text, flags=re.IGNORECASE):
                ln = text[: m.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{ln} matches /{term}/")
    assert offenders == [], "Banned terms found:\n" + "\n".join(offenders)
