"""Single-line text cleaning for values that end up in line-based records (watermarks)."""

import unicodedata
from typing import Optional


def clean_line(value: Optional[str], limit: int = 120) -> Optional[str]:
    """One printable line: control and invisible formatting characters (line breaks, tabs,
    bidi overrides, zero-width marks) become spaces, runs of spaces collapse, and the
    result is capped at `limit` characters. None stays None."""
    if value is None:
        return None
    out = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch for ch in str(value))
    return " ".join(out.split())[:limit]
