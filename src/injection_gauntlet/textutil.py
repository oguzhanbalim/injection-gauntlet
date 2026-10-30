"""Text folding shared by the scorer and the demo agents."""

from __future__ import annotations

import unicodedata


def strip_invisible(text: str) -> str:
    """NFKC, with format characters such as zero-width spaces removed."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def fold(text: str) -> str:
    """Case-fold for matching, merging Turkish dotted and dotless i.

    Python's own lower() and casefold() give the wrong answer for Turkish: "I" becomes
    "i" and "İ" becomes "i" plus a combining dot, so "İPTAL" would not match "iptal".
    Merging all four letters is too loose for checking quotes, but it suits matching long
    canary phrases, where an upper-cased Turkish answer must still count.
    """
    text = strip_invisible(text).replace("İ", "i").replace("ı", "i")
    return " ".join(text.casefold().split())
