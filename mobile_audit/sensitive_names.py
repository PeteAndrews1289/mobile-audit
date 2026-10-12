"""Small, shared key-name classifier for local-storage leads.

Only a key's spelling is classified here. The stored value still needs review.
"""

from __future__ import annotations

import re


_BENIGN_SUFFIXES = {"count", "enabled", "exists", "present", "hint", "label", "length", "type"}


def sensitive_storage_key(key: str) -> str | None:
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", separated)
    words = [item for item in re.split(r"[^a-z0-9]+", separated.lower()) if item]
    if not words or words[-1] in _BENIGN_SUFFIXES:
        return None
    for word in ("token", "password", "passwd", "passcode", "pin", "secret", "credential", "cvv", "ssn"):
        if word in words:
            return word
    pairs = set(zip(words, words[1:]))
    if {("api", "key"), ("private", "key"), ("card", "no"), ("card", "number"),
        ("credit", "card"), ("chat", "history")} & pairs:
        return "sensitive key"
    return None
