"""Token format and the reversible-vs-masked decision.

Low/medium-tier PII -> reversible token ([PERSON_1]) backed by the vault, so an LLM answer
can be re-hydrated. High-tier PII (SSN, cards, PAN, passport) -> irreversible mask
([REDACTED:SSN]); those values are never given a token and never stored.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional, Tuple

from . import policy

TOKEN_RE = re.compile(r"\[([A-Z_]+)_(\d+)\]")
MASK_RE = re.compile(r"\[REDACTED:([A-Z_]+)\]")


def format_token(entity_type: str, n: int) -> str:
    return f"[{entity_type}_{n}]"


def mask(entity_type: str) -> str:
    return f"[REDACTED:{entity_type}]"


class Tokenizer:
    def __init__(self, vault, reversible_tiers: Optional[Iterable[str]] = None):
        self.vault = vault
        self.reversible_tiers = set(reversible_tiers or policy.REVERSIBLE_TIERS)

    def replacement(self, entity_type: str, value: str) -> Tuple[str, bool, str]:
        """Return (replacement text, reversible?, tier)."""
        tier = policy.tier_of(entity_type)
        if tier in self.reversible_tiers:
            return self.vault.tokenise(entity_type, value), True, tier
        return mask(entity_type), False, tier
