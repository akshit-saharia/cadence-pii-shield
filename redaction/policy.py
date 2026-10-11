"""P4 policy: sensitivity tiers, handling rules and gate thresholds.

Every value can be overridden by defining the same name in the team's config.py.
"""
from __future__ import annotations

from typing import Iterable

import config


def _cfg(name, default):
    return getattr(config, name, default)


TIER_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
TIER_WEIGHT = _cfg("TIER_WEIGHT", {"LOW": 1, "MEDIUM": 3, "HIGH": 10})
TIER_LABEL = {"HIGH": "RESTRICTED", "MEDIUM": "CONFIDENTIAL", "LOW": "INTERNAL"}
NO_PII_LABEL = "NO_PII_FOUND"
UNCLASSIFIED_LABEL = "UNCLASSIFIED"

# Government IDs / payment data = HIGH. Contact + identity attributes = MEDIUM. Names alone = LOW.
ENTITY_TIER = _cfg("ENTITY_TIER", {
    "CREDIT_CARD": "HIGH", "SSN": "HIGH", "PAN": "HIGH", "PASSPORT": "HIGH",
    "DOB": "MEDIUM", "PHONE": "MEDIUM", "EMAIL": "MEDIUM", "ADDRESS": "MEDIUM",
    "PERSON": "LOW",
})

# PERSON + 2 of these in one document = a full identity profile -> escalate to HIGH.
QUASI_IDENTIFIERS = set(_cfg("QUASI_IDENTIFIERS", ["DOB", "ADDRESS", "PHONE", "EMAIL"]))

# Tiers that get reversible tokens ([PERSON_1], kept in the vault so LLM answers can be
# re-hydrated). Everything else is irreversibly masked and NEVER stored in the vault.
REVERSIBLE_TIERS = set(_cfg("REVERSIBLE_TIERS", ["LOW", "MEDIUM"]))

# ---- fail-closed gate ----
OCR_MIN_CONF = _cfg("OCR_MIN_CONF", 0.50)            # any OCR block below this blocks the file
GATE_RESIDUAL_MIN_TIER = _cfg("GATE_RESIDUAL_MIN_TIER", "LOW")   # residual PII at/above this blocks
# A page/slide with embedded images but (almost) no text was probably never scanned (needs OCR).
MIN_TEXT_CHARS_ON_IMAGE_PAGE = _cfg("MIN_TEXT_CHARS_ON_IMAGE_PAGE", 50)
BLOCK_ON_UNSCANNED_IMAGE_PAGES = _cfg("BLOCK_ON_UNSCANNED_IMAGE_PAGES", True)

# ---- OCR stage ----
MIN_OCR_IMAGE_PX = _cfg("MIN_OCR_IMAGE_PX", 40)                # smaller images (icons, bullets) cannot hold legible text
OCR_UNREADABLE_MIN_WORDS = _cfg("OCR_UNREADABLE_MIN_WORDS", 5)  # >= this many words seen, none readable -> "unreadable"
OCR_MAX_DROPPED_RATIO = _cfg("OCR_MAX_DROPPED_RATIO", None)     # e.g. 0.4; None = off until calibrated
OCR_FRAGMENT_SWEEP = _cfg("OCR_FRAGMENT_SWEEP", True)           # redact email-like fragments in OCR text


def tier_of(entity_type: str) -> str:
    """Unknown entity types are treated as HIGH (fail-closed)."""
    return ENTITY_TIER.get(entity_type, "HIGH")


def rank(tier: str) -> int:
    return TIER_RANK.get(tier, 3)


def score(findings: Iterable) -> int:
    """Weighted exposure score, capped at 100."""
    return min(100, sum(TIER_WEIGHT[tier_of(f.entity_type)] for f in findings))


def norm_conf(value) -> float:
    """OCR engines disagree on scale (Tesseract 0-100, Paddle 0-1). Normalise to 0-1."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    return v / 100.0 if v > 1.0 else v


def score_residual(residual: Iterable[dict]) -> int:
    """Same weighting as score(), for residual dicts from the gate."""
    return min(100, sum(TIER_WEIGHT[r.get("tier", "HIGH")] for r in residual))
