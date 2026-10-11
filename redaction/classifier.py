"""Sensitivity classification: Findings -> per-document label, tier and risk score."""
from __future__ import annotations

from collections import Counter
from typing import Iterable

from . import policy
from .models import Classification


def classify(findings: Iterable, failed: bool = False) -> Classification:
    findings = list(findings)
    if failed:
        return Classification(label=policy.UNCLASSIFIED_LABEL, tier=None, risk_score=0,
                              reasons=["processing_failed"])
    if not findings:
        return Classification(label=policy.NO_PII_LABEL, tier=None, risk_score=0,
                              reasons=["no_findings"])

    by_entity = Counter(f.entity_type for f in findings)
    by_tier = Counter(policy.tier_of(f.entity_type) for f in findings)
    tier = max(by_tier, key=policy.rank)
    reasons = [f"highest_tier:{tier}"]
    escalated = False

    present = set(by_entity)
    if (policy.rank(tier) < policy.rank("HIGH") and "PERSON" in present
            and len(present & policy.QUASI_IDENTIFIERS) >= 2):
        tier, escalated = "HIGH", True
        reasons.append("identity_bundle: PERSON + 2 or more quasi-identifiers")

    return Classification(label=policy.TIER_LABEL[tier], tier=tier,
                          risk_score=policy.score(findings),
                          counts_by_entity=dict(by_entity), counts_by_tier=dict(by_tier),
                          escalated=escalated, reasons=reasons)
