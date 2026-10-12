"""Detection engine (P3): TextBlocks in -> Findings out.

    from detection import DetectionEngine
    findings = DetectionEngine().detect(blocks)

Pipeline per block: regex + validators + context -> phones -> NER -> allowlist
-> confidence threshold -> overlap merge.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Iterable, List

import config
from schemas import Finding, TextBlock
from . import allowlist
from .recognizers import context_rules, ner, regex_patterns, validators


@dataclass
class _Cand:
    entity: str
    start: int
    end: int
    conf: float
    detector: str
    reasons: list = field(default_factory=list)


def _block_id(b) -> str:
    """Tolerate different TextBlock schemas (block_id | id)."""
    return getattr(b, "id", None) or getattr(b, "block_id", "") or ""


def _block_origin(b) -> str:
    """Tolerate different TextBlock schemas (origin | source). Anything 'ocr' counts as OCR."""
    v = getattr(b, "source", None) or getattr(b, "origin", None) or "native"
    return "ocr" if str(v).lower() == "ocr" else "native"


def _clamp(x: float) -> float:
    return max(0.0, min(0.99, round(x, 2)))


class DetectionEngine:
    def __init__(self, use_ner: bool = True):
        self.use_ner = use_ner

    # ---- candidate generators -------------------------------------------------
    def _regex(self, text):
        out = []
        for p in regex_patterns.PATTERNS:
            for m in p.regex.finditer(text):
                s, e = m.span()
                conf, reasons = p.base_conf, [f"pattern:{p.name}"]
                check = validators.VALIDATORS.get(p.entity)
                if check:
                    if check(m.group(0)):
                        conf += config.VALIDATOR_BOOST
                        reasons.append("validator_pass")
                    else:
                        conf -= config.VALIDATOR_PENALTY
                        reasons.append("validator_fail")
                conf, extra, hit = context_rules.adjust(p.entity, text, s, e, conf)
                if p.requires_context and not hit:
                    continue
                out.append(_Cand(p.entity, s, e, conf, "regex", reasons + extra))
        return out

    def _phones(self, text):
        out = []
        for s, e, validated in regex_patterns.find_phones(text):
            conf = 0.70 if validated else 0.35
            reasons = ["phonenumbers_valid" if validated else "pattern:phone_fallback"]
            conf, extra, hit = context_rules.adjust("PHONE", text, s, e, conf)
            if not validated and not hit:
                continue
            out.append(_Cand("PHONE", s, e, conf, "phonenumbers" if validated else "regex", reasons + extra))
        return out

    def _ner(self, text):
        return [_Cand(en, s, e, c, det, r) for en, s, e, c, det, r in ner.find_entities(text)]

    # ---- per block -----------------------------------------------------------
    def detect_block(self, block: TextBlock) -> List[Finding]:
        text = block.text or ""
        if not text.strip():
            return []

        cands = self._regex(text) + self._phones(text)
        if self.use_ner:
            cands += self._ner(text)

        # 1) allowlist (EMP-/RSK-/INC-/ISS- IDs, card last-four)
        spans = allowlist.allowlisted_spans(text)
        cands = [c for c in cands if not allowlist.covered(c.start, c.end, spans)]

        # 2) confidence threshold (OCR gets a lower bar: fail-closed on noisy text)
        origin = _block_origin(block)
        discount = config.OCR_THRESHOLD_DISCOUNT if origin == "ocr" else 0.0
        cands = [c for c in cands if _clamp(c.conf) >= round(config.min_conf(c.entity) - discount, 2)]

        # 3) overlap merge: best entity wins, no overlapping spans leave this stage
        cands.sort(key=lambda c: (config.priority(c.entity), -c.conf, -(c.end - c.start)))
        kept = []
        for c in cands:
            if all(c.end <= k.start or c.start >= k.end for k in kept):
                kept.append(c)
        kept.sort(key=lambda c: c.start)

        return [Finding(block_id=_block_id(block), entity_type=c.entity, start=c.start, end=c.end,
                        text=text[c.start:c.end], confidence=_clamp(c.conf), detector=c.detector,
                        origin=origin, reasons=c.reasons) for c in kept]

    def detect(self, blocks: Iterable[TextBlock]) -> List[Finding]:
        findings = []
        for b in blocks:
            findings.extend(self.detect_block(b))
        return findings

    def detect_text(self, text: str, origin: str = "native", block_id: str = "adhoc") -> List[Finding]:
        return self.detect_block(TextBlock(id=block_id, file="", page_or_slide=0, text=text,
                                           bbox=None, source=origin, ocr_conf=1.0))


if __name__ == "__main__":
    # python -m detection.engine data/sample_blocks.json   -> prints Findings as JSON
    if len(sys.argv) > 1:
        raw = json.load(open(sys.argv[1], encoding="utf-8"))
        blocks = [TextBlock(**{k: v for k, v in d.items() if k in TextBlock.__dataclass_fields__}) for d in raw]
    else:
        blocks = [TextBlock("demo", "demo.txt", 1, "Name: Priya Nair, DOB: 14/03/1989, SSN 123-45-6789, "
                            "email priya@example.com, phone +91 98765 43210, EMP-38104", None, "native", 1.0)]
    print(json.dumps([f.to_dict() for f in DetectionEngine().detect(blocks)], indent=2))
