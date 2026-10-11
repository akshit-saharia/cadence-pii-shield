"""Fail-closed gate: text reaches the LLM only if every check passes.

Default answer is BLOCK. A file is ALLOWed only when ALL of these hold:
  PIPELINE_ERROR      no detection / redaction error occurred
  NO_TEXT_EXTRACTED   at least one block with text was extracted
  UNSCANNED_IMAGE_PAGE every page/slide holding images either has text or has OCR blocks
  LOW_OCR_CONFIDENCE  every OCR block with text has ocr_conf >= OCR_MIN_CONF
  VALUE_SURVIVED      no detected value still appears anywhere in the redacted text
  RESCAN_FAILED       the independent re-scan of the redacted text ran
  RESIDUAL_PII        the re-scan finds no PII (tokens/masks are ignored)
Residual details never contain raw values, so the report stays safe to share.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Callable, Iterable, List, Optional

from . import policy
from .models import GateDecision
from .redactor import block_id
from .tokenizer import MASK_RE, TOKEN_RE


def _is_ocr(b) -> bool:
    return str(getattr(b, "source", None) or getattr(b, "origin", None) or "native").lower() == "ocr"


def _token_spans(text: str):
    return [m.span() for rx in (TOKEN_RE, MASK_RE) for m in rx.finditer(text)]


def _overlaps(s: int, e: int, spans) -> bool:
    return any(s < te and e > ts for ts, te in spans)


class FailClosedGate:
    def __init__(self, detect_fn: Callable, ocr_min_conf: Optional[float] = None,
                 residual_min_tier: Optional[str] = None):
        """detect_fn(text, origin=..., block_id=...) -> List[Finding]  (e.g. engine.detect_text)."""
        self.detect_fn = detect_fn
        self.ocr_min_conf = policy.OCR_MIN_CONF if ocr_min_conf is None else ocr_min_conf
        self.min_rank = policy.rank(residual_min_tier or policy.GATE_RESIDUAL_MIN_TIER)

    def evaluate(self, file: str, original_blocks: Iterable, redacted_blocks: Iterable,
                 findings: Iterable, errors: Iterable[str] = (), images: Iterable = ()) -> GateDecision:
        original_blocks, redacted_blocks = list(original_blocks), list(redacted_blocks)
        findings, errors = list(findings), list(errors)
        reasons: List[dict] = []
        warnings: List[str] = []
        residual: List[dict] = []

        def block(code: str, message: str, **extra):
            reasons.append({"code": code, "message": message, **extra})

        for err in errors:
            block("PIPELINE_ERROR", err)

        if not errors and not any((b.text or "").strip() for b in original_blocks):
            block("NO_TEXT_EXTRACTED", "No text was extracted, so nothing can be verified")

        self._coverage(original_blocks, list(images), block, warnings)

        for b in original_blocks:
            if not _is_ocr(b):
                continue
            if not (b.text or "").strip():
                warnings.append(f"empty OCR block {block_id(b)!r} (nothing to send)")
                continue
            conf = policy.norm_conf(getattr(b, "ocr_conf", 1.0))
            if conf < self.ocr_min_conf:
                block("LOW_OCR_CONFIDENCE",
                      f"OCR confidence {conf:.2f} < {self.ocr_min_conf:.2f}; detection recall unreliable",
                      block_id=block_id(b), ocr_conf=round(conf, 2))

        if not errors:                       # redacted output is only trustworthy without errors
            self._values_survived(findings, redacted_blocks, block)
            self._rescan(redacted_blocks, residual, block)

        return GateDecision(file=file, decision="BLOCK" if reasons else "ALLOW",
                            reasons=reasons, warnings=warnings, residual=residual)

    # ---- checks ---------------------------------------------------------------
    @staticmethod
    def _coverage(blocks, images, block, warnings) -> None:
        """Pages with images but no text/OCR were never inspected: we cannot vouch for them."""
        if not images:
            return
        chars, ocr_pages = Counter(), set()
        for b in blocks:
            t = (b.text or "").strip()
            chars[getattr(b, "page_or_slide", 0)] += len(t)
            if t and _is_ocr(b):
                ocr_pages.add(getattr(b, "page_or_slide", 0))
        per_page = Counter(getattr(i, "page_or_slide", 0) for i in images)
        for page, n in sorted(per_page.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
            where = "The document" if page is None else f"Page/slide {page}"
            covered = page in ocr_pages or chars[page] >= policy.MIN_TEXT_CHARS_ON_IMAGE_PAGE
            if covered:
                warnings.append(f"{where}: {n} embedded image(s) not text-scanned")
            elif policy.BLOCK_ON_UNSCANNED_IMAGE_PAGES:
                block("UNSCANNED_IMAGE_PAGE",
                      f"{where} has {n} image(s) and almost no text; content could not be scanned (no OCR, or unreadable)",
                      page_or_slide=page)
            else:
                warnings.append(f"{where}: {n} image(s), almost no text, not scanned")

    @staticmethod
    def _values_survived(findings, redacted_blocks, block) -> None:
        corpus = "\n".join(rb.text for rb in redacted_blocks)
        seen = set()
        for f in findings:
            key = (f.text or "").lower()
            if not key or key in seen:
                continue
            seen.add(key)
            if re.search(r"(?<!\w)" + re.escape(f.text) + r"(?!\w)", corpus, re.I):
                block("VALUE_SURVIVED", f"A detected {f.entity_type} value is still present after redaction",
                      entity_type=f.entity_type, block_id=f.block_id)

    def _rescan(self, redacted_blocks, residual: List[dict], block) -> None:
        for rb in redacted_blocks:
            if not rb.text.strip():
                continue
            try:
                hits = self.detect_fn(rb.text, origin=rb.source, block_id=rb.id)
            except Exception as exc:         # re-scan could not run -> cannot vouch for the text
                block("RESCAN_FAILED", f"{type(exc).__name__}: {exc}", block_id=rb.id)
                return
            spans = _token_spans(rb.text)
            for f in hits:
                tier = policy.tier_of(f.entity_type)
                if policy.rank(tier) < self.min_rank or _overlaps(f.start, f.end, spans):
                    continue
                residual.append({"block_id": rb.id, "entity_type": f.entity_type, "tier": tier,
                                 "start": f.start, "end": f.end,
                                 "confidence": f.confidence, "detector": f.detector})
        if residual:
            block("RESIDUAL_PII", f"{len(residual)} PII item(s) still detected after redaction")
