"""Redaction: replace every Finding span with a vault token or an irreversible mask.

Works on text (TextBlock.text). It records old and new offsets for each replacement so the
exposure report / audit trail can map back to the original document.
Visual redaction of scanned PDFs would need word-level boxes; TextBlock only carries one
block-level bbox, so that is out of scope here (the LLM only ever sees text anyway).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Optional

from . import policy
from .models import RedactedBlock, Replacement
from .tokenizer import Tokenizer
from .vault import Vault


class RedactionError(Exception):
    """Raised on any inconsistency. The pipeline turns this into a BLOCK (fail-closed)."""


def block_id(b) -> str:
    return getattr(b, "id", None) or getattr(b, "block_id", "") or ""


class Redactor:
    def __init__(self, vault: Vault, reversible_tiers: Optional[Iterable[str]] = None):
        self.vault = vault
        self.tokenizer = Tokenizer(vault, reversible_tiers)

    # ---- one block ------------------------------------------------------------
    def redact_block(self, block, findings: List) -> RedactedBlock:
        text = block.text or ""
        spans = self._merge(text, findings, block_id(block))

        out: List[str] = []
        repls: List[Replacement] = []
        cursor = new_pos = 0
        for sp in spans:
            gap = text[cursor:sp["start"]]
            out.append(gap)
            new_pos += len(gap)

            token, reversible, tier = self.tokenizer.replacement(sp["entity"], text[sp["start"]:sp["end"]])
            out.append(token)
            repls.append(Replacement(
                entity_type=sp["entity"], tier=tier, orig_start=sp["start"], orig_end=sp["end"],
                new_start=new_pos, new_end=new_pos + len(token), token=token, reversible=reversible,
                confidence=sp["conf"], detector=sp["detector"], merged=sp["merged"]))
            new_pos += len(token)
            cursor = sp["end"]
        out.append(text[cursor:])

        return RedactedBlock(
            id=block_id(block), file=getattr(block, "file", ""),
            page_or_slide=getattr(block, "page_or_slide", 0), text="".join(out),
            source=(getattr(block, "source", None) or getattr(block, "origin", None) or "native"),
            ocr_conf=getattr(block, "ocr_conf", 1.0), bbox=getattr(block, "bbox", None),
            block_type=getattr(block, "block_type", "text") or "text",
            replacements=repls)

    @staticmethod
    def _merge(text: str, findings: List, bid: str) -> List[dict]:
        """Validate offsets, then merge overlaps into the widest span (higher tier wins)."""
        for f in findings:
            if not (0 <= f.start < f.end <= len(text)) or text[f.start:f.end] != f.text:
                raise RedactionError(f"stale or invalid offsets in block {bid!r} "
                                     f"({f.entity_type} {f.start}-{f.end})")
        merged: List[dict] = []
        for f in sorted(findings, key=lambda f: (f.start, -f.end)):
            if merged and f.start < merged[-1]["end"]:
                m = merged[-1]
                m["end"] = max(m["end"], f.end)
                m["merged"] = True
                m["conf"] = max(m["conf"], f.confidence)
                if policy.rank(policy.tier_of(f.entity_type)) > policy.rank(policy.tier_of(m["entity"])):
                    m["entity"], m["detector"] = f.entity_type, f.detector
            else:
                merged.append({"start": f.start, "end": f.end, "entity": f.entity_type,
                               "conf": f.confidence, "detector": f.detector, "merged": False})
        return merged

    # ---- many blocks ----------------------------------------------------------
    def redact(self, blocks: Iterable, findings: Iterable) -> List[RedactedBlock]:
        blocks = list(blocks)
        by_block: Dict[str, List] = defaultdict(list)
        for f in findings:
            by_block[f.block_id].append(f)
        orphans = set(by_block) - {block_id(b) for b in blocks}
        if orphans:
            raise RedactionError(f"findings reference unknown blocks: {sorted(orphans)}")
        return [self.redact_block(b, by_block.get(block_id(b), [])) for b in blocks]
