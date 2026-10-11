"""Exposure report: what was found, what was done, what the LLM was allowed to see.

The report never contains raw PII values - only entity types, tiers, locations, counts and tokens -
so it is safe to show in the demo and to share.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

from . import policy
from .vault import _normalise


def _metadata_keys(md, prefix="") -> list:
    """Names (never values) of non-empty metadata fields. Metadata is withheld from the LLM."""
    keys = []
    for k, v in (md or {}).items():
        if isinstance(v, dict):
            keys += _metadata_keys(v, f"{prefix}{k}.")
        elif v not in (None, "", [], {}):
            keys.append(f"{prefix}{k}")
    return sorted(keys)


def _file_entry(fr) -> dict:
    page_of = {getattr(b, "id", None) or getattr(b, "block_id", ""): getattr(b, "page_or_slide", 0)
               for b in fr.blocks}
    repl_by_block = {rb.id: rb.replacements for rb in fr.redacted_blocks}

    findings_out, by_location = [], Counter()
    for f in fr.findings:
        page = page_of.get(f.block_id, 0)
        by_location["document" if page is None else f"p{page}"] += 1
        token, reversible = None, None
        for r in repl_by_block.get(f.block_id, []):
            if r.orig_start <= f.start and f.end <= r.orig_end:
                token, reversible = r.token, r.reversible
                break
        findings_out.append({
            "block_id": f.block_id, "page_or_slide": page, "entity_type": f.entity_type,
            "tier": policy.tier_of(f.entity_type), "start": f.start, "end": f.end,
            "confidence": f.confidence, "detector": f.detector, "origin": f.origin,
            "replacement_token": token, "reversible": reversible})

    repls = [r for rb in fr.redacted_blocks for r in rb.replacements]
    ocr_confs = [policy.norm_conf(b.ocr_conf) for b in fr.blocks
                 if str(getattr(b, "source", "native")).lower() == "ocr"]
    released = fr.decision.allowed
    residual_score = policy.score_residual(fr.decision.residual)
    return {
        "file": fr.file,
        "decision": fr.decision.decision,
        "text_released_to_llm": released,
        "classification": fr.classification.to_dict(),
        "exposure_score_before": fr.classification.risk_score,
        "exposure_score_after": residual_score if released else 0,
        "blocks": len(fr.blocks),
        "ocr_blocks": len(ocr_confs),
        "min_ocr_conf": round(min(ocr_confs), 2) if ocr_confs else None,
        "pii_by_entity": fr.classification.counts_by_entity,
        "pii_by_tier": fr.classification.counts_by_tier,
        "pii_distinct_values": len({(f.entity_type, _normalise(f.entity_type, f.text)) for f in fr.findings}),
        "images_found": (getattr(fr, "ocr", None) or {}).get("images_total", len(getattr(fr, "images", []) or [])),
        "images_unscanned": len(getattr(fr, "images", []) or []),
        "ocr": getattr(fr, "ocr", None) or {},
        "extraction_warnings": list(getattr(fr, "extraction_warnings", []) or []),
        "metadata_withheld": _metadata_keys(getattr(fr, "metadata", {})),
        "pii_by_location": dict(by_location),
        "redaction": {
            "reversible_tokens": sum(1 for r in repls if r.reversible),
            "irreversible_masks": sum(1 for r in repls if not r.reversible),
            "merged_spans": sum(1 for r in repls if r.merged)},
        "gate": {"reasons": fr.decision.reasons, "warnings": fr.decision.warnings,
                 "residual": fr.decision.residual},
        "findings": findings_out,
    }


def build_report(result) -> dict:
    files = [_file_entry(fr) for fr in result.files]
    by_entity, by_tier = Counter(), Counter()
    for f in files:
        by_entity.update(f["pii_by_entity"])
        by_tier.update(f["pii_by_tier"])
    total = sum(by_entity.values())
    allowed = [f for f in files if f["decision"] == "ALLOW"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session_id": result.vault.session_id,
        "vault": result.vault.status(),
        "summary": {
            "files_total": len(files),
            "files_allowed": len(allowed),
            "files_blocked": len(files) - len(allowed),
            "pii_items_found": total,
            "pii_distinct_values": sum(f["pii_distinct_values"] for f in files),
            "pii_by_entity": dict(by_entity),
            "pii_by_tier": dict(by_tier),
            "pii_to_llm_without_protection": total,
            "pii_to_llm_with_protection": sum(len(f["gate"]["residual"]) for f in allowed),
            "reversible_tokens": sum(f["redaction"]["reversible_tokens"] for f in files),
            "irreversible_masks": sum(f["redaction"]["irreversible_masks"] for f in files),
        },
        "files": files,
    }


def to_markdown(report: dict) -> str:
    s = report["summary"]
    v = report["vault"]
    lines = [
        "# PII Exposure Report", "",
        f"Session `{report['session_id']}` - generated {report['generated_at']}", "",
        "## Summary", "",
        "| Metric | Value |", "|---|---|",
        f"| Files processed | {s['files_total']} |",
        f"| Allowed to LLM / Blocked | {s['files_allowed']} / {s['files_blocked']} |",
        f"| PII items found (distinct values) | {s['pii_items_found']} ({s['pii_distinct_values']}) |",
        f"| PII reaching LLM, no protection | {s['pii_to_llm_without_protection']} |",
        f"| PII reaching LLM, with protection | {s['pii_to_llm_with_protection']} |",
        f"| Reversible tokens / irreversible masks | {s['reversible_tokens']} / {s['irreversible_masks']} |",
        f"| Vault | {v['entries']} entries, {'encrypted' if v['encrypted'] else 'NOT encrypted'} |",
        "", "## Files", "",
        "| File | Classification | PII found | Score before -> after | Gate |", "|---|---|---|---|---|"]
    for f in report["files"]:
        n = sum(f["pii_by_entity"].values())
        lines.append(f"| {f['file']} | {f['classification']['label']} | {n} | "
                     f"{f['exposure_score_before']} -> {f['exposure_score_after']} | {f['decision']} |")
    for f in report["files"]:
        lines += ["", f"### {f['file']} - {f['decision']}", ""]
        if f["pii_by_entity"]:
            lines.append("- PII: " + ", ".join(f"{k} x{n}" for k, n in sorted(f["pii_by_entity"].items())))
        if f["classification"]["escalated"]:
            lines.append("- Escalated to RESTRICTED: " + "; ".join(f["classification"]["reasons"][1:]))
        for r in f["gate"]["reasons"]:
            lines.append(f"- BLOCKED [{r['code']}]: {r['message']}")
        for w in f["gate"]["warnings"]:
            lines.append(f"- warning: {w}")
        for w in f["extraction_warnings"][:5]:
            lines.append(f"- extraction: {w}")
        if len(f["extraction_warnings"]) > 5:
            lines.append(f"- extraction: ... and {len(f['extraction_warnings']) - 5} more")
        o = f.get("ocr") or {}
        if o.get("available") is False:
            lines.append(f"- OCR: not available, {o.get('images_total', 0)} image(s) were not scanned")
        elif o.get("images_total"):
            lines.append(f"- OCR: {o['images_scanned']} image(s) scanned, {o['images_skipped_small']} too small, "
                         f"{o['images_unvouched']} unreadable/unverified, {o['words_dropped']} low-confidence word(s) dropped, "
                         f"{o['sweep_fragments']} email-like fragment(s) redacted")
        if f["metadata_withheld"]:
            lines.append("- document metadata withheld from LLM: " + ", ".join(f["metadata_withheld"]))
        if f["decision"] == "ALLOW":
            lines.append("- Redacted text released to the LLM.")
    return "\n".join(lines) + "\n"


def write_report(report: dict, out_dir) -> Tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jp, mp = out / "exposure_report.json", out / "exposure_report.md"
    jp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    mp.write_text(to_markdown(report), encoding="utf-8")
    return jp, mp
