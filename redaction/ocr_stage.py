"""OCR stage: ExtractedImage bytes -> P2's ocr() -> TextBlocks, plus a verdict per image.

P2's ocr() wants an image FILE PATH, P1 hands over BYTES, and image_router.py is empty, so this module is
the glue and the minimal router:
  * images too small to hold legible text are skipped (icons, bullets)       -> counted as vouched
  * identical images are OCR'd once (a logo repeated on 40 slides)
  * an image OCR cannot decode becomes a warning + "unscanned"               (EMF/WMF logos etc.)
  * any other OCR failure (Tesseract missing, crash) becomes an ERROR        -> the file is BLOCKED
  * if P2's ocr_with_stats() exists we can tell "no text" (logo/photo) from "text we could not read"
    (words seen, none above the confidence cut-off); with plain ocr() we only know blocks/no blocks.

"Unscanned" images are what the gate's coverage rule looks at: an unscanned image on a page with almost
no other text blocks the file.

Also here: the OCR fragment sweep. P2 drops words below 0.40 confidence, so a mangled email can come out
as 'daniel.kim@acme' - too broken for the detector, still personal data. We redact anything email-like
in OCR text that P3 did not already cover.
"""
from __future__ import annotations

import dataclasses
import hashlib
import io
import os
import re
import tempfile
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from schemas import Finding

from . import policy

OcrFn = Callable[[str, str, Optional[int]], Tuple[list, Optional[dict]]]   # (path, file, page) -> (blocks, stats|None)


@dataclass
class OcrOutcome:
    blocks: List = field(default_factory=list)
    unscanned_images: List = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


def default_ocr_fn() -> Optional[OcrFn]:
    """P2's OCR if importable, else None (the pipeline then reports OCR as unavailable)."""
    try:
        from ocr import ocr_pipeline as op
    except Exception:
        return None
    if hasattr(op, "ocr_with_stats"):
        return lambda path, file, page: op.ocr_with_stats(path, file, page)
    return lambda path, file, page: (op.ocr(path, file, page), None)


def _dims(data: bytes) -> Optional[Tuple[int, int]]:
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            return im.size
    except Exception:
        return None


def _suffix(image) -> str:
    ext = str((getattr(image, "metadata", None) or {}).get("ext") or "png").lstrip(".").lower()
    return "." + (ext if ext.isalnum() else "png")


def _ocr_once(data: bytes, image, file: str, ocr_fn: OcrFn):
    """Run OCR on one image's bytes. Returns (status, blocks, stats, message)."""
    fd, path = tempfile.mkstemp(suffix=_suffix(image), prefix="p4_ocr_")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            blocks, stats = ocr_fn(path, file, getattr(image, "page_or_slide", None))
            return "ok", list(blocks), stats, ""
        except ValueError as exc:                      # P2's preprocess() raises this for undecodable images
            return "undecodable", [], None, str(exc)
        except Exception as exc:
            return "error", [], None, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _vouch(stats: Optional[dict], n_blocks: int) -> Tuple[bool, Optional[str]]:
    """Can we vouch that nothing readable was left behind in this image?"""
    if stats is None:                                  # plain ocr(): no visibility into dropped words
        return n_blocks > 0, None if n_blocks else "OCR returned no text (cannot tell blank from unreadable)"
    total, kept, dropped = stats["words_total"], stats["words_kept"], stats["words_dropped"]
    if kept == 0 and dropped >= policy.OCR_UNREADABLE_MIN_WORDS:
        return False, f"{dropped} word(s) seen but none readable (image resolution too low?)"
    ratio = dropped / total if total else 0.0
    if policy.OCR_MAX_DROPPED_RATIO is not None and ratio > policy.OCR_MAX_DROPPED_RATIO:
        return False, f"{dropped} of {total} words dropped as low-confidence ({ratio:.0%})"
    return True, None


def run_ocr(images: Iterable, ocr_fn: OcrFn, file: str = "") -> OcrOutcome:
    out = OcrOutcome()
    cache: Dict[str, tuple] = {}
    s = dict(available=True, images_total=0, images_scanned=0, images_skipped_small=0, images_undecodable=0,
             images_unvouched=0, words_total=0, words_dropped=0, ocr_blocks=0, sweep_fragments=0)

    for im in images:
        s["images_total"] += 1
        page = getattr(im, "page_or_slide", None)
        where = "document" if page is None else f"page/slide {page}"
        data = getattr(im, "image_bytes", b"") or b""
        if not data:
            s["images_skipped_small"] += 1
            continue
        dims = _dims(data)
        if dims and min(dims) < policy.MIN_OCR_IMAGE_PX:
            s["images_skipped_small"] += 1
            continue

        key = hashlib.sha256(data).hexdigest()
        if key not in cache:
            cache[key] = _ocr_once(data, im, file, ocr_fn)
        status, tmpl_blocks, stats, msg = cache[key]

        if status == "undecodable":
            s["images_undecodable"] += 1
            out.warnings.append(f"OCR: image on {where} could not be decoded ({msg})")
            out.unscanned_images.append(im)
            continue
        if status == "error":
            out.errors.append(f"OCR failed on image on {where}: {msg}")
            out.unscanned_images.append(im)
            continue

        s["images_scanned"] += 1
        for b in tmpl_blocks:                          # repeated image -> fresh blocks for this page
            out.blocks.append(dataclasses.replace(b, id=str(uuid.uuid4()), file=file, page_or_slide=page))
        if stats:
            s["words_total"] += stats["words_total"]
            s["words_dropped"] += stats["words_dropped"]
        vouched, note = _vouch(stats, len(tmpl_blocks))
        if not vouched:
            s["images_unvouched"] += 1
            out.unscanned_images.append(im)
        if note:
            out.warnings.append(f"OCR: image on {where}: {note}")
        elif stats and stats["words_dropped"]:
            out.warnings.append(f"OCR: image on {where}: {stats['words_dropped']} of "
                                f"{stats['words_total']} words dropped as low-confidence")

    s["ocr_blocks"] = len(out.blocks)
    out.summary = s
    return out


# ---- fragment sweep ----------------------------------------------------------------
_EMAIL_FRAGMENT = re.compile(r"[\w.+\-]*@[\w.\-]*\w")


def email_fragment_findings(blocks: Iterable, findings: Iterable[Finding]) -> List[Finding]:
    """Email-like text in OCR blocks that P3 did not already flag (e.g. 'daniel.kim@acme')."""
    by_block = defaultdict(list)
    for f in findings:
        by_block[f.block_id].append(f)
    out: List[Finding] = []
    for b in blocks:
        if str(getattr(b, "source", "") or "").lower() != "ocr":
            continue
        text = b.text or ""
        bid = getattr(b, "id", None) or getattr(b, "block_id", "")
        for m in _EMAIL_FRAGMENT.finditer(text):
            st, en = m.span()
            if any(st < f.end and en > f.start for f in by_block[bid]):
                continue
            out.append(Finding(block_id=bid, entity_type="EMAIL", start=st, end=en, text=text[st:en],
                               confidence=0.5, detector="ocr_sweep", origin="ocr",
                               reasons=["ocr_fragment:email_like"]))
    return out
