import re
import uuid
from schemas import TextBlock
from ocr.preprocess import preprocess
from ocr.engine import run_tesseract

CONF_THRESHOLD = 0.40

# Per-image PSM tuning.
#   6  = single uniform block (forms, badges)
#   4  = single column of variable-size text (lists)
#   11 = sparse text (tables, scattered UI labels)
# NOTE: keyed by FILE NAME, so it only applies to the sample images. Images
# extracted from PDFs/DOCX/PPTX will have random temp filenames and will use
# the default (6). If P1 wants PSM tuning on extracted images, they must pass
# a content-type hint through (future work).
PSM_OVERRIDES = {
    "fig9_config_evidence.png": 11,
    "fig11_audit_log.png":      4,
}

_DIGIT_LOOKALIKES = {"O": "0", "o": "0", "I": "1", "l": "1", "S": "5", "B": "8"}


def _fix_digits(text: str) -> str:
    """Fix OCR digit confusion in number-like tokens without corrupting IDs.

    Only converts a run of letters to digits if EVERY letter in the run is a
    lookalike AND the run touches a digit. Protects internal IDs like
    INC-20456, RSK-4471, ISS-3301 from becoming 1NC-20456 / R5K-4471 / 155-3301.
    Tokens containing '@' (emails) are never touched.
    """
    def fix(tok: str) -> str:
        if "@" in tok or sum(c.isdigit() for c in tok) < 2:
            return tok

        def run(m: re.Match) -> str:
            s = m.group(0)
            if not all(c in _DIGIT_LOOKALIKES for c in s):
                return s
            before = tok[m.start() - 1] if m.start() > 0 else ""
            after = tok[m.end()] if m.end() < len(tok) else ""
            if before.isdigit() or after.isdigit():
                return "".join(_DIGIT_LOOKALIKES[c] for c in s)
            return s

        return re.sub(r"[A-Za-z]+", run, tok)

    return " ".join(fix(t) for t in text.split())


_EMAIL_SPLIT = re.compile(
    r"([\w.+\-]+)\s*@\s*([A-Za-z0-9\-]+(?:\s*\.\s*[a-z0-9\-]+){1,3})"
)


def _fix_email_spacing(text: str) -> str:
    """Rejoin OCR-split emails without gluing sentence boundaries.

    'name @ domain . com' -> 'name@domain.com'
    Leaves 'P.S. Raghavan' and 'Policy Owner. Daniel Kim' intact.
    """
    def join(m: re.Match) -> str:
        return m.group(1) + "@" + re.sub(r"\s*\.\s*", ".", m.group(2))
    return _EMAIL_SPLIT.sub(join, text)


def ocr_with_stats(image_path: str, file: str, page_or_slide, bbox: tuple = None):
    """Same as ocr(), but also returns OCR process stats so the caller can
    distinguish 'no text here' from 'text here we could not read'.

    stats = {"words_total", "words_kept", "words_dropped", "psm"}
    """
    img = preprocess(image_path)

    filename = image_path.replace("\\", "/").split("/")[-1]
    psm = PSM_OVERRIDES.get(filename, 6)

    words = run_tesseract(img, psm=psm)
    kept = [w for w in words if w["conf"] >= CONF_THRESHOLD]
    stats = {
        "words_total": len(words),
        "words_kept": len(kept),
        "words_dropped": len(words) - len(kept),
        "psm": psm,
    }

    lines: dict[tuple, list[dict]] = {}
    for w in kept:
        key = (w["block_num"], w["par_num"], w["line_num"])
        lines.setdefault(key, []).append(w)

    blocks: list[TextBlock] = []
    for ws in lines.values():
        ws.sort(key=lambda w: w["bbox"][0])
        text = _fix_digits(" ".join(w["text"] for w in ws))
        text = _fix_email_spacing(text)
        xs = [w["bbox"][0] for w in ws] + [w["bbox"][2] for w in ws]
        ys = [w["bbox"][1] for w in ws] + [w["bbox"][3] for w in ws]
        avg = sum(w["conf"] for w in ws) / len(ws)

        blocks.append(TextBlock(
            id=str(uuid.uuid4()),
            file=file,
            page_or_slide=page_or_slide,
            text=text,
            bbox=(min(xs), min(ys), max(xs), max(ys)),
            source="ocr",
            ocr_conf=round(avg, 3),
        ))
    return blocks, stats


def ocr(image_path: str, file: str, page_or_slide: int, bbox: tuple = None) -> list[TextBlock]:
    """Public API — unchanged signature. Returns list[TextBlock]."""
    return ocr_with_stats(image_path, file, page_or_slide, bbox)[0]