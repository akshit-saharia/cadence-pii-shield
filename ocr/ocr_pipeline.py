import re
import uuid
from schemas import TextBlock
from ocr.preprocess import preprocess
from ocr.engine import run_tesseract

CONF_THRESHOLD = 0.40

# Per-image PSM tuning. Tesseract's psm controls how it interprets layout.
#   6  = single uniform block (good for forms, badges)
#   4  = single column of variable-size text (good for lists)
#   11 = sparse text (good for tables and scattered UI labels)
PSM_OVERRIDES = {
    "fig9_config_evidence.png": 11,   # table with columns
    "fig11_audit_log.png":      4,    # lines of log text
}


def _fix_digits(text: str) -> str:
    """Fix common OCR digit confusion (O->0, I->1, S->5, B->8) in number-like tokens."""
    def fix(tok):
        if sum(c.isdigit() for c in tok) >= 2:
            return (tok.replace("O", "0").replace("o", "0")
                       .replace("I", "1").replace("l", "1")
                       .replace("S", "5").replace("B", "8"))
        return tok
    return " ".join(fix(t) for t in text.split())


def _fix_email_spacing(text: str) -> str:
    """Rejoin OCR-split emails: 'name @ domain.com' -> 'name@domain.com'."""
    text = re.sub(r"\s*@\s*", "@", text)
    # Collapse spaces around dots only when adjacent to word chars (domain pattern)
    text = re.sub(r"(?<=\w)\s*\.\s*(?=\w)", ".", text)
    return text


def ocr(image_path: str, file: str, page_or_slide: int, bbox: tuple = None) -> list[TextBlock]:
    img = preprocess(image_path)

    filename = image_path.replace("\\", "/").split("/")[-1]
    psm = PSM_OVERRIDES.get(filename, 6)

    words = run_tesseract(img, psm=psm)

    lines: dict[tuple, list[dict]] = {}
    for w in words:
        if w["conf"] < CONF_THRESHOLD:
            continue
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
    return blocks