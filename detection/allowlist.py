"""False-positive controls: things that look like PII but are not."""
import re

import config

# Internal IDs: EMP-38104, RSK-1002, INC-20456, ISS-3301 ...
_ID = re.compile(r"\b(?:%s)[-_]?\d{3,}\b" % "|".join(map(re.escape, config.ALLOWLIST_PREFIXES)))

# Card last-four: "ending in 4417", "last four 4417", "XXXX-XXXX-XXXX-4417", "**** 4417"
_LAST4 = re.compile(
    r"(?:ending(?:\s+in)?|last\s+(?:4|four)(?:\s+digits)?(?:\s+(?:of|is|are))?)[\s:#-]*\d{4}\b"
    r"|(?:[Xx*\u2022]{2,}[\s-]*){1,4}\d{4}\b", re.I)

# Organisation / document words that NER mistakes for people
_ORG_WORDS = {"financial", "group", "inc", "ltd", "llc", "bank", "corp", "services",
              "policy", "department", "team", "cadence", "committee", "board", "company"}
_NAME_STOP = {"streamlit", "tesseract", "paddleocr", "spacy", "presidio", "python", "azure"}


def allowlisted_spans(text: str):
    return [(m.start(), m.end()) for rx in (_ID, _LAST4) for m in rx.finditer(text)]


def covered(start: int, end: int, spans) -> bool:
    """True if >= 50% of [start, end) sits inside an allowlisted span."""
    length = max(end - start, 1)
    inside = sum(max(0, min(end, e) - max(start, s)) for s, e in spans)
    return inside / length >= 0.5


def is_stopword_name(name: str) -> bool:
    words = {w.lower().strip(".,") for w in name.split()}
    return bool(words & _ORG_WORDS) or name.lower() in _NAME_STOP
