"""Keyword-context scoring: 'DOB', 'SSN', 'passport' near a value raises confidence;
'invoice', 'ticket', 'order no' near a number lowers it."""
import re
from functools import lru_cache

import config


@lru_cache(maxsize=512)
def _kw(keyword: str):
    return re.compile(r"(?<!\w)" + re.escape(keyword) + r"(?!\w)", re.I)


def _find(text, start, end, keywords):
    w = config.CONTEXT_WINDOW
    left = text[max(0, start - w):start]
    right = text[end:end + w // 2]
    for kw in keywords:
        rx = _kw(kw)
        if rx.search(left) or rx.search(right):
            return kw
    return None


def adjust(entity, text, start, end, conf):
    """Returns (new_conf, reasons, positive_context_found)."""
    reasons, hit = [], False
    kw = _find(text, start, end, config.CONTEXT_KEYWORDS.get(entity, []))
    if kw:
        conf += config.CONTEXT_BOOST
        reasons.append(f"context:{kw}")
        hit = True
    if entity in config.NEGATIVE_CONTEXT_ENTITIES:
        neg = _find(text, start, end, config.NEGATIVE_KEYWORDS)
        if neg:
            conf -= config.NEGATIVE_PENALTY
            reasons.append(f"negative_context:{neg}")
    return conf, reasons, hit
