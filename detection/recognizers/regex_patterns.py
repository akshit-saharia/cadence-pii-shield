"""Regex candidates for structured PII. These only say 'looks like'; validators
and context_rules decide whether it really is."""
import re
from dataclasses import dataclass

import config

try:
    import phonenumbers
except ImportError:  # pip install phonenumbers
    phonenumbers = None

MONTHS = (r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|"
          r"Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)")


@dataclass(frozen=True)
class Pattern:
    entity: str
    regex: re.Pattern
    base_conf: float
    requires_context: bool = False   # only report when a keyword (DOB, SSN...) is nearby
    name: str = ""


def _p(entity, rx, conf, ctx=False, name="", flags=0):
    return Pattern(entity, re.compile(rx, flags), conf, ctx, name or entity.lower())


PATTERNS = [
    # SSN
    _p("SSN", r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])", 0.60, name="ssn_dashed"),
    _p("SSN", r"(?<!\d)\d{3} \d{2} \d{4}(?!\d)", 0.40, True, "ssn_spaced"),
    _p("SSN", r"(?<![\d-])\d{9}(?![\d-])", 0.30, True, "ssn_plain"),
    # India PAN
    _p("PAN", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0.60, name="pan"),
    # Passport (India format, then generic) - all need the word "passport" nearby
    _p("PASSPORT", r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b", 0.45, True, "passport_in"),
    _p("PASSPORT", r"\b[A-Z]{1,2}\d{6,8}\b", 0.45, True, "passport_generic"),
    _p("PASSPORT", r"(?<!\d)\d{9}(?!\d)", 0.45, True, "passport_us"),
    # Email
    _p("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b", 0.85),
    # Card: 13-19 digits, optional space/dash separators (Luhn decides)
    _p("CREDIT_CARD", r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])", 0.40, name="card"),
    # Date of birth: dates are everywhere, so they need DOB-type context
    _p("DOB", r"\b\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)\d{2}\b", 0.35, True, "dob_dmy"),
    _p("DOB", r"\b(?:19|20)\d{2}[/.-]\d{1,2}[/.-]\d{1,2}\b", 0.35, True, "dob_ymd"),
    _p("DOB", r"\b\d{1,2}(?:st|nd|rd|th)?\s+" + MONTHS + r"\.?,?\s+(?:19|20)\d{2}\b",
       0.35, True, "dob_dmonthy", re.I),
    _p("DOB", r"\b" + MONTHS + r"\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2}\b",
       0.35, True, "dob_monthdy", re.I),
]

_PHONE_FALLBACK = re.compile(r"(?<![\w-])(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?){2,4}\d{2,4}(?![\w-])")


def find_phones(text: str):
    """Return [(start, end, validated)]. 'validated' = accepted by Google's libphonenumber."""
    out, seen = [], set()
    if phonenumbers is not None:
        for region in config.PHONE_REGIONS:
            for m in phonenumbers.PhoneNumberMatcher(text, region, leniency=phonenumbers.Leniency.VALID):
                if (m.start, m.end) not in seen:
                    seen.add((m.start, m.end))
                    out.append((m.start, m.end, True))
    else:
        for m in _PHONE_FALLBACK.finditer(text):
            if len(re.sub(r"\D", "", m.group(0))) >= 10:
                out.append((m.start(), m.end(), False))
    return out
