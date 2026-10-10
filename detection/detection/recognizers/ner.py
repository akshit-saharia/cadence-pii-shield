"""Names and addresses. Uses spaCy PERSON when installed, plus heuristics that work
without any model (titles, 'Name:' labels, street addresses)."""
import re

import config
from .. import allowlist

_NLP, _TRIED = None, False


def _nlp():
    global _NLP, _TRIED
    if _TRIED:
        return _NLP
    _TRIED = True
    if config.USE_SPACY:
        try:
            import spacy
            _NLP = spacy.load(config.SPACY_MODEL)
        except Exception:
            _NLP = None   # model not installed -> heuristics only
    return _NLP


_TITLED = re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt)\.?[ \t]+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,2})")
_LABELED = re.compile(
    r"(?<!Company )(?<!File )(?<!Project )(?<!Document )(?<!Product )(?<!User )(?<!Domain )"
    r"(?:Full Name|Employee Name|Customer Name|Applicant|Account Holder|Policyholder|Insured|Beneficiary|Name)"
    r"[ \t]*[:\-\u2013][ \t]*([A-Z][A-Za-z'.-]+(?:[ \t]+[A-Z][A-Za-z'.-]+){0,3})")
_STREET = re.compile(
    r"\b\d{1,5}[A-Za-z]?,?[ \t]+(?:[A-Z][A-Za-z.'-]*[ \t]+){1,4}"
    r"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Boulevard|Blvd|Drive|Dr|Court|Ct|Way|Nagar|Colony|Marg)\b\.?")
_LABELED_ADDR = re.compile(
    r"(?:Address|Addr|Residential Address|Mailing Address)[ \t]*[:\-\u2013][ \t]*"
    r"([^\n]{10,120}?)(?=[ \t]*(?:[;|]|\b(?:Phone|Tel|Mobile|Mob|Email|E-mail|Contact|Ph)\b)|\n|$)")


def find_entities(text: str):
    """Return [(entity, start, end, conf, detector, reasons)]."""
    out = []

    for m in _TITLED.finditer(text):
        out.append(("PERSON", m.start(1), m.end(1), 0.80, "heuristic", ["pattern:titled_name"]))
    for m in _LABELED.finditer(text):
        out.append(("PERSON", m.start(1), m.end(1), 0.80, "heuristic", ["pattern:labeled_name"]))
    for m in _STREET.finditer(text):
        out.append(("ADDRESS", m.start(), m.end(), 0.70, "heuristic", ["pattern:street_address"]))
    for m in _LABELED_ADDR.finditer(text):
        out.append(("ADDRESS", m.start(1), m.end(1), 0.75, "heuristic", ["pattern:labeled_address"]))

    nlp = _nlp()
    if nlp is not None:
        for ent in nlp(text).ents:
            if ent.label_ != "PERSON" or any(c.isdigit() for c in ent.text):
                continue
            conf = 0.70 if len(ent.text.split()) > 1 else 0.60
            out.append(("PERSON", ent.start_char, ent.end_char, conf, "spacy", ["ner:spacy_person"]))

    # Trim spans so they never swallow an allowlisted ID (e.g. "Priya Nair EMP-38104" -> "Priya Nair")
    spans = allowlist.allowlisted_spans(text)
    trimmed = []
    for ent, s, e, c, det, r in out:
        for a, b in spans:
            if s < a < e:
                e = a
        while e > s and text[e - 1] in " \t,;:-":
            e -= 1
        if e > s:
            trimmed.append((ent, s, e, c, det, r))

    return [o for o in trimmed if not (o[0] == "PERSON" and allowlist.is_stopword_name(text[o[1]:o[2]]))]
