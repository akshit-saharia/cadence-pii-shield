"""Validators: turn 'looks like PII' into 'is valid PII'. Cuts false positives."""
import re
from datetime import date

import config


def luhn(number: str) -> bool:
    digits = [int(d) for d in number][::-1]
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_valid(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    return 13 <= len(digits) <= 19 and len(set(digits)) > 1 and luhn(digits)


def ssn_valid(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    return area not in (0, 666) and area < 900 and group != 0 and serial != 0


def pan_valid(raw: str) -> bool:
    # Format AAAAA9999A; 4th letter = holder type (P person, C company, ...)
    return bool(re.fullmatch(r"[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]", raw))


def email_valid(raw: str) -> bool:
    local, _, domain = raw.rpartition("@")
    return bool(local) and ".." not in raw and "." in domain and not domain.startswith(".")


def dob_valid(raw: str) -> bool:
    m = re.search(r"(?:19|20)\d{2}", raw)
    return bool(m) and 1900 <= int(m.group(0)) <= date.today().year


VALIDATORS = {
    "CREDIT_CARD": card_valid,
    "SSN": ssn_valid,
    "PAN": pan_valid,
    "EMAIL": email_valid,
    "DOB": dob_valid,
}
