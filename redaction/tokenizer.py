
from __future__ import annotations

import re
import unicodedata
from typing import Optional

from .vault import Vault

_NAME_TYPES = {"PERSON", "NAME", "PER", "PERSON_NAME"}
_ID_HINTS = ("SSN", "PAN", "PASSPORT", "CARD", "ACCOUNT", "IBAN", "PESEL", "TIN",
             "NATIONAL", "LICENSE", "LICENCE", "AADHAAR", "NINO", "EMPLOYEE",
             "VENDOR", "_ID", "ID_")


def _collapse(v: str) -> str:
    return re.sub(r"\s+", " ", v).strip()


def label_for(entity_type: str) -> str:
    """Token label, e.g. 'US_SSN' -> 'US_SSN', 'email address' -> 'EMAIL_ADDRESS'."""
    lab = re.sub(r"[^A-Z0-9]+", "_", entity_type.upper()).strip("_")
    return lab or "PII"


def normalize(entity_type: str, value: str) -> str:
    """
    Canonical form used ONLY to decide whether two strings are 'the same value'.
    The original string is what the vault stores for the audit trail.
    """
    t = entity_type.upper()
    v = unicodedata.normalize("NFKC", value)
    if "EMAIL" in t:
        return v.strip().casefold()
    if "PHONE" in t or t in {"MOBILE", "TEL", "FAX"}:
        digits = re.sub(r"\D", "", v)
        if len(digits) == 11 and digits.startswith("1"):   # US country code
            digits = digits[1:]
        return digits
    if t in _NAME_TYPES:
        v = re.sub(r"[.,]", " ", v)
        return _collapse(v).casefold()
    if any(h in t for h in _ID_HINTS):
        return re.sub(r"[\s\-./]", "", v).upper()
    return _collapse(v).casefold()


def _name_parts(norm_name: str) -> set[str]:
    """Name words without single-letter initials ('m', 't')."""
    return {w for w in norm_name.split() if len(w) > 1}


class Tokenizer:
    def __init__(self, vault: Optional[Vault] = None,
                 merge_person_aliases: bool = False):
        """
        vault                : shared Vault (default: in-memory vault).
        merge_person_aliases : if True, 'Miriam Achebe' and 'Miriam T. Achebe'
                               share a token when one name's words are a subset
                               of the other's (both need >= 2 non-initial words).
                               Off by default: exact-match is safer (no wrong merges).
        """
        self.vault = vault if vault is not None else Vault(path=None, persist=False)
        self.merge_person_aliases = merge_person_aliases

    def tokenize(self, entity_type: str, value: str) -> str:
        etype = entity_type.upper()
        key = normalize(etype, value)

        token = self.vault.lookup(etype, key)
        if token:
            return token

        if self.merge_person_aliases and etype in _NAME_TYPES:
            merged = self._find_person_alias(etype, key)
            if merged:
                self.vault.alias(etype, key, merged)
                return merged

        return self.vault.add(etype, key, value, label=label_for(etype))

    def _find_person_alias(self, etype: str, key: str) -> Optional[str]:
        mine = _name_parts(key)
        if len(mine) < 2:
            return None
        for other_key, token in self.vault.keys_for(etype):
            theirs = _name_parts(other_key)
            if len(theirs) >= 2 and (mine <= theirs or theirs <= mine):
                return token
        return None