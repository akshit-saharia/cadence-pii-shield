
from __future__ import annotations

from dataclasses import dataclass

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

GOV_ID, FINANCIAL, PERSONAL, CONTACT, ORG, TECH, BIOMETRIC, OTHER = (
    "GOVERNMENT_ID", "FINANCIAL", "PERSONAL", "CONTACT",
    "ORGANISATIONAL", "TECHNICAL", "BIOMETRIC", "UNCLASSIFIED",
)

# entity_type -> (category, risk)
_CATALOG: dict[str, tuple[str, str]] = {
    # Government-issued identifiers
    "US_SSN": (GOV_ID, "CRITICAL"), "SSN": (GOV_ID, "CRITICAL"),
    "PASSPORT": (GOV_ID, "CRITICAL"), "US_PASSPORT": (GOV_ID, "CRITICAL"),
    "IN_PAN": (GOV_ID, "CRITICAL"), "PAN": (GOV_ID, "CRITICAL"),
    "PESEL": (GOV_ID, "CRITICAL"), "TIN": (GOV_ID, "CRITICAL"),
    "TAX_ID": (GOV_ID, "CRITICAL"), "NATIONAL_ID": (GOV_ID, "CRITICAL"),
    "IN_AADHAAR": (GOV_ID, "CRITICAL"), "UK_NINO": (GOV_ID, "CRITICAL"),
    "US_DRIVER_LICENSE": (GOV_ID, "CRITICAL"), "DRIVER_LICENSE": (GOV_ID, "CRITICAL"),
    # Financial
    "CREDIT_CARD": (FINANCIAL, "CRITICAL"), "CARD_NUMBER": (FINANCIAL, "CRITICAL"),
    "BANK_ACCOUNT": (FINANCIAL, "CRITICAL"), "US_BANK_NUMBER": (FINANCIAL, "CRITICAL"),
    "IBAN": (FINANCIAL, "CRITICAL"), "IBAN_CODE": (FINANCIAL, "CRITICAL"),
    # Personal
    "DATE_OF_BIRTH": (PERSONAL, "HIGH"), "DOB": (PERSONAL, "HIGH"),
    "ADDRESS": (PERSONAL, "HIGH"), "HOME_ADDRESS": (PERSONAL, "HIGH"),
    "LOCATION": (PERSONAL, "LOW"),
    # Contact / identity
    "PERSON": (CONTACT, "MEDIUM"), "NAME": (CONTACT, "MEDIUM"),
    "EMAIL_ADDRESS": (CONTACT, "MEDIUM"), "EMAIL": (CONTACT, "MEDIUM"),
    "PHONE_NUMBER": (CONTACT, "MEDIUM"), "PHONE": (CONTACT, "MEDIUM"),
    # Organisational identifiers
    "EMPLOYEE_ID": (ORG, "MEDIUM"), "VENDOR_ID": (ORG, "MEDIUM"),
    "DIRECTOR_ID": (ORG, "MEDIUM"),
    # Technical
    "IP_ADDRESS": (TECH, "MEDIUM"), "USERNAME": (TECH, "MEDIUM"),
    "URL": (TECH, "LOW"),
    # Biometric / image
    "PHOTO": (BIOMETRIC, "HIGH"), "FACE": (BIOMETRIC, "HIGH"),
}

_ALIASES = {
    "EMAIL ADDRESS": "EMAIL_ADDRESS", "PHONE NUMBER": "PHONE_NUMBER",
    "DATE_TIME": "DATE_OF_BIRTH",   # only if P3 emits DATE_TIME for DOB; revisit
    "ORGANIZATION": "ORGANISATION",
}


@dataclass(frozen=True)
class Classification:
    entity_type: str
    category: str
    risk: str


def _norm(entity_type: str) -> str:
    return entity_type.strip().upper().replace("-", "_")


def register(entity_type: str, category: str, risk: str) -> None:
    """Add or override a mapping (e.g. for a custom recogniser from P3)."""
    if risk not in RISK_LEVELS:
        raise ValueError(f"risk must be one of {RISK_LEVELS}")
    _CATALOG[_norm(entity_type)] = (category, risk)


def classify(entity_type: str) -> Classification:
    t = _norm(entity_type)
    t = _ALIASES.get(t, t)
    category, risk = _CATALOG.get(t, (OTHER, "HIGH"))   # unknown -> conservative
    return Classification(entity_type=t, category=category, risk=risk)


def risk_rank(risk: str) -> int:
    return RISK_LEVELS.index(risk)


def max_risk(risks: list[str]) -> str:
    return max(risks, key=risk_rank) if risks else "LOW"