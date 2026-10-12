"""Shared settings for the whole pipeline (detection P3 + optional overrides for redaction/policy.py)."""
from pathlib import Path

ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
INPUT_DIR = DATA_DIR / "input"
VAULT_DIR = DATA_DIR / "vault"
OUTPUT_DIR = ROOT / "outputs"

# ---- Detection (P3) ----
# Highest priority first: used to resolve overlapping detections.
ENTITY_PRIORITY = ["CREDIT_CARD", "SSN", "PAN", "PASSPORT", "EMAIL",
                   "PHONE", "DOB", "ADDRESS", "PERSON"]
ENTITY_TYPES = list(ENTITY_PRIORITY)

DEFAULT_MIN_CONFIDENCE = 0.60
MIN_CONFIDENCE = {}                 # per-entity override, e.g. {"PERSON": 0.65}
OCR_THRESHOLD_DISCOUNT = 0.10       # OCR text is noisy -> be more willing to flag (fail-closed)

VALIDATOR_BOOST = 0.25
VALIDATOR_PENALTY = 0.30
CONTEXT_BOOST = 0.20
NEGATIVE_PENALTY = 0.30
CONTEXT_WINDOW = 40                 # chars looked at around a value

# Internal IDs that look like PII but are NOT (false-positive control)
ALLOWLIST_PREFIXES = ["EMP", "RSK", "INC", "ISS"]

PHONE_REGIONS = ["IN", "US"]
USE_SPACY = True
SPACY_MODEL = "en_core_web_sm"

CONTEXT_KEYWORDS = {
    "SSN": ["ssn", "social security", "social security number", "ss#", "ss no"],
    "PAN": ["pan", "pan no", "pan number", "pan card", "permanent account number"],
    "PASSPORT": ["passport", "passport no", "passport number", "travel document"],
    "CREDIT_CARD": ["card", "credit card", "debit card", "card number", "visa", "mastercard", "amex"],
    "DOB": ["dob", "d.o.b", "date of birth", "birth date", "birthdate", "born"],
    "PHONE": ["phone", "mobile", "tel", "telephone", "contact", "cell", "whatsapp", "call"],
    "EMAIL": ["email", "e-mail", "mail"],
    "ADDRESS": ["address", "residing", "resident", "lives at"],
}
NEGATIVE_CONTEXT_ENTITIES = ["PHONE", "SSN", "PASSPORT", "CREDIT_CARD"]
NEGATIVE_KEYWORDS = ["invoice", "order no", "order number", "ticket", "tracking",
                     "reference", "ref no", "case id", "transaction id", "txn",
                     "serial", "sku", "po number", "batch"]


def priority(entity: str) -> int:
    return ENTITY_PRIORITY.index(entity) if entity in ENTITY_PRIORITY else len(ENTITY_PRIORITY)


def min_conf(entity: str) -> float:
    return MIN_CONFIDENCE.get(entity, DEFAULT_MIN_CONFIDENCE)


# ---- Redaction (P4) overrides: uncomment to change redaction/policy.py defaults ----
# OCR_MIN_CONF = 0.50                 # any OCR block below this blocks the file
# GATE_RESIDUAL_MIN_TIER = "LOW"
# REVERSIBLE_TIERS = ["LOW", "MEDIUM"]
