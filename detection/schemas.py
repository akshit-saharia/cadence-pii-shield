from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class TextBlock:
    id: str
    file: str
    page_or_slide: int
    text: str
    bbox: Optional[tuple]
    source: str
    ocr_conf: float


@dataclass
class Finding:
    """Output of the detection stage (P3). One PII hit inside one TextBlock."""
    block_id: str                 # = TextBlock.id
    entity_type: str              # SSN, PAN, PASSPORT, EMAIL, PHONE, CREDIT_CARD, DOB, PERSON, ADDRESS
    start: int                    # character offsets inside TextBlock.text
    end: int
    text: str                     # the matched value, == block.text[start:end]
    confidence: float             # 0..1
    detector: str                 # regex | phonenumbers | spacy | heuristic
    origin: str = "native"        # copied from TextBlock.source ("ocr" or not)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)
