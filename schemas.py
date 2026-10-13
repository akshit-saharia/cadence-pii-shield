"""Shared data classes for every stage. This is the single source of truth.

  P1 extraction -> ExtractionResult / TextBlock / ExtractedImage
  P2 OCR        -> TextBlock(source="ocr")
  P3 detection  -> Finding
  P4 redaction  -> RedactedBlock / Replacement / Classification / GateDecision / FileResult

TextBlock keeps P3's positional order (id, file, page_or_slide, text, bbox, source, ocr_conf)
and adds P1's optional extras (block_type, metadata) at the end, so both construction styles work.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- text
@dataclass
class TextBlock:
    id: str
    file: str
    page_or_slide: Optional[int] = None      # None for DOCX (no pages)
    text: str = ""
    bbox: Optional[tuple] = None
    source: str = "native"                   # "native" | "ocr"
    ocr_conf: Optional[float] = None         # None = unknown. Native text defaults to 1.0 (see below)
    block_type: str = "text"                 # text | table | header | footer | notes
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.ocr_conf is None and not self.is_ocr:
            self.ocr_conf = 1.0

    @property
    def is_ocr(self) -> bool:
        return str(self.source or "").lower() == "ocr"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractedImage:
    id: str
    file: str
    page_or_slide: Optional[int] = None
    image_bytes: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:               # bytes are never serialised
        return {"id": self.id, "file": self.file, "page_or_slide": self.page_or_slide,
                "size_bytes": len(self.image_bytes or b""), "metadata": dict(self.metadata)}


@dataclass
class ExtractionResult:
    file: str
    success: bool = False
    text_blocks: List[TextBlock] = field(default_factory=list)
    images: List[ExtractedImage] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"file": self.file, "success": self.success,
                "text_blocks": [b.to_dict() for b in self.text_blocks],
                "images": [i.to_dict() for i in self.images],
                "metadata": self.metadata, "warnings": self.warnings, "errors": self.errors}


# ------------------------------------------------------------------------ detection
@dataclass
class Finding:
    """Output of the detection stage (P3). One PII hit inside one TextBlock."""
    block_id: str                 # = TextBlock.id
    entity_type: str              # SSN, PAN, PASSPORT, EMAIL, PHONE, CREDIT_CARD, DOB, PERSON, ADDRESS
    start: int                    # character offsets inside TextBlock.text
    end: int
    text: str                     # the matched value, == block.text[start:end]
    confidence: float             # 0..1
    detector: str                 # regex | phonenumbers | spacy | heuristic | ocr_sweep
    origin: str = "native"        # copied from TextBlock.source ("ocr" or not)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------------ redaction
@dataclass
class Replacement:
    entity_type: str
    tier: str
    orig_start: int
    orig_end: int
    new_start: int
    new_end: int
    token: str
    reversible: bool
    confidence: float = 0.0
    detector: str = ""
    merged: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RedactedBlock:
    id: str
    file: str
    page_or_slide: Optional[int]
    text: str
    source: str = "native"
    ocr_conf: Optional[float] = 1.0
    bbox: Optional[tuple] = None
    block_type: str = "text"
    replacements: List[Replacement] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Classification:
    label: str
    tier: Optional[str] = None
    risk_score: int = 0
    counts_by_entity: Dict[str, int] = field(default_factory=dict)
    counts_by_tier: Dict[str, int] = field(default_factory=dict)
    escalated: bool = False
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GateDecision:
    file: str
    decision: str = "BLOCK"                   # "ALLOW" | "BLOCK"  (default is fail-closed)
    reasons: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    residual: List[dict] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def codes(self) -> List[str]:
        return [r["code"] for r in self.reasons]


@dataclass
class FileResult:
    file: str
    blocks: List[Any] = field(default_factory=list)
    images: List[Any] = field(default_factory=list)          # images OCR could not vouch for
    extraction_warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)   # withheld from the LLM; report lists key names only
    ocr: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    redacted_blocks: List[RedactedBlock] = field(default_factory=list)
    classification: Classification = field(default_factory=lambda: Classification(label="UNCLASSIFIED"))
    decision: GateDecision = field(default_factory=lambda: GateDecision(file=""))

    @property
    def released(self) -> List[RedactedBlock]:
        """Redacted blocks the LLM may see: all of them if the gate said ALLOW, otherwise none."""
        return list(self.redacted_blocks) if self.decision.allowed else []

    def text(self) -> str:
        """Redacted text for the LLM payload. Never contains raw PII or metadata."""
        lines: List[str] = []
        last_page = object()
        for rb in self.released:
            if rb.page_or_slide is not None and rb.page_or_slide != last_page:
                lines.append(f"--- page/slide {rb.page_or_slide} ---")
                last_page = rb.page_or_slide
            if rb.block_type and rb.block_type != "text":
                lines.append(f"[{rb.block_type}]")
            lines.append(rb.text)
        return "\n".join(lines)
