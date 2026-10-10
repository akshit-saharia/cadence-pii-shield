from dataclasses import dataclass
from typing import Optional


@dataclass
class TextBlock:
    id: str
    file: str
    page_or_slide: int
    text: str
    bbox: Optional[tuple]
    source: str
    ocr_conf: float