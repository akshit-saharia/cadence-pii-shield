"""One-command entrypoint:  extraction -> OCR -> detection -> classify -> redact -> gate -> report.

    python pipeline.py a.pdf b.docx c.pptx          # files
    python pipeline.py some_folder/ --show          # every file in a folder, print redacted text
    python pipeline.py                              # demo on redaction/demo_blocks.json

Same CLI as `python -m redaction.pipeline` (this file just forwards to it).
Programmatic use:

    from pipeline import protect
    result = protect(["a.pdf", "b.docx"])
    safe = result.llm_payload()          # {file: redacted text} for files the gate ALLOWED
    answer = result.rehydrate(llm_reply) # put original values back into the LLM's answer
"""
from __future__ import annotations

from typing import Iterable

from redaction.pipeline import ProtectionPipeline, ProtectionResult, main


def protect(paths: Iterable, use_ner: bool = True, ocr: bool = True) -> ProtectionResult:
    return ProtectionPipeline(use_ner=use_ner, ocr_fn="auto" if ocr else None).run_files(paths)


if __name__ == "__main__":
    raise SystemExit(main())
