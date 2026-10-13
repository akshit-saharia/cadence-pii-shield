# Cadence PII Shield

Documents (PDF / DOCX / PPTX) -> **extract** -> **OCR** embedded images -> **detect** PII -> **classify + redact** -> **fail-closed gate** -> LLM payload + exposure report.

## Layout (after integration)

| Folder | Stage | Entry point |
|---|---|---|
| `extraction/` | P1 text, tables, images out of PDF/DOCX/PPTX | `extraction.router.extract_file` |
| `ocr/` | P2 Tesseract + OpenCV, image -> TextBlocks | `ocr.ocr_pipeline.ocr / ocr_with_stats` |
| `detection/` | P3 regex + validators + context + NER | `detection.DetectionEngine` |
| `redaction/` | P4 classify, tokenise (vault), gate, report | `redaction.ProtectionPipeline` |
| `schemas.py` | **single** shared dataclasses (all stages) | |
| `config.py` | shared settings (P3 values; P4 policy overrides optional) | |
| `pipeline.py` | one-command entrypoint | `python pipeline.py files...` |

## Setup

    pip install -r requirements.txt
    # Tesseract binary must be installed (or set TESSERACT_CMD)
    # Better PERSON detection: pip install spacy && python -m spacy download en_core_web_sm

## Run

    python pipeline.py                       # demo on data/sample_blocks.json
    python pipeline.py a.pdf b.docx c.pptx --show
    python pipeline.py some_folder/ --out outputs
    pytest
    streamlit run app/streamlit_app.py       # launch the web UI                                 # all suites

Outputs go to `outputs/` (`exposure_report.json|md`, `llm_payload.json`, `redacted_blocks.json`);
the encrypted token vault goes to `data/vault/` (git-ignore it; never commit `.vault.key`).

```python
from pipeline import protect
res = protect(["policy.pdf"])
safe = res.llm_payload()            # only files the gate ALLOWED, redacted
answer = res.rehydrate(llm_reply)   # tokens -> original values, for the end user only
```

## Known gaps (read before demoing)

1. **Label/value split in OCR output.** OCR emits one block per line, so on forms/badges the label
   ("DATE OF BIRTH") and the value are separate blocks and detection's context rules cannot connect them.
2. **The gate re-scans with the same detector**, so it cannot catch what detection cannot see.
   "0 PII with protection" is only as good as detection recall. Measure it (`evaluation/` is still empty).
3. Without `phonenumbers` / `spaCy` installed, phone and name recall drop sharply.

5. `tests/test_redaction_independent.py` targets an older redaction API and is skipped (rewrite or delete).
