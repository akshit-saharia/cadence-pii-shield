
# redaction/ (P4)

Drop this folder next to `detection/` (same level as `config.py` and `schemas.py`).

    python -m redaction.pipeline --show                 # demo run on redaction/demo_blocks.json
    python -m redaction.pipeline a.pdf b.docx c.pptx     # real files via extraction.router
    python -m redaction.pipeline some_folder/            # every file in the folder
    python -m redaction.pipeline data/blocks.json --out outputs
    pytest redaction/tests

Outputs (in `outputs/`): `exposure_report.json|md`, `llm_payload.json` (allowed files only),
`redacted_blocks.json`; the token vault goes to `data/vault/`.

Optional: `pip install cryptography` so the vault is encrypted (the report says if it is not).

Every policy value in `redaction/policy.py` (tiers, reversible tiers, OCR_MIN_CONF,
GATE_RESIDUAL_MIN_TIER, ...) can be overridden by defining the same name in `config.py`.

Modules: classifier.py (labels/tiers/score) - tokenizer.py (token format, reversible vs masked) -
vault.py (token store, encryption) - redactor.py - gate.py (fail-closed) - report.py (exposure report) -
pipeline.py (orchestration + CLI) - policy.py / models.py (settings, dataclasses).

Data classes live in the shared `schemas.py` (repo root). `redaction/models.py` only re-exports them.
Replace the team's `schemas.py` with the merged one only after diffing it against the current file.

## OCR (P2) hookup
`pipeline.run_files()` runs P1's extractor, then OCRs the extracted images (`ocr_stage.py`), then detection.
- Needs P2's `ocr/` package + Tesseract. Without them OCR is reported as unavailable and image-only pages are BLOCKED.
- `python -m redaction.pipeline scan.pdf --no-ocr` switches OCR off on purpose.
- `python -m redaction.calibrate_ocr` prints OCR quality per sample image and suggests config values.
- Optional config.py overrides: MIN_OCR_IMAGE_PX, OCR_UNREADABLE_MIN_WORDS, OCR_MAX_DROPPED_RATIO, OCR_FRAGMENT_SWEEP, OCR_MIN_CONF.
