# OCR Module (P2)

Extracts text from image-only artifacts via Tesseract + OpenCV.

## API

    from ocr.ocr_pipeline import ocr
    blocks = ocr(image_path, file, page_or_slide, bbox=None) -> list[TextBlock]

Returns TextBlocks with source="ocr", bbox, ocr_conf.

## Pipeline

1. Grayscale; auto-invert if mean < 120
2. Denoise, upscale to >= 3000px wide
3. Tesseract with per-image PSM (6 default, 11 for tables, 4 for logs)
4. Merge word-level results into line blocks; digit post-fix (O->0, I->1, S->5, B->8)

## Test images and results

| Image | Status |
|---|---|
| fig3_identity_record.png | OK — names, EMP IDs, emails, mobiles |
| fig8_rcsa_signed.png | OK — SSN, DOB, PAN, passport, mobile |
| fig9_config_evidence.png | Partial — names, roles, dates, partial emails |
| fig11_audit_log.png | FAILS — source resolution below OCR limit |
| fig13_id_badge.png | OK — every field |

## Known limitations

Fig 11 (audit log screenshot) has ~6–8px character height, below both Tesseract's
and EasyOCR's readability threshold. Documented source-image limitation, not a
pipeline bug. Production remediation: source log file or higher-DPI capture.

## Dependencies

opencv-python, pytesseract, pillow, numpy, pymupdf

External: Tesseract OCR binary v5+ at C:\Program Files\Tesseract-OCR\