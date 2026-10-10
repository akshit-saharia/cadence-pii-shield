import fitz
import os

PDF = "Cadence_Group_Risk_Management_Policy__v6.0.pdf"
OUT = "ocr/samples"

TARGETS = [
    (9,  "fig3_identity_record",  "fig3_identity_record.png"),
    (18, "fig8_rcsa_signed",      "fig8_rcsa_signed.png"),
    (19, "fig9_config_evidence",  "fig9_config_evidence.png"),
    (20, "fig11_audit_log",       "fig11_audit_log.png"),
    (28, "fig13_id_badge",        "fig13_id_badge.png"),
]

os.makedirs(OUT, exist_ok=True)
doc = fitz.open(PDF)
for page_num, _, filename in TARGETS:
    pix = doc[page_num - 1].get_pixmap(dpi=300)
    pix.save(os.path.join(OUT, filename))
    print(f"Saved {filename}")