import cv2

CROPS = {
    "fig3_identity_record.png": 0.72,   # unchanged, it's good
    "fig8_rcsa_signed.png":     0.60,   # lower — include reviewer-note table
    "fig9_config_evidence.png": 0.62,   # unchanged, it's good
    "fig11_audit_log.png":      0.72,   # lower — include top of log
    "fig13_id_badge.png":       0.74,   # lower — include full badge
}

for name, top_frac in CROPS.items():
    path = f"ocr/samples/{name}"
    img = cv2.imread(path)
    if img is None:
        print(f"SKIP: {path}")
        continue
    h, w = img.shape[:2]
    cut = int(h * top_frac)
    crop = img[cut:, :]
    cv2.imwrite(path, crop)
    print(f"{name}: cut top {cut}px, kept {crop.shape[0]}px")