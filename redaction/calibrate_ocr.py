"""Calibrate the OCR gate settings from YOUR sample images (stop guessing).

    python -m redaction.calibrate_ocr                       # uses ocr/samples/ground_truth.json
    python -m redaction.calibrate_ocr path/to/ground_truth.json --samples ocr/samples

For every sample image it reports what Tesseract saw (words total / kept / dropped), the line confidences,
and which ground-truth PII values came out intact, partial or missing. Then it prints suggested values:

  OCR_MIN_CONF           a cut-off between lines where PII was misread and lines where it was read right
                         (only suggested when those two groups are actually separable)
  OCR_MAX_DROPPED_RATIO  a cut-off separating images that read well from images that did not (if one exists)
  OCR_UNREADABLE_MIN_WORDS  smallest word count seen on an unreadable image (for fig11-style files)

Paste the printed table back so the numbers in config.py come from data. Needs the ocr/ package and Tesseract.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PII = {
    "email": re.compile(r"[\w.\-]+@[\w.\-]+\.\w+"), "emp_id": re.compile(r"EMP-\d+"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "mobile": re.compile(r"\+?\d[\d\s\-\(\)]{8,}\d"),
    "dob": re.compile(r"\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b"), "pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "passport": re.compile(r"\b[A-Z]{2}\d{7}\b"),
}


def _truth_values(text: str):
    return sorted({(k, m) for k, rx in PII.items() for m in rx.findall(text)})


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s).lower()


def _status(value: str, ocr_text: str) -> str:
    """intact | partial (>=60% of it survives as a run) | missing"""
    if _norm(value) in _norm(ocr_text):
        return "intact"
    v, o = _norm(value), _norm(ocr_text)
    need = max(4, int(len(v) * 0.6))
    return "partial" if any(v[i:i + need] in o for i in range(0, len(v) - need + 1)) else "missing"


def _bad_line_confs(value: str, blocks) -> list:
    """Confidence of lines that hold a PARTIAL copy of the value (read, but wrongly)."""
    v = _norm(value)
    need = max(4, int(len(v) * 0.6))
    out = []
    for b in blocks:
        t = _norm(b.text)
        if v not in t and any(v[i:i + need] in t for i in range(0, len(v) - need + 1)):
            out.append(b.ocr_conf)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("truth", nargs="?", default="ocr/samples/ground_truth.json")
    ap.add_argument("--samples", default="ocr/samples")
    ap.add_argument("--out", default="outputs/ocr_calibration.json")
    args = ap.parse_args(argv)

    from ocr import ocr_pipeline as op
    from ocr.engine import run_tesseract
    from ocr.preprocess import preprocess

    truth = json.load(open(args.truth, encoding="utf-8"))
    rows, good_line_conf, bad_line_conf, good_ratios, bad_ratios, unreadable_words = [], [], [], [], [], []
    print(f"{'image':26} {'words':>5} {'kept':>5} {'drop%':>6} {'lineConf min/mean':>18}  PII intact/partial/missing")
    for name, gt in truth.items():
        path = Path(args.samples) / (name if name.endswith(".png") else name + ".png")
        if not path.exists():
            print(f"{name:26} (image not found: {path})")
            continue
        words = run_tesseract(preprocess(str(path)), psm=op.PSM_OVERRIDES.get(path.name, 6))
        kept = [w for w in words if w["conf"] >= op.CONF_THRESHOLD]
        dropped = len(words) - len(kept)
        ratio = dropped / len(words) if words else 0.0
        blocks = op.ocr(str(path), "cal.pdf", 1)
        ocr_text = " ".join(b.text for b in blocks)
        confs = [b.ocr_conf for b in blocks]

        if gt.startswith("(unreadable"):
            if words:
                unreadable_words.append(len(words))
            bad_ratios.append(ratio)
            print(f"{name:26} {len(words):>5} {len(kept):>5} {ratio:>6.0%} "
                  f"{(min(confs) if confs else 0):>8.2f}/{(sum(confs)/len(confs) if confs else 0):<8.2f}  (ground truth: unreadable)")
            rows.append({"image": name, "words": len(words), "kept": len(kept), "dropped_ratio": round(ratio, 3),
                         "unreadable": True})
            continue

        vals = _truth_values(gt)
        st = {v: _status(v[1], ocr_text) for v in vals}
        counts = {k: sum(1 for s in st.values() if s == k) for k in ("intact", "partial", "missing")}
        for (kind, value), s in st.items():
            if s == "intact":
                line_confs = [b.ocr_conf for b in blocks if _norm(value) in _norm(b.text)]
                if line_confs:
                    good_line_conf.append(min(line_confs))
            elif s == "partial":
                bad_line_conf += _bad_line_confs(value, blocks)
        (good_ratios if counts["partial"] + counts["missing"] == 0 else bad_ratios).append(ratio)
        print(f"{name:26} {len(words):>5} {len(kept):>5} {ratio:>6.0%} "
              f"{(min(confs) if confs else 0):>8.2f}/{(sum(confs)/len(confs) if confs else 0):<8.2f}  "
              f"{counts['intact']}/{counts['partial']}/{counts['missing']}")
        rows.append({"image": name, "words": len(words), "kept": len(kept), "dropped_ratio": round(ratio, 3),
                     "pii": counts, "partial_or_missing": [f"{k}:{v}" for (k, v), s in st.items() if s != "intact"]})

    print("\nSuggested settings")
    sugg = {}
    if good_line_conf and bad_line_conf and max(bad_line_conf) < min(good_line_conf):
        sugg["OCR_MIN_CONF"] = round((max(bad_line_conf) + min(good_line_conf)) / 2, 2)
        print(f"  OCR_MIN_CONF = {sugg['OCR_MIN_CONF']}   (misread-PII lines <= {max(bad_line_conf):.2f}, "
              f"correct-PII lines >= {min(good_line_conf):.2f})")
    elif good_line_conf and not bad_line_conf:
        print(f"  OCR_MIN_CONF: no misread-PII lines in the samples, so no data to move it. "
              f"Keep the default; correct-PII lines were all >= {min(good_line_conf):.2f}")
    elif good_line_conf:
        print(f"  OCR_MIN_CONF: not separable (misread-PII lines up to {max(bad_line_conf):.2f}, "
              f"correct-PII lines from {min(good_line_conf):.2f}); a confidence cut-off will not catch these")
    if good_ratios and bad_ratios:
        if max(good_ratios) < min(bad_ratios):
            sugg["OCR_MAX_DROPPED_RATIO"] = round((max(good_ratios) + min(bad_ratios)) / 2, 2)
            print(f"  OCR_MAX_DROPPED_RATIO = {sugg['OCR_MAX_DROPPED_RATIO']}   (good images <= {max(good_ratios):.0%}, bad images >= {min(bad_ratios):.0%})")
        else:
            print(f"  OCR_MAX_DROPPED_RATIO: not separable (good up to {max(good_ratios):.0%}, bad from {min(bad_ratios):.0%}); leave it off")
    if not unreadable_words and any(r.get("unreadable") for r in rows):
        print("  OCR_UNREADABLE_MIN_WORDS: Tesseract saw 0 words on the unreadable image(s), so it looks like "
              "'no text' to the gate. Those pages are caught by the gate's page-text rule instead, not by word counts.")
    if unreadable_words:
        sugg["OCR_UNREADABLE_MIN_WORDS"] = max(1, min(unreadable_words))
        print(f"  OCR_UNREADABLE_MIN_WORDS = {sugg['OCR_UNREADABLE_MIN_WORDS']}   (words seen on unreadable images: {unreadable_words})")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps({"images": rows, "suggested": sugg}, indent=2), encoding="utf-8")
    print(f"\nsaved {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
