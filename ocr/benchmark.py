import json
import re
from ocr.ocr_pipeline import ocr


# Patterns matching the PII items we care about
PII_PATTERNS = {
    "email":      re.compile(r"[\w\.\-]+@[\w\.\-]+\.\w+"),
    "employee_id":re.compile(r"EMP-\d+"),
    "ssn":        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "mobile":     re.compile(r"\+?\d[\d\s\-\(\)]{8,}\d"),
    "dob":        re.compile(r"\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b"),
    "pan":        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "passport":   re.compile(r"\b[A-Z]{2}\d{7}\b"),
}


def extract_pii(text: str) -> dict[str, set[str]]:
    found = {k: set() for k in PII_PATTERNS}
    for kind, pat in PII_PATTERNS.items():
        for m in pat.findall(text):
            found[kind].add(m)
    return found


def benchmark():
    with open("ocr/samples/ground_truth.json", encoding="utf-8") as f:
        truth_map = json.load(f)

    print(f"{'Image':<30} {'PII Recall':<15} {'PII Counts'}")
    print("-" * 80)

    for name, truth in truth_map.items():
        if truth.startswith("(unreadable"):
            print(f"{name:<30} {'N/A':<15} source resolution limit")
            continue

        blocks = ocr(f"ocr/samples/{name}.png", "test.pdf", 1)
        ocr_text = " ".join(b.text for b in blocks)

        truth_pii = extract_pii(truth)
        ocr_pii = extract_pii(ocr_text)

        total_truth = sum(len(v) for v in truth_pii.values())
        if total_truth == 0:
            print(f"{name:<30} {'no PII in GT':<15} 0")
            continue

        matched = 0
        for kind in truth_pii:
            matched += len(truth_pii[kind] & ocr_pii[kind])

        recall = matched / total_truth
        counts = ", ".join(
            f"{k}={len(truth_pii[k])}/{len(ocr_pii[k])}"
            for k in PII_PATTERNS if truth_pii[k] or ocr_pii[k]
        )
        print(f"{name:<30} {recall:.0%}            {counts}")


if __name__ == "__main__":
    benchmark()