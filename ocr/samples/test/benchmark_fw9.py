from ocr.ocr_pipeline import ocr

# Ground truth = form labels (word tokenized) that a human reads on each page
GT = {
    "fw9_page1": (
        "Form W-9 Request Taxpayer Identification Number Certification "
        "Name entity individual Business name disregarded entity "
        "Check box federal tax classification Individual sole proprietor "
        "C corporation S corporation Partnership Trust estate LLC "
        "Enter tax classification Social security number Employer "
        "identification number Signature Date"
    ).lower().split(),
    "fw9_page2": (
        "Form W-9 Page 2 taxpayer identification number TIN "
        "social security number SSN individual taxpayer identification "
        "number ITIN adoption taxpayer identification number ATIN "
        "employer identification number EIN"
    ).lower().split(),
}


def main():
    print(f"{'Page':<12} {'GT words found':<18} {'Total GT':<12} {'Recall':<10} {'Avg Conf'}")
    print("-" * 70)
    for name, gt_words in GT.items():
        blocks = ocr(f"ocr/samples/test/{name}.png", "fw9.pdf", 1)
        ocr_text = " ".join(b.text for b in blocks).lower()
        found = sum(1 for w in gt_words if w in ocr_text)
        avg_conf = sum(b.ocr_conf for b in blocks) / len(blocks) if blocks else 0
        recall = found / len(gt_words)
        print(f"{name:<12} {found:<18} {len(gt_words):<12} {recall:.0%}       {avg_conf:.3f}")


if __name__ == "__main__":
    main()