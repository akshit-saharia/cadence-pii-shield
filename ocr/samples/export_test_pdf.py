import fitz
import os

PDF = "fw9.pdf"
OUT = "ocr/samples/test"
os.makedirs(OUT, exist_ok=True)

doc = fitz.open(PDF)
print(f"Total pages: {len(doc)}")

# Export first 2 pages at 300 DPI
for i in range(min(2, len(doc))):
    page = doc[i]
    pix = page.get_pixmap(dpi=300)
    path = f"{OUT}/fw9_page{i+1}.png"
    pix.save(path)
    print(f"Saved {path}")