import os
import shutil

import pytesseract
from pytesseract import Output
import numpy as np

# Portable Tesseract resolution: env var > PATH > fallback Windows path
pytesseract.pytesseract.tesseract_cmd = (
    os.environ.get("TESSERACT_CMD")
    or shutil.which("tesseract")
    or r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


def run_tesseract(image: np.ndarray, psm: int = 6) -> list[dict]:
    config = f"--oem 3 --psm {psm}"
    data = pytesseract.image_to_data(image, output_type=Output.DICT, config=config)

    words = []
    for i in range(len(data["text"])):
        text = data["text"][i].strip()
        conf = int(data["conf"][i])
        if not text or conf < 0:
            continue
        words.append({
            "text": text,
            "conf": conf / 100.0,
            "bbox": (data["left"][i], data["top"][i],
                     data["left"][i] + data["width"][i],
                     data["top"][i] + data["height"][i]),
            "block_num": data["block_num"][i],
            "par_num": data["par_num"][i],
            "line_num": data["line_num"][i],
        })
    return words