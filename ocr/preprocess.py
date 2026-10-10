import cv2
import numpy as np


def preprocess(image_path: str) -> np.ndarray:
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Could not load image: {image_path}")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    if gray.mean() < 120:
        gray = cv2.bitwise_not(gray)

    gray = cv2.fastNlMeansDenoising(gray, h=15)

    h, w = gray.shape
    # Target at least 3000px wide for tiny UI text; caps at 4x to avoid huge images
    if w < 3000:
        scale = min(3000 / w, 4.0)
    else:
        scale = 1.0
    gray = cv2.resize(gray, None, fx=scale, fy=scale,
                      interpolation=cv2.INTER_CUBIC)

    return gray