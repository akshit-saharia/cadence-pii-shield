import re
from typing import List, Union
from schemas import TextBlock

def normalize_text(text: str) -> str:
    """Normalizes whitespace and standardizes punctuation for comparison."""
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    return text

def calculate_retention(extracted: Union[str, List[TextBlock]], reference: str) -> dict:
    """
    Compares extracted text with a trusted original reference.
    Returns the percentage of reference text successfully extracted.
    """
    if isinstance(extracted, list):
        extracted_text = " ".join([block.text for block in extracted])
    else:
        extracted_text = extracted

    norm_ref = normalize_text(reference)
    norm_ext = normalize_text(extracted_text)

    if not norm_ref:
        return {
            "retention_score": 100.0,
            "meets_target": True,
            "message": "Empty reference text, trivially meets target."
        }

    ref_words = norm_ref.split()
    ext_words = norm_ext.split()
    
    if not ref_words:
        return {"retention_score": 100.0, "meets_target": True}

    match_count = 0
    from collections import Counter
    ref_counter = Counter(ref_words)
    ext_counter = Counter(ext_words)
    
    for word, count in ref_counter.items():
        match_count += min(count, ext_counter.get(word, 0))
        
    score = (match_count / len(ref_words)) * 100
    
    return {
        "retention_score": round(score, 2),
        "meets_target": score >= 80.0,
        "message": f"Retention score is {score:.2f}%"
    }
