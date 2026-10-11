import os
from schemas import ExtractionResult
from extraction.pdf_extractor import extract_pdf
from extraction.docx_extractor import extract_docx
from extraction.pptx_extractor import extract_pptx

def extract_file(file_path: str) -> ExtractionResult:
    if not os.path.exists(file_path):
        return ExtractionResult(
            file=file_path,
            success=False,
            errors=[f"File not found: {file_path}"]
        )
    
    ext = os.path.splitext(file_path)[1].lower()
    
    try:
        if ext == ".pdf":
            return extract_pdf(file_path)
        elif ext == ".docx":
            return extract_docx(file_path)
        elif ext == ".pptx":
            return extract_pptx(file_path)
        else:
            return ExtractionResult(
                file=file_path,
                success=False,
                errors=[f"Unsupported file format: {ext}"]
            )
    except Exception as e:
        return ExtractionResult(
            file=file_path,
            success=False,
            errors=[f"Extraction failed with error: {str(e)}"]
        )
