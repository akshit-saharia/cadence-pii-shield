import pymupdf
import pdfplumber
import uuid
from schemas import ExtractionResult, TextBlock, ExtractedImage

def extract_pdf(file_path: str) -> ExtractionResult:
    result = ExtractionResult(file=file_path, success=False)
    
    try:
        doc = pymupdf.open(file_path)
        result.metadata["pdf_metadata"] = doc.metadata
        result.metadata["page_count"] = len(doc)
    except Exception as e:
        result.errors.append(f"Failed to open PDF with PyMuPDF: {str(e)}")
        return result
        
    try:
        pdf_plumber_doc = pdfplumber.open(file_path)
    except Exception as e:
        result.warnings.append(f"Failed to open PDF with pdfplumber: {str(e)}. Table extraction may fail.")
        pdf_plumber_doc = None

    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        
        # Extract native text blocks
        blocks = page.get_text("blocks")
        native_text_len = 0
        for b in blocks:
            # b is (x0, y0, x1, y1, text, block_no, block_type)
            if len(b) >= 7 and b[6] == 0: # text block
                text = b[4].strip()
                if not text:
                    continue
                native_text_len += len(text)
                
                result.text_blocks.append(TextBlock(
                    id=str(uuid.uuid4()),
                    file=file_path,
                    page_or_slide=page_num + 1,
                    text=text,
                    bbox=[b[0], b[1], b[2], b[3]],
                    source="native",
                    block_type="text",
                ))
        
        if native_text_len < 50:
            result.warnings.append(f"Page {page_num + 1} has very little native text. May require OCR.")
            
        # Extract images
        image_list = page.get_images(full=True)
        for img_info in image_list:
            xref = img_info[0]
            try:
                base_image = doc.extract_image(xref)
                image_bytes = base_image["image"]
                result.images.append(ExtractedImage(
                    id=str(uuid.uuid4()),
                    file=file_path,
                    page_or_slide=page_num + 1,
                    image_bytes=image_bytes,
                    metadata={"ext": base_image.get("ext"), "colorspace": base_image.get("colorspace")}
                ))
            except Exception as e:
                result.warnings.append(f"Failed to extract image on page {page_num + 1}: {str(e)}")

        # Extract tables with pdfplumber
        if pdf_plumber_doc and page_num < len(pdf_plumber_doc.pages):
            try:
                plumber_page = pdf_plumber_doc.pages[page_num]
                tables = plumber_page.extract_tables()
                for table in tables:
                    table_text = "\n".join(["\t".join([str(cell) if cell else "" for cell in row]) for row in table])
                    if table_text.strip():
                        result.text_blocks.append(TextBlock(
                            id=str(uuid.uuid4()),
                            file=file_path,
                            page_or_slide=page_num + 1,
                            text=table_text,
                            source="native",
                            block_type="table",
                        ))
            except Exception as e:
                result.warnings.append(f"Failed to extract tables on page {page_num + 1}: {str(e)}")
                
    doc.close()
    if pdf_plumber_doc:
        pdf_plumber_doc.close()
        
    result.success = True
    return result
