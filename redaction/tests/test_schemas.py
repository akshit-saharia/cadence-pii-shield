import json

from schemas import (ExtractedImage, ExtractionResult, Finding, TextBlock)
from redaction import ProtectionPipeline, Vault
from redaction.gate import FailClosedGate
from redaction.models import RedactedBlock
from redaction.tests.test_protection import FakeEngine


def test_p3_positional_construction_still_works():
    b = TextBlock("demo", "demo.txt", 1, "Name: Priya Nair", None, "native", 1.0)
    assert (b.id, b.page_or_slide, b.text, b.source, b.ocr_conf) == ("demo", 1, "Name: Priya Nair", "native", 1.0)
    d = TextBlock(id="x", file="", page_or_slide=0, text="t", bbox=None, source="native", ocr_conf=1.0)
    assert d.text == "t"                                   # exactly how engine.detect_text builds it


def test_p1_keyword_only_construction_works():
    b = TextBlock(id="1", file="f", block_type="text", source="n", text="hello")   # P1 retention test style
    assert b.page_or_slide is None and b.bbox is None and b.ocr_conf == 1.0
    p = TextBlock(id="2", file="f", page_or_slide=3, text="t", source="native", block_type="notes",
                  metadata={"shape_name": "Title 1"})
    assert p.metadata["shape_name"] == "Title 1"


def test_ocr_without_confidence_is_unknown_and_gate_blocks():
    b = TextBlock(id="o", file="f", page_or_slide=1, text="some scanned words here", source="ocr")
    assert b.ocr_conf is None and b.is_ocr
    d = FailClosedGate(detect_fn=FakeEngine().detect_text).evaluate(
        "f", [b], [RedactedBlock("o", "f", 1, b.text)], [])
    assert "LOW_OCR_CONFIDENCE" in d.codes


def test_extraction_result_defaults_and_json():
    assert ExtractionResult(file="x", success=False, errors=["File not found: x"]).errors
    r = ExtractionResult(file="a.docx", success=True)
    r.text_blocks.append(TextBlock(id="1", file="a.docx", text="hi"))
    r.images.append(ExtractedImage(id="i", file="a.docx", image_bytes=b"\x89PNG\x00\x01"))
    out = json.loads(json.dumps(r.to_dict()))              # bytes must not break JSON
    assert out["images"][0]["size_bytes"] == 6


def test_finding_to_dict():
    f = Finding("b", "SSN", 0, 3, "123", 0.9, "regex")
    assert f.to_dict()["origin"] == "native" and f.to_dict()["reasons"] == []


def test_docx_style_blocks_without_pages_end_to_end(tmp_path):
    """DOCX: page_or_slide=None everywhere, header/footer/table blocks, real ExtractionResult objects."""
    res = ExtractionResult(file="hr.docx", success=True, metadata={"title": "HR", "author": "Jane Q. Secretary"})
    res.text_blocks += [
        TextBlock(id="p", file="hr.docx", text="Name: Priya Nair, SSN 123-45-6789", block_type="text"),
        TextBlock(id="t", file="hr.docx", text="Cell 1\tCell 2", block_type="table"),
        TextBlock(id="h", file="hr.docx", text="Confidential - contact priya@example.com", block_type="header"),
    ]
    res.images.append(ExtractedImage(id="i", file="hr.docx", image_bytes=b"x"))     # no page -> None
    pipe = ProtectionPipeline(engine=FakeEngine(), vault=Vault("t", tmp_path), ocr_fn=None)
    out = pipe.run_files(["hr.docx"], extractor=lambda p: res)
    f = out.files[0]
    assert f.decision.allowed, f.decision.reasons              # text is long enough, image is covered
    payload = out.llm_payload()["hr.docx"]
    assert "None" not in payload and "[header]" in payload and "[table]" in payload
    assert "123-45-6789" not in payload and "priya@example.com" not in payload
    rep = out.report()["files"][0]
    assert "document" in rep["pii_by_location"] and "Jane Q. Secretary" not in json.dumps(out.report())
    assert {"author", "title"} <= set(rep["metadata_withheld"])


def test_docx_image_only_document_is_blocked(tmp_path):
    res = ExtractionResult(file="scan.docx", success=True)
    res.text_blocks.append(TextBlock(id="p", file="scan.docx", text="See attached."))
    res.images.append(ExtractedImage(id="i", file="scan.docx", image_bytes=b"x"))
    out = ProtectionPipeline(engine=FakeEngine(), vault=Vault("t", tmp_path), ocr_fn=None).run_files(
        ["scan.docx"], extractor=lambda p: res)
    assert "UNSCANNED_IMAGE_PAGE" in out.files[0].decision.codes
    assert "The document" in out.files[0].decision.reasons[0]["message"]
