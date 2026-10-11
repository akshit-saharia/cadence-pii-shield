import io
import json
import os
import shutil

import pytest
from PIL import Image

from schemas import ExtractedImage, ExtractionResult, Finding, TextBlock
from redaction import ProtectionPipeline, Vault
from redaction.ocr_stage import email_fragment_findings, run_ocr
from redaction.tests.test_protection import FakeEngine


def png(w=300, h=120, color="white") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, "PNG")
    return buf.getvalue()


def image(page=1, data=None, ext="png"):
    return ExtractedImage(id="i", file="f", page_or_slide=page, image_bytes=data or png(), metadata={"ext": ext})


def line(text, conf=0.9, page=1):
    return TextBlock(id="x", file="f", page_or_slide=page, text=text, source="ocr", ocr_conf=conf)


class StubOcr:
    """Stands in for ocr.ocr_pipeline.ocr_with_stats and records what it was called with."""
    def __init__(self, blocks=(), stats=None, exc=None):
        self.blocks, self.stats, self.exc, self.calls = list(blocks), stats, exc, []

    def __call__(self, path, file, page):
        assert os.path.exists(path)                              # bytes were written to a real file
        self.calls.append((path, file, page))
        if self.exc:
            raise self.exc
        return list(self.blocks), self.stats


def stats(total, kept):
    return {"words_total": total, "words_kept": kept, "words_dropped": total - kept}


# ---- run_ocr -----------------------------------------------------------------------
def test_ocr_runs_on_bytes_and_cleans_up_temp_file():
    stub = StubOcr([line("SSN 123-45-6789")], stats(3, 3))
    out = run_ocr([image(page=2)], stub, file="scan.pdf")
    assert [b.text for b in out.blocks] == ["SSN 123-45-6789"]
    assert out.blocks[0].page_or_slide == 2 and out.blocks[0].file == "scan.pdf" and out.blocks[0].is_ocr
    assert not os.path.exists(stub.calls[0][0]) and stub.calls[0][0].endswith(".png")
    assert out.unscanned_images == [] and out.summary["images_scanned"] == 1


def test_tiny_images_are_skipped_and_vouched():
    stub = StubOcr()
    out = run_ocr([image(data=png(16, 16))], stub)
    assert stub.calls == [] and out.unscanned_images == [] and out.summary["images_skipped_small"] == 1


def test_identical_images_ocr_once_but_every_page_gets_blocks():
    stub = StubOcr([line("Quarterly figures")], stats(2, 2))
    same = png()
    out = run_ocr([image(1, same), image(2, same), image(3, same)], stub)
    assert len(stub.calls) == 1 and [b.page_or_slide for b in out.blocks] == [1, 2, 3]
    assert len({b.id for b in out.blocks}) == 3


def test_undecodable_image_is_a_warning_and_unscanned():
    out = run_ocr([image(data=png())], StubOcr(exc=ValueError("Could not load image")))
    assert not out.errors and len(out.unscanned_images) == 1 and "could not be decoded" in out.warnings[0]


def test_engine_failure_is_an_error():
    out = run_ocr([image()], StubOcr(exc=RuntimeError("tesseract is not installed")))
    assert out.errors and "tesseract is not installed" in out.errors[0] and out.unscanned_images


def test_vouching_uses_word_stats():
    logo = run_ocr([image()], StubOcr([], stats(0, 0)))                   # nothing seen: logo / photo
    junk = run_ocr([image()], StubOcr([], stats(2, 0)))                   # 2 junk words: still a logo
    unreadable = run_ocr([image()], StubOcr([], stats(40, 0)))            # fig11 case
    good = run_ocr([image()], StubOcr([line("ok")], stats(40, 38)))
    assert logo.unscanned_images == [] and junk.unscanned_images == []
    assert len(unreadable.unscanned_images) == 1 and "none readable" in unreadable.warnings[0]
    assert good.unscanned_images == [] and "2 of 40 words dropped" in good.warnings[0]


def test_dropped_ratio_rule_is_opt_in(monkeypatch):
    from redaction import policy
    mostly_lost = StubOcr([line("a b")], stats(40, 10))
    assert run_ocr([image()], mostly_lost).unscanned_images == []
    monkeypatch.setattr(policy, "OCR_MAX_DROPPED_RATIO", 0.4)
    assert len(run_ocr([image()], StubOcr([line("a b")], stats(40, 10))).unscanned_images) == 1


def test_without_stats_empty_result_cannot_be_vouched():
    assert len(run_ocr([image()], StubOcr([], None)).unscanned_images) == 1
    assert run_ocr([image()], StubOcr([line("text")], None)).unscanned_images == []


# ---- fragment sweep ----------------------------------------------------------------
def test_sweep_catches_broken_email_but_not_covered_or_plain_text():
    b = line("Owner daniel.kim@acme and full m.achebe@cadencefg.com meet @ 5pm")
    b.id = "b"
    full_start = b.text.index("m.achebe")
    full = Finding("b", "EMAIL", full_start, full_start + len("m.achebe@cadencefg.com"),
                   "m.achebe@cadencefg.com", 0.9, "regex")
    got = email_fragment_findings([b], [full])
    assert [f.text for f in got] == ["daniel.kim@acme"] and got[0].detector == "ocr_sweep"


def test_sweep_ignores_native_blocks():
    nb = TextBlock(id="n", file="f", text="x@y", source="native")
    assert email_fragment_findings([nb], []) == []


# ---- pipeline with OCR -------------------------------------------------------------
def _scan(file="scan.pdf", page=1):
    r = ExtractionResult(file=file, success=True,
                         warnings=["Page 1 has very little native text. May require OCR."])
    r.images.append(image(page))
    return r


def _pipe(tmp_path, ocr_fn):
    return ProtectionPipeline(engine=FakeEngine(), vault=Vault("t", tmp_path), ocr_fn=ocr_fn)


def test_scanned_pdf_is_ocrd_redacted_and_released(tmp_path):
    stub = StubOcr([line("Name: Priya Nair SSN 123-45-6789"), line("mail priya.nair@acme")], stats(8, 8))
    res = _pipe(tmp_path, stub).run_files(["scan.pdf"], extractor=lambda p: _scan())
    f = res.files[0]
    assert f.decision.allowed, f.decision.reasons
    payload = res.llm_payload()["scan.pdf"]
    for secret in ("123-45-6789", "Priya Nair", "priya.nair@acme"):
        assert secret not in payload
    assert f.ocr["images_scanned"] == 1 and f.ocr["sweep_fragments"] == 1
    assert "123-45-6789" not in json.dumps(res.report())


def test_unreadable_scan_is_blocked(tmp_path):
    res = _pipe(tmp_path, StubOcr([], stats(60, 0))).run_files(["fig11.pdf"], extractor=lambda p: _scan("fig11.pdf"))
    assert not res.files[0].decision.allowed and "UNSCANNED_IMAGE_PAGE" in res.files[0].decision.codes
    assert res.llm_payload() == {}


def test_ocr_unavailable_blocks_scanned_pages_and_says_so(tmp_path):
    res = _pipe(tmp_path, None).run_files(["scan.pdf"], extractor=lambda p: _scan())
    f = res.files[0]
    assert not f.decision.allowed and f.ocr == {"available": False, "images_total": 1}
    assert "OCR: not available" in __import__("redaction.report", fromlist=["x"]).to_markdown(res.report())


def test_ocr_engine_crash_blocks_file(tmp_path):
    res = _pipe(tmp_path, StubOcr(exc=RuntimeError("tesseract missing"))).run_files(
        ["scan.pdf"], extractor=lambda p: _scan())
    assert "PIPELINE_ERROR" in res.files[0].decision.codes


def test_low_confidence_ocr_line_blocks(tmp_path):
    res = _pipe(tmp_path, StubOcr([line("blurry words here", conf=0.42)], stats(4, 3))).run_files(
        ["scan.pdf"], extractor=lambda p: _scan())
    assert "LOW_OCR_CONFIDENCE" in res.files[0].decision.codes


# ---- real chain: P1 extractor -> real Tesseract -> P4 ------------------------------------
def _tesseract_ok():
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


@pytest.fixture
def scanned_pdf(tmp_path):
    pymupdf = pytest.importorskip("pymupdf")
    pytest.importorskip("extraction.router")
    pytest.importorskip("ocr.ocr_pipeline")
    if not _tesseract_ok():
        pytest.skip("tesseract binary not available")
    from PIL import ImageDraw, ImageFont
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 34)
    except OSError:
        font = ImageFont.load_default(size=34)
    img = Image.new("RGB", (1500, 360), "white")
    d = ImageDraw.Draw(img)
    for i, t in enumerate(["NAME Miriam T. Achebe   EMPLOYEE ID EMP-38104",
                           "WORK E-MAIL m.achebe@cadencefg.com",
                           "SSN 123-45-6789   DOB 14/03/1989"]):
        d.text((40, 30 + i * 90), t, fill="black", font=font)
    png_path, pdf_path = tmp_path / "badge.png", tmp_path / "scan.pdf"
    img.save(png_path)
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_image(page.rect, filename=str(png_path))
    doc.save(str(pdf_path))
    return str(pdf_path)


def test_real_scanned_pdf_end_to_end(tmp_path, scanned_pdf):
    res = ProtectionPipeline(engine=FakeEngine(), vault=Vault("t", tmp_path)).run_files([scanned_pdf])
    f = res.files[0]
    assert f.decision.allowed, (f.decision.reasons, f.extraction_warnings)
    payload = list(res.llm_payload().values())[0]
    for secret in ("123-45-6789", "m.achebe@cadencefg.com", "14/03/1989"):
        assert secret not in payload
    assert f.ocr["images_scanned"] == 1 and f.ocr["ocr_blocks"] >= 3


def test_real_pipeline_with_ocr_switched_off_blocks_the_scan(tmp_path, scanned_pdf):
    res = ProtectionPipeline(engine=FakeEngine(), vault=Vault("t", tmp_path), ocr_fn=None).run_files([scanned_pdf])
    assert not res.files[0].decision.allowed
