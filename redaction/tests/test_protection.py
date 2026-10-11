import json
import re

import pytest

from schemas import Finding, TextBlock
from redaction import ProtectionPipeline, Vault
from redaction.classifier import classify
from redaction.gate import FailClosedGate
from redaction.models import RedactedBlock
from redaction.redactor import RedactionError, Redactor
from redaction.tokenizer import Tokenizer


# ---- stand-in for P3's DetectionEngine (same public surface) ----------------------
class FakeEngine:
    PATTERNS = [("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
                ("EMAIL", r"[\w.]+@[\w.]+\.\w+"),
                ("PERSON", r"(?<=Name: )[A-Z][a-z]+ [A-Z][a-z]+"),
                ("PAN", r"\b[A-Z]{5}\d{4}[A-Z]\b"),
                ("DOB", r"\b\d{2}/\d{2}/\d{4}\b"),
                ("PHONE", r"\+91 \d{5} \d{5}")]

    def detect_block(self, b):
        out = []
        for ent, rx in self.PATTERNS:
            for m in re.finditer(rx, b.text):
                out.append(Finding(b.id, ent, m.start(), m.end(), m.group(0), 0.9, "regex", b.source))
        return sorted(out, key=lambda f: f.start)

    def detect(self, blocks):
        return [f for b in blocks for f in self.detect_block(b)]

    def detect_text(self, text, origin="native", block_id="adhoc"):
        return self.detect_block(TextBlock(block_id, "", 0, text, None, origin, 1.0))


def tb(id_, file, text, source="native", conf=1.0, page=1):
    return TextBlock(id_, file, page, text, None, source, conf)


def F(block, ent, text, full):
    s = full.index(text)
    return Finding(block, ent, s, s + len(text), text, 0.9, "regex")


@pytest.fixture
def vault(tmp_path):
    return Vault(session_id="t", vault_dir=tmp_path)


# ---- classifier -------------------------------------------------------------------
def test_classify_tiers_and_no_pii():
    assert classify([]).label == "NO_PII_FOUND"
    assert classify([F("b", "PERSON", "Ann Lee", "Name: Ann Lee")]).label == "INTERNAL"
    assert classify([F("b", "EMAIL", "a@b.co", "a@b.co")]).label == "CONFIDENTIAL"
    assert classify([F("b", "SSN", "123-45-6789", "123-45-6789")]).label == "RESTRICTED"
    assert classify([], failed=True).label == "UNCLASSIFIED"


def test_identity_bundle_escalates():
    t = "Ann Lee 01/01/1990 a@b.co"
    fs = [F("b", "PERSON", "Ann Lee", t), F("b", "DOB", "01/01/1990", t), F("b", "EMAIL", "a@b.co", t)]
    c = classify(fs)
    assert c.label == "RESTRICTED" and c.escalated


def test_unknown_entity_is_high():
    assert classify([F("b", "MYSTERY", "xx", "xx")]).tier == "HIGH"


# ---- vault ------------------------------------------------------------------------
def test_vault_consistency_and_roundtrip(vault):
    a = vault.tokenise("PERSON", "Priya Nair")
    assert a == "[PERSON_1]"
    assert vault.tokenise("PERSON", "  priya   NAIR ") == a        # same person, same token
    assert vault.tokenise("PERSON", "Rahul Verma") == "[PERSON_2]"
    assert vault.detokenise("Hi [PERSON_1] and [PERSON_2] and [PERSON_9]") == \
        "Hi Priya Nair and Rahul Verma and [PERSON_9]"


def test_vault_save_load(vault, tmp_path):
    vault.tokenise("EMAIL", "a@b.co")
    vault.save()
    again = Vault.load("t", tmp_path)
    assert again.detokenise("[EMAIL_1]") == "a@b.co"
    assert again.tokenise("EMAIL", "A@B.CO") == "[EMAIL_1]"


# ---- redactor ---------------------------------------------------------------------
def test_redaction_offsets_and_modes(vault):
    t = "Name: Priya Nair, SSN 123-45-6789."
    b = tb("b1", "f", t)
    rb = Redactor(vault).redact_block(b, [F("b1", "PERSON", "Priya Nair", t), F("b1", "SSN", "123-45-6789", t)])
    assert rb.text == "Name: [PERSON_1], SSN [REDACTED:SSN]."
    for r in rb.replacements:
        assert rb.text[r.new_start:r.new_end] == r.token
    assert [r.reversible for r in rb.replacements] == [True, False]
    assert "123-45-6789" not in json.dumps(vault._tokens)          # HIGH tier never stored


def test_overlap_merges_to_widest_span(vault):
    t = "call 98765 43210 now"
    fs = [Finding("b", "PHONE", 5, 16, "98765 43210", .9, "r"), Finding("b", "PERSON", 5, 10, "98765", .9, "r")]
    rb = Redactor(vault).redact_block(tb("b", "f", t), fs)
    assert rb.text == "call [PHONE_1] now" and rb.replacements[0].merged


def test_stale_offsets_raise(vault):
    bad = Finding("b", "SSN", 0, 11, "123-45-6789", .9, "r")
    with pytest.raises(RedactionError):
        Redactor(vault).redact_block(tb("b", "f", "something else entirely"), [bad])


def test_orphan_findings_raise(vault):
    with pytest.raises(RedactionError):
        Redactor(vault).redact([tb("b", "f", "x")], [Finding("ghost", "SSN", 0, 1, "x", .9, "r")])


# ---- gate -------------------------------------------------------------------------
def _gate():
    return FailClosedGate(detect_fn=FakeEngine().detect_text)


def test_gate_allows_clean():
    b = tb("b", "f", "Quarterly policy review.")
    d = _gate().evaluate("f", [b], [RedactedBlock("b", "f", 1, b.text)], [])
    assert d.allowed


def test_gate_blocks_residual_pii():
    b = tb("b", "f", "mail a@b.co")
    leaky = RedactedBlock("b", "f", 1, "mail a@b.co")                 # redaction did nothing
    d = _gate().evaluate("f", [b], [leaky], [])
    assert not d.allowed and "RESIDUAL_PII" in d.codes
    assert all("text" not in r for r in d.residual)                   # no raw values in the audit trail


def test_gate_ignores_tokens():
    b = tb("b", "f", "mail [EMAIL_1] and [REDACTED:SSN]")
    d = _gate().evaluate("f", [b], [RedactedBlock("b", "f", 1, b.text)], [])
    assert d.allowed


def test_gate_blocks_surviving_value():
    t = "SSN 123-45-6789"
    b = tb("b", "f", t)
    rb = RedactedBlock("b", "f", 1, "SSN [REDACTED:SSN] (dup 123-45-6789)")
    d = _gate().evaluate("f", [b], [rb], [F("b", "SSN", "123-45-6789", t)])
    assert "VALUE_SURVIVED" in d.codes


def test_gate_blocks_low_ocr_and_scale_normalisation():
    low = tb("b", "f", "some scanned words", "ocr", 0.3)
    assert "LOW_OCR_CONFIDENCE" in _gate().evaluate("f", [low], [RedactedBlock("b", "f", 1, low.text)], []).codes
    pct = tb("b", "f", "some scanned words", "ocr", 91)               # 0-100 scale
    assert _gate().evaluate("f", [pct], [RedactedBlock("b", "f", 1, pct.text)], []).allowed


def test_gate_blocks_no_text_and_errors():
    assert "NO_TEXT_EXTRACTED" in _gate().evaluate("f", [tb("b", "f", "  ")], [], []).codes
    d = _gate().evaluate("f", [tb("b", "f", "x")], [], [], errors=["boom"])
    assert "PIPELINE_ERROR" in d.codes


def test_gate_blocks_when_rescan_crashes():
    def broken(*a, **k):
        raise RuntimeError("spacy missing")
    b = tb("b", "f", "hello")
    d = FailClosedGate(detect_fn=broken).evaluate("f", [b], [RedactedBlock("b", "f", 1, "hello")], [])
    assert "RESCAN_FAILED" in d.codes


# ---- end to end -------------------------------------------------------------------
def _pipe(tmp_path, engine=None):
    return ProtectionPipeline(engine=engine or FakeEngine(), vault=Vault("t", tmp_path), ocr_fn=None)


def test_end_to_end(tmp_path):
    blocks = [
        tb("h1", "hr.docx", "Name: Priya Nair, DOB: 14/03/1989, SSN 123-45-6789, email priya@example.com"),
        tb("c1", "clean.pdf", "Policy text with no personal data."),
        tb("k1", "scan.pdf", "PAN: ABCDE1234F", "ocr", 0.2),
    ]
    res = _pipe(tmp_path).run(blocks)
    by = {f.file: f for f in res.files}
    assert by["hr.docx"].decision.allowed and by["hr.docx"].classification.label == "RESTRICTED"
    assert by["clean.pdf"].decision.allowed and by["clean.pdf"].classification.label == "NO_PII_FOUND"
    assert not by["scan.pdf"].decision.allowed and by["scan.pdf"].released == []

    payload = res.llm_payload()
    assert set(payload) == {"hr.docx", "clean.pdf"}
    for secret in ("123-45-6789", "Priya Nair", "priya@example.com", "14/03/1989"):
        assert secret not in payload["hr.docx"]
    assert "[PERSON_1]" in payload["hr.docx"]
    assert res.rehydrate("Hello [PERSON_1]") == "Hello Priya Nair"
    assert res.rehydrate("[REDACTED:SSN]") == "[REDACTED:SSN]"          # masks are irreversible


def test_engine_crash_blocks_only_that_file(tmp_path):
    class Flaky(FakeEngine):
        def detect(self, blocks):
            if blocks[0].file == "bad.pdf":
                raise RuntimeError("OCR model crashed")
            return super().detect(blocks)

    res = _pipe(tmp_path, Flaky()).run([tb("a", "bad.pdf", "x"), tb("b", "ok.pdf", "fine")])
    by = {f.file: f for f in res.files}
    assert not by["bad.pdf"].decision.allowed and by["bad.pdf"].classification.label == "UNCLASSIFIED"
    assert by["ok.pdf"].decision.allowed


def test_report_has_no_raw_pii(tmp_path):
    res = _pipe(tmp_path).run([tb("h", "hr.docx", "Name: Priya Nair, SSN 123-45-6789, email priya@example.com")])
    blob = json.dumps(res.report())
    for secret in ("123-45-6789", "Priya Nair", "priya@example.com"):
        assert secret not in blob
    s = res.report()["summary"]
    assert s["pii_to_llm_without_protection"] == 3 and s["pii_to_llm_with_protection"] == 0


def test_real_engine_smoke(tmp_path):
    try:
        from detection import DetectionEngine
        engine = DetectionEngine(use_ner=False)
    except Exception as exc:                                           # P3 deps not installed here
        pytest.skip(f"real detection engine unavailable: {exc}")
    res = ProtectionPipeline(engine=engine, vault=Vault("t", tmp_path)).run(
        [tb("d", "demo.txt", "Name: Priya Nair, DOB: 14/03/1989, SSN 123-45-6789, EMP-38104")])
    assert "123-45-6789" not in res.llm_payload().get("demo.txt", "")


def test_tokenizer_decision(vault):
    t = Tokenizer(vault)
    assert t.replacement("PERSON", "Ann Lee") == ("[PERSON_1]", True, "LOW")
    assert t.replacement("SSN", "123-45-6789") == ("[REDACTED:SSN]", False, "HIGH")
    assert len(vault) == 1


# ---- extraction hookup (P1) -------------------------------------------------------
from types import SimpleNamespace as NS


def ex_result(file, blocks=(), images=(), warnings=(), errors=(), success=True, metadata=None):
    return NS(file=file, success=success, text_blocks=list(blocks), images=list(images),
              warnings=list(warnings), errors=list(errors), metadata=metadata or {})


def img(page):
    return NS(id="i", file="f", page_or_slide=page, image_bytes=b"\x00", metadata={})


def run_with(tmp_path, results):
    by_name = {r.file: r for r in results}
    return _pipe(tmp_path).run_files(list(by_name), extractor=lambda p: by_name[p])


def test_extraction_failure_blocks_and_is_reported(tmp_path):
    res = run_with(tmp_path, [
        ex_result("broken.pdf", success=False, errors=["Failed to open PDF with PyMuPDF: bad header"]),
        ex_result("notes.txt", success=False, errors=["Unsupported file format: .txt"]),
        ex_result("ok.docx", [tb("a", "ok.docx", "Nothing personal in this paragraph at all.")])])
    by = {f.file: f for f in res.files}
    assert not by["broken.pdf"].decision.allowed and "PIPELINE_ERROR" in by["broken.pdf"].decision.codes
    assert by["notes.txt"].classification.label == "UNCLASSIFIED"
    assert by["ok.docx"].decision.allowed
    assert set(res.llm_payload()) == {"ok.docx"}
    assert {f["file"] for f in res.report()["files"]} == {"broken.pdf", "notes.txt", "ok.docx"}


def test_extractor_exception_blocks(tmp_path):
    def boom(_):
        raise RuntimeError("segfault in pymupdf")
    res = _pipe(tmp_path).run_files(["x.pdf"], extractor=boom)
    assert not res.files[0].decision.allowed


def test_scanned_page_without_ocr_is_blocked(tmp_path):
    scan = ex_result("scan.pdf", [tb("a", "scan.pdf", "p")], images=[img(1)],
                     warnings=["Page 1 has very little native text. May require OCR."])
    d = run_with(tmp_path, [scan]).files[0].decision
    assert "UNSCANNED_IMAGE_PAGE" in d.codes


def test_logo_on_text_page_is_fine_but_noted(tmp_path):
    body = "This page is full of ordinary policy text with no personal data. " * 3
    res = run_with(tmp_path, [ex_result("memo.pdf", [tb("a", "memo.pdf", body)], images=[img(1)])])
    d = res.files[0].decision
    assert d.allowed and any("not text-scanned" in w for w in d.warnings)


def test_ocr_blocks_cover_an_image_page(tmp_path):
    ocr = tb("o", "id.pdf", "Short OCR text", "ocr", 0.9)
    res = run_with(tmp_path, [ex_result("id.pdf", [ocr], images=[img(1)])])
    assert "UNSCANNED_IMAGE_PAGE" not in res.files[0].decision.codes


def test_metadata_is_withheld_and_never_in_output(tmp_path):
    md = {"page_count": 2, "pdf_metadata": {"author": "Jane Q. Secretary", "title": ""}}
    res = run_with(tmp_path, [ex_result("a.pdf", [tb("a", "a.pdf", "Plain text only here.")], metadata=md)])
    blob = json.dumps(res.report()) + json.dumps(res.llm_payload())
    assert "Jane Q. Secretary" not in blob
    assert "pdf_metadata.author" in res.report()["files"][0]["metadata_withheld"]


def test_duplicate_table_text_counts_once_as_distinct(tmp_path):
    t = "Name: Priya Nair, SSN 123-45-6789"
    res = run_with(tmp_path, [ex_result("t.pdf", [tb("a", "t.pdf", t), tb("b", "t.pdf", t)])])
    f = res.report()["files"][0]
    assert sum(f["pii_by_entity"].values()) == 4 and f["pii_distinct_values"] == 2


def test_block_type_survives_redaction(tmp_path):
    b = tb("a", "t.docx", "Name: Priya Nair")
    b.block_type = "table"
    res = run_with(tmp_path, [ex_result("t.docx", [b])])
    assert res.files[0].redacted_blocks[0].block_type == "table"
