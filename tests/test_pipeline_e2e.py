"""End-to-end: real DOCX -> extraction -> detection -> redaction -> gate -> LLM payload (no OCR, no PDF needed)."""
import docx

from pipeline import protect
from redaction import Vault, ProtectionPipeline
from redaction.pipeline import load_blocks

SECRETS = ["123-45-6789", "priya@example.com", "Priya Nair"]


def _make_docx(path):
    d = docx.Document()
    d.add_paragraph("Employee record. Name: Priya Nair, SSN 123-45-6789, email priya@example.com. " * 2)
    d.save(path)
    return str(path)


def test_docx_end_to_end(tmp_path):
    f = _make_docx(tmp_path / "hr.docx")
    pipe = ProtectionPipeline(vault=Vault("t", tmp_path / "vault"), ocr_fn=None)
    res = pipe.run_files([f])
    out = res.files[0]
    assert out.decision.allowed, out.decision.reasons
    payload = res.llm_payload()[f]
    for s in SECRETS:
        assert s not in payload
    assert "[REDACTED:SSN]" in payload and "[EMAIL_1]" in payload
    # LLM answer mentioning a token can be re-hydrated for the user
    assert "priya@example.com" in res.rehydrate("Please contact [EMAIL_1].")


def test_demo_blocks_gate_blocks_low_confidence_ocr(tmp_path):
    blocks = load_blocks("data/sample_blocks.json")
    res = ProtectionPipeline(vault=Vault("t", tmp_path), ocr_fn=None).run(blocks)
    by = {x.file: x for x in res.files}
    assert not by["kyc_scan.pdf"].decision.allowed            # OCR conf 0.38 -> fail closed
    assert "kyc_scan.pdf" not in res.llm_payload()
    assert by["hr_onboarding.docx"].decision.allowed
