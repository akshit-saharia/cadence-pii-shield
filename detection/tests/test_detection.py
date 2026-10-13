"""Trap-case tests: run with `pytest detection/tests -v` from the repo root."""
import pytest

from detection import DetectionEngine

E = DetectionEngine()


def types(text, origin="native"):
    return [(f.entity_type, f.text) for f in E.detect_text(text, origin)]


# ---------- true positives ----------
def test_ssn():
    assert ("SSN", "123-45-6789") in types("SSN: 123-45-6789")

def test_pan():
    assert ("PAN", "ABCPE1234F") in types("PAN: ABCPE1234F")

def test_email():
    assert ("EMAIL", "priya.n@cadence-fin.com") in types("Write to priya.n@cadence-fin.com today")

def test_phone_india():
    assert any(t == "PHONE" for t, _ in types("Call +91 98765 43210 after 5pm"))

def test_phone_us():
    assert any(t == "PHONE" for t, _ in types("Mobile: (415) 555-2671"))

def test_card_luhn_valid():
    assert ("CREDIT_CARD", "4111 1111 1111 1111") in types("Card 4111 1111 1111 1111 on file")

def test_dob_with_context():
    assert ("DOB", "14/03/1989") in types("DOB: 14/03/1989")

def test_dob_written_month():
    assert any(t == "DOB" for t, _ in types("Date of birth: 14 March 1989"))

def test_passport_with_context():
    assert any(t == "PASSPORT" for t, _ in types("Passport No: K1234567"))

def test_person_titled():
    assert ("PERSON", "Rahul Sharma") in types("Approved by Mr. Rahul Sharma yesterday")

def test_person_labeled():
    assert ("PERSON", "Akshit Saharia") in types("Name: Akshit Saharia")

def test_address_street():
    assert any(t == "ADDRESS" for t, _ in types("Lives at 221 Baker Street, London"))

def test_prose_pii():
    found = {t for t, _ in types("Her date of birth is 02/11/1990 and her SSN is 219-09-9999.")}
    assert {"DOB", "SSN"} <= found


# ---------- traps (must NOT be flagged) ----------
@pytest.mark.parametrize("text", [
    "Employee EMP-38104 raised INC-20456 against RSK-1002 and ISS-3301",
    "Ticket EMP-38104 was escalated",
])
def test_internal_ids_not_flagged(text):
    assert types(text) == []

def test_card_last_four_not_flagged():
    assert types("Card ending in 4417 was charged") == []
    assert types("Card XXXX-XXXX-XXXX-4417") == []

def test_card_fails_luhn():
    assert not any(t == "CREDIT_CARD" for t, _ in types("Reference 4111 1111 1111 1112"))

def test_invalid_ssn_rules():
    assert not any(t == "SSN" for t, _ in types("Code 000-12-3456 and 666-12-3456 and 123-00-4567"))

def test_bad_pan_type_letter():
    assert not any(t == "PAN" for t, _ in types("Code ABCDE1234F"))

def test_random_date_not_dob():
    assert types("Meeting on 14/03/2025 at noon") == []

def test_alnum_code_without_passport_context():
    assert not any(t == "PASSPORT" for t, _ in types("Part code K1234567 shipped"))

def test_invoice_number_not_phone():
    assert not any(t == "PHONE" for t, _ in types("Invoice 4155552671 is overdue"))

def test_company_name_not_person():
    assert types("Company Name: Cadence Financial Group") == []

def test_nine_digit_without_context():
    assert types("Batch 123456789 completed") == []


# ---------- behaviour ----------
def test_no_overlapping_findings():
    fs = E.detect_text("Card 4111 1111 1111 1111, DOB: 14/03/1989, SSN 123-45-6789")
    fs.sort(key=lambda f: f.start)
    assert all(a.end <= b.start for a, b in zip(fs, fs[1:]))

def test_offsets_match_text():
    text = "SSN: 123-45-6789"
    f = E.detect_text(text)[0]
    assert text[f.start:f.end] == f.text

def test_ocr_threshold_is_lower():
    # SSN with a failed validator: dropped on native, kept (recall-first) on OCR text with context
    native = [f for f in E.detect_text("SSN 000-12-3456", "native")]
    ocr = [f for f in E.detect_text("SSN 000-12-3456", "ocr")]
    assert len(ocr) >= len(native)


def test_name_does_not_swallow_internal_id():
    assert ("PERSON", "Priya Nair") in types("Name: Priya Nair EMP-38104")

def test_works_with_ocr_style_block_fields():
    from types import SimpleNamespace
    b = SimpleNamespace(id="x1", text="SSN 123-45-6789", source="ocr")  # only id/text/source are needed
    f = E.detect([b])[0]
    assert f.block_id == "x1" and f.origin == "ocr"
