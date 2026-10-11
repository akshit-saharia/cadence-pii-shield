"""Regression tests for OCR text clean-up."""
from ocr.ocr_pipeline import _fix_digits, _fix_email_spacing


def test_internal_ids_survive():
    s = "Ticket INC-20456 raised by EMP-38104 against RSK-4471 and ISS-3301"
    assert _fix_digits(s) == s


def test_digit_lookalikes_still_fixed():
    assert _fix_digits("1OO-45-6789") == "100-45-6789"
    assert _fix_digits("555-O188") == "555-0188"
    assert _fix_digits("+1 (646) 555-0I88") == "+1 (646) 555-0188"
    assert _fix_digits("4471S") == "44715"


def test_words_and_emails_untouched():
    assert _fix_digits("Sales Report 2024") == "Sales Report 2024"
    assert _fix_digits("a1l2@x.com") == "a1l2@x.com"


def test_email_rejoin():
    assert _fix_email_spacing("m.achebe @ cadencefg . com") == "m.achebe@cadencefg.com"
    assert _fix_email_spacing("n.osadebe@cadencefg.com") == "n.osadebe@cadencefg.com"


def test_sentences_not_glued():
    s = "Policy Owner. Daniel Kim reviewed it. P.S. Raghavan signed."
    assert _fix_email_spacing(s) == s
    assert _fix_email_spacing("mail a@b.com. Then call") == "mail a@b.com. Then call"