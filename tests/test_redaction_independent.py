import pytest
pytest.skip("STALE: written for an older redaction API (Vault(path, persist), Tokenizer.tokenize, normalize, "
            "classify(str).risk). Rewrite against redaction/ or delete.", allow_module_level=True)

from redaction.vault import Vault
from redaction.tokenizer import Tokenizer, normalize
from redaction.classifier import classify, max_risk


def test_same_value_same_token_and_distinct_values_differ():
    tk = Tokenizer(Vault(path=None, persist=False))
    a = tk.tokenize("PERSON", "Miriam T. Achebe")
    b = tk.tokenize("PERSON", "  miriam t achebe ")
    c = tk.tokenize("PERSON", "Tobias Lindqvist")
    assert a == b == "[PERSON_1]" and c == "[PERSON_2]"


def test_phone_and_id_normalisation():
    assert normalize("PHONE_NUMBER", "+1 (212) 555-0147") == normalize("PHONE_NUMBER", "212-555-0147")
    assert normalize("US_SSN", "900-55-2043") == normalize("US_SSN", "900 55 2043")
    assert normalize("EMAIL_ADDRESS", "M.Achebe@CadenceFG.com") == "m.achebe@cadencefg.com"


def test_person_alias_merging_is_opt_in():
    off = Tokenizer(Vault(path=None, persist=False))
    assert off.tokenize("PERSON", "Miriam Achebe") != off.tokenize("PERSON", "Miriam T. Achebe")
    on = Tokenizer(Vault(path=None, persist=False), merge_person_aliases=True)
    assert on.tokenize("PERSON", "Miriam Achebe") == on.tokenize("PERSON", "Miriam T. Achebe")
    assert on.tokenize("PERSON", "M. T. Achebe") != on.tokenize("PERSON", "Miriam Achebe")


def test_vault_persistence_and_reveal(tmp_path):
    p = tmp_path / "v.json"
    t1 = Tokenizer(Vault(p)).tokenize("US_SSN", "900-55-2043")
    v2 = Vault(p)
    assert v2.reveal(t1) == "900-55-2043"
    assert Tokenizer(v2).tokenize("US_SSN", "900 55 2043") == t1
    v2.clear()
    assert not p.exists()


def test_classifier():
    assert classify("US_SSN").risk == "CRITICAL"
    assert classify("email address").category == "CONTACT"
    assert classify("SOMETHING_NEW").risk == "HIGH"
    assert max_risk(["LOW", "CRITICAL", "MEDIUM"]) == "CRITICAL"