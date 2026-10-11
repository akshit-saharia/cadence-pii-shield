"""Token vault: token <-> original value, optionally encrypted at rest.

Same value -> same token inside a session, so the LLM can still reason about "who is who".
Encrypted with Fernet when `cryptography` is installed; otherwise written as plain JSON
(chmod 600) and `status()` says so, so the report never overstates protection.
Demo-grade key handling: in production keep the key in a KMS, not next to the vault.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

import config

from .tokenizer import TOKEN_RE, format_token


def _normalise(entity_type: str, value: str) -> str:
    if entity_type in ("PHONE", "CREDIT_CARD"):
        return "".join(ch for ch in value if ch.isdigit())
    return " ".join(value.split()).casefold()


def _chmod(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class Vault:
    def __init__(self, session_id: Optional[str] = None, vault_dir=None, encrypt: bool = True):
        self.session_id = session_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.vault_dir = Path(vault_dir or getattr(config, "VAULT_DIR", "data/vault"))
        self.want_encryption = encrypt
        self._tokens: Dict[str, dict] = {}
        self._index: Dict[Tuple[str, str], str] = {}
        self._counters: Dict[str, int] = {}
        self.path: Optional[Path] = None
        self.encrypted = False

    def __len__(self) -> int:
        return len(self._tokens)

    # ---- tokenise / detokenise ------------------------------------------------
    def tokenise(self, entity_type: str, value: str) -> str:
        key = (entity_type, _normalise(entity_type, value))
        if key in self._index:
            return self._index[key]
        n = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = n
        token = format_token(entity_type, n)
        self._tokens[token] = {"entity": entity_type, "value": value}
        self._index[key] = token
        return token

    def detokenise(self, text: str) -> str:
        """Put original values back into text containing tokens (e.g. an LLM response)."""
        return TOKEN_RE.sub(lambda m: self._tokens.get(m.group(0), {}).get("value", m.group(0)), text)

    # ---- persistence ----------------------------------------------------------
    def _fernet(self):
        if not self.want_encryption:
            return None
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            return None
        key = os.environ.get("PII_VAULT_KEY")
        if not key:
            self.vault_dir.mkdir(parents=True, exist_ok=True)
            key_file = self.vault_dir / ".vault.key"
            if key_file.exists():
                key = key_file.read_text().strip()
            else:
                key = Fernet.generate_key().decode()
                key_file.write_text(key)
                _chmod(key_file)
        return Fernet(key.encode())

    def save(self) -> Path:
        payload = json.dumps({"session_id": self.session_id, "tokens": self._tokens,
                              "counters": self._counters}).encode("utf-8")
        fernet = self._fernet()
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        if fernet:
            self.path = self.vault_dir / f"{self.session_id}.vault.enc"
            self.path.write_bytes(fernet.encrypt(payload))
            self.encrypted = True
        else:
            self.path = self.vault_dir / f"{self.session_id}.vault.json"
            self.path.write_bytes(payload)
            self.encrypted = False
        _chmod(self.path)
        return self.path

    @classmethod
    def load(cls, session_id: str, vault_dir=None) -> "Vault":
        v = cls(session_id=session_id, vault_dir=vault_dir)
        enc = v.vault_dir / f"{session_id}.vault.enc"
        plain = v.vault_dir / f"{session_id}.vault.json"
        if enc.exists():
            fernet = v._fernet()
            if fernet is None:
                raise RuntimeError("Encrypted vault found but `cryptography`/key is unavailable")
            raw, v.path, v.encrypted = fernet.decrypt(enc.read_bytes()), enc, True
        elif plain.exists():
            raw, v.path = plain.read_bytes(), plain
        else:
            raise FileNotFoundError(f"No vault for session {session_id} in {v.vault_dir}")
        data = json.loads(raw)
        v._tokens, v._counters = data["tokens"], data["counters"]
        v._index = {(t["entity"], _normalise(t["entity"], t["value"])): tok
                    for tok, t in v._tokens.items()}
        return v

    def status(self) -> dict:
        return {"session_id": self.session_id, "entries": len(self._tokens),
                "encrypted": self.encrypted, "path": str(self.path) if self.path else None}
