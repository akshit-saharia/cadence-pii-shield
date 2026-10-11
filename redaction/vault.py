from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Optional

DEFAULT_VAULT_PATH = Path("data/vault/vault.json")


class Vault:
    def __init__(self, path: Optional[os.PathLike | str] = DEFAULT_VAULT_PATH,
                 persist: bool = True):
        """
        path    : JSON file used for persistence.
        persist : False -> pure in-memory vault (handy for tests / demo reset).
        """
        self.path: Optional[Path] = Path(path) if path else None
        self.persist: bool = bool(persist and self.path)
        self._forward: dict[str, str] = {}   # "TYPE|normalised_key" -> token
        self._reverse: dict[str, dict] = {}  # token -> {"entity_type", "value"}
        self._counters: dict[str, int] = {}  # label -> last number used
        if self.persist and self.path.exists():
            self._load()

    # ------------------------------------------------------------------ keys
    @staticmethod
    def _fkey(entity_type: str, norm_key: str) -> str:
        return f"{entity_type}|{norm_key}"

    # ------------------------------------------------------------- core API
    def lookup(self, entity_type: str, norm_key: str) -> Optional[str]:
        """Return the existing token for this value, or None."""
        return self._forward.get(self._fkey(entity_type, norm_key))

    def add(self, entity_type: str, norm_key: str, original_value: str,
            label: Optional[str] = None) -> str:
        """Return the token for this value, creating one if it is new."""
        existing = self.lookup(entity_type, norm_key)
        if existing:
            return existing
        label = label or entity_type
        n = self._counters.get(label, 0) + 1
        self._counters[label] = n
        token = f"[{label}_{n}]"
        self._forward[self._fkey(entity_type, norm_key)] = token
        self._reverse[token] = {"entity_type": entity_type, "value": original_value}
        self._save()
        return token

    def alias(self, entity_type: str, norm_key: str, token: str) -> None:
        """Point another spelling of the same value at an existing token."""
        if token not in self._reverse:
            raise KeyError(f"Unknown token: {token}")
        self._forward[self._fkey(entity_type, norm_key)] = token
        self._save()

    def reveal(self, token: str) -> Optional[str]:
        """Original value for a token (authorised, local use only)."""
        rec = self._reverse.get(token)
        return rec["value"] if rec else None

    def keys_for(self, entity_type: str) -> list[tuple[str, str]]:
        """All (normalised_key, token) pairs stored for one entity type."""
        prefix = f"{entity_type}|"
        return [(k[len(prefix):], t) for k, t in self._forward.items()
                if k.startswith(prefix)]

    def tokens(self) -> list[str]:
        return list(self._reverse.keys())

    def __len__(self) -> int:
        return len(self._reverse)

    def clear(self) -> None:
        """Wipe everything (memory and disk file)."""
        self._forward.clear()
        self._reverse.clear()
        self._counters.clear()
        if self.persist and self.path.exists():
            self.path.unlink()

    # ----------------------------------------------------------- persistence
    def _save(self) -> None:
        if not self.persist:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"forward": self._forward, "reverse": self._reverse,
                "counters": self._counters}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)          # atomic write
            try:
                os.chmod(self.path, 0o600)      # owner-only (best effort)
            except OSError:
                pass
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def _load(self) -> None:
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        self._forward = data.get("forward", {})
        self._reverse = data.get("reverse", {})
        self._counters = data.get("counters", {})