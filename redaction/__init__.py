"""P4 - redaction stage: Findings in -> classified, redacted, gated, reported.

    from redaction import ProtectionPipeline
    result = ProtectionPipeline().run(blocks)
    safe_text = result.llm_payload()      # only files the fail-closed gate allowed
"""
from .pipeline import ProtectionPipeline, ProtectionResult, FileResult  # noqa: F401
from .vault import Vault  # noqa: F401
