"""P4 data classes now live in the shared schemas.py. This shim keeps old imports working."""
from schemas import (Classification, FileResult, GateDecision,  # noqa: F401
                     RedactedBlock, Replacement)
