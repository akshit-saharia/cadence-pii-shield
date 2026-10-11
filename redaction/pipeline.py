"""P4 pipeline: (P1 extraction) -> (P3 detection) -> classify -> redact -> fail-closed gate -> report.

    python -m redaction.pipeline                         # demo on redaction/demo_blocks.json
    python -m redaction.pipeline a.pdf b.docx c.pptx     # real files, extracted via extraction.router
    python -m redaction.pipeline folder/                 # every file in the folder (unsupported -> BLOCKED)
    python -m redaction.pipeline blocks.json --show      # already-extracted TextBlocks

Everything is decided per FILE. A file that cannot be extracted, or any exception while processing it,
becomes a BLOCK for that file only. Nothing partially redacted is ever released, and files are never
silently dropped: every input shows up in the report.
Only redacted text reaches the LLM payload; extraction metadata and images are never forwarded.
"""
from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

import config
from schemas import FileResult, TextBlock

from .classifier import classify
from .gate import FailClosedGate
from .ocr_stage import default_ocr_fn, email_fragment_findings, run_ocr
from . import policy
from schemas import RedactedBlock
from .redactor import Redactor
from .report import build_report, write_report
from .vault import Vault


@dataclass
class ProtectionResult:
    files: List[FileResult]
    vault: Vault

    def llm_payload(self) -> Dict[str, str]:
        return {f.file: f.text() for f in self.files if f.decision.allowed}

    def released_blocks(self) -> List[RedactedBlock]:
        return [b for f in self.files for b in f.released]

    def report(self) -> dict:
        return build_report(self)

    def rehydrate(self, llm_text: str) -> str:
        """Swap [PERSON_1]-style tokens in an LLM answer back to the original values."""
        return self.vault.detokenise(llm_text)


class ProtectionPipeline:
    def __init__(self, engine=None, vault: Optional[Vault] = None, use_ner: bool = True, ocr_fn="auto"):
        if engine is None:
            from detection import DetectionEngine      # imported lazily so P4 tests run standalone
            engine = DetectionEngine(use_ner=use_ner)
        self.engine = engine
        self.vault = vault or Vault()
        self.redactor = Redactor(self.vault)
        self.gate = FailClosedGate(detect_fn=engine.detect_text)
        # "auto" = P2's OCR if importable; None = no OCR (image pages then fail closed in the gate)
        self.ocr_fn = default_ocr_fn() if ocr_fn == "auto" else ocr_fn

    # ---- entry points ---------------------------------------------------------
    def run(self, blocks: Iterable) -> ProtectionResult:
        """Already-extracted TextBlocks (grouped by block.file)."""
        by_file: "OrderedDict[str, list]" = OrderedDict()
        for b in blocks:
            by_file.setdefault(getattr(b, "file", "") or "unknown", []).append(b)
        return self._finish([self._process_file(n, bl) for n, bl in by_file.items()])

    def run_files(self, paths: Iterable, extractor: Optional[Callable] = None) -> ProtectionResult:
        """File paths -> P1's extraction.router.extract_file -> everything else."""
        if extractor is None:
            from extraction.router import extract_file as extractor
        files = []
        for p in paths:
            name = str(p)
            try:
                ex = extractor(name)
            except Exception as exc:                     # router already catches; belt and braces
                files.append(self._process_file(name, [], errors=[f"extraction crashed: {type(exc).__name__}: {exc}"]))
                continue
            errors = list(getattr(ex, "errors", None) or [])
            if not getattr(ex, "success", False) and not errors:
                errors = ["extraction reported failure without a message"]
            blocks = list(getattr(ex, "text_blocks", None) or [])
            warnings = list(getattr(ex, "warnings", None) or [])
            images = list(getattr(ex, "images", None) or [])
            ocr_summary: dict = {}
            if not errors and images:
                if self.ocr_fn is None:
                    warnings.append("OCR unavailable: embedded images were not scanned")
                    ocr_summary = {"available": False, "images_total": len(images)}
                else:
                    oc = run_ocr(images, self.ocr_fn, file=name)
                    blocks += oc.blocks
                    warnings += oc.warnings
                    errors += oc.errors
                    images, ocr_summary = oc.unscanned_images, oc.summary   # gate only sees what OCR could not vouch for
            files.append(self._process_file(name, blocks, errors=errors, warnings=warnings, images=images,
                                            metadata=dict(getattr(ex, "metadata", None) or {}), ocr=ocr_summary))
        return self._finish(files)

    # ---- internals ------------------------------------------------------------
    def _finish(self, files: List[FileResult]) -> ProtectionResult:
        self.vault.save()
        return ProtectionResult(files=files, vault=self.vault)

    def _process_file(self, name: str, blocks: list, errors=(), warnings=(), images=(),
                      metadata=None, ocr=None) -> FileResult:
        fr = FileResult(file=name, blocks=blocks, images=list(images),
                        extraction_warnings=list(warnings), metadata=metadata or {}, ocr=ocr or {})
        fr.errors.extend(errors)
        if not fr.errors:
            try:
                fr.findings = list(self.engine.detect(blocks))
                if policy.OCR_FRAGMENT_SWEEP:
                    extra = email_fragment_findings(blocks, fr.findings)
                    fr.findings += extra
                    if fr.ocr is not None and extra:
                        fr.ocr["sweep_fragments"] = fr.ocr.get("sweep_fragments", 0) + len(extra)
            except Exception as exc:
                fr.errors.append(f"detection failed: {type(exc).__name__}: {exc}")
        if not fr.errors:
            try:
                fr.redacted_blocks = self.redactor.redact(blocks, fr.findings)
            except Exception as exc:
                fr.errors.append(f"redaction failed: {type(exc).__name__}: {exc}")
                fr.redacted_blocks = []
        fr.classification = classify(fr.findings, failed=bool(fr.errors))
        fr.decision = self.gate.evaluate(name, blocks, fr.redacted_blocks, fr.findings,
                                         fr.errors, images=fr.images)
        return fr


def load_blocks(path) -> List[TextBlock]:
    raw = json.load(open(path, encoding="utf-8"))
    return [TextBlock(**{k: v for k, v in d.items() if k in TextBlock.__dataclass_fields__}) for d in raw]


def _expand(inputs: List[str]) -> List[Path]:
    out: List[Path] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            out += sorted(x for x in p.iterdir() if x.is_file() and not x.name.startswith("."))
        else:
            out.append(p)
    return out


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="P4: classify, redact, gate and report")
    ap.add_argument("inputs", nargs="*", help="files / folders, or one blocks .json (default: demo blocks)")
    ap.add_argument("--out", default=str(getattr(config, "OUTPUT_DIR", "outputs")))
    ap.add_argument("--no-ner", action="store_true")
    ap.add_argument("--no-ocr", action="store_true", help="skip OCR (image-only pages will be BLOCKED)")
    ap.add_argument("--show", action="store_true", help="print the redacted text of allowed files")
    args = ap.parse_args(argv)

    pipe = ProtectionPipeline(use_ner=not args.no_ner, ocr_fn=None if args.no_ocr else "auto")
    inputs = args.inputs or [str(Path(__file__).parent / "demo_blocks.json")]
    if len(inputs) == 1 and inputs[0].lower().endswith(".json"):
        result = pipe.run(load_blocks(inputs[0]))
    else:
        result = pipe.run_files(_expand(inputs))

    report = result.report()
    jp, mp = write_report(report, args.out)
    out = Path(args.out)
    (out / "llm_payload.json").write_text(json.dumps(result.llm_payload(), indent=2), encoding="utf-8")
    (out / "redacted_blocks.json").write_text(
        json.dumps([b.to_dict() for b in result.released_blocks()], indent=2), encoding="utf-8")

    print(f"{'FILE':32} {'CLASS':14} {'PII':>4}  GATE")
    for f in report["files"]:
        why = ",".join(r["code"] for r in f["gate"]["reasons"])
        print(f"{Path(f['file']).name[:32]:32} {f['classification']['label']:14} "
              f"{sum(f['pii_by_entity'].values()):>4}  {f['decision']}{'  ' + why if why else ''}")
    s = report["summary"]
    print(f"\nPII to LLM: {s['pii_to_llm_without_protection']} without protection -> "
          f"{s['pii_to_llm_with_protection']} with protection | vault: {result.vault.path}")
    print(f"report: {jp} , {mp}")
    if args.show:
        for name, text in result.llm_payload().items():
            print(f"\n===== {name} =====\n{text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
