"""
Cadence PII Shield — Streamlit UI
Run: streamlit run app/streamlit_app.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import streamlit as st

# ── make the repo root importable regardless of CWD ──────────────────────────
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cadence PII Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── colour palette for tiers / decisions ──────────────────────────────────────
TIER_COLOR = {"HIGH": "#d62728", "MEDIUM": "#ff7f0e", "LOW": "#2ca02c"}
LABEL_BADGE = {
    "RESTRICTED":    ("🔴", "red"),
    "CONFIDENTIAL":  ("🟠", "orange"),
    "INTERNAL":      ("🟡", "orange"),
    "NO_PII_FOUND":  ("🟢", "green"),
    "UNCLASSIFIED":  ("⚪", "grey"),
}
ENTITY_EMOJI = {
    "SSN": "🪪", "PAN": "🪪", "PASSPORT": "🛂", "CREDIT_CARD": "💳",
    "EMAIL": "📧", "PHONE": "📞", "DOB": "🎂", "ADDRESS": "🏠", "PERSON": "👤",
}


# ── helpers ───────────────────────────────────────────────────────────────────
def _badge(label: str) -> str:
    emoji, color = LABEL_BADGE.get(label, ("⚫", "grey"))
    return f":{color}[{emoji} **{label}**]"


def _gate_badge(decision: str) -> str:
    if decision == "ALLOW":
        return ":green[✅ **ALLOW**]"
    return ":red[🚫 **BLOCK**]"


def _run_pipeline(paths: list[str], use_ner: bool, use_ocr: bool):
    """Import and run the pipeline lazily so import errors surface in the UI."""
    from redaction.pipeline import ProtectionPipeline
    pipe = ProtectionPipeline(use_ner=use_ner, ocr_fn="auto" if use_ocr else None)
    return pipe.run_files(paths)


def _entity_rows(findings: list[dict]) -> dict[str, list]:
    """Group findings by entity type."""
    groups: dict[str, list] = {}
    for f in findings:
        groups.setdefault(f["entity_type"], []).append(f)
    return groups


# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=64)
    st.title("🛡️ Cadence PII Shield")
    st.caption("Upload documents → detect & redact PII → safe LLM payload")

    st.divider()
    st.subheader("⚙️ Options")
    use_ner = st.toggle("Enable NER (spaCy names & addresses)", value=True)
    use_ocr = st.toggle("Enable OCR (image pages via Tesseract)", value=True)

    st.divider()
    st.subheader("📂 Upload Documents")
    uploaded = st.file_uploader(
        "PDF, DOCX or PPTX",
        type=["pdf", "docx", "pptx"],
        accept_multiple_files=True,
        label_visibility="collapsed",
    )
    run_btn = st.button("🚀 Run Pipeline", use_container_width=True, type="primary",
                        disabled=not uploaded)

    st.divider()
    st.caption("Outputs saved to `outputs/` · Vault saved to `data/vault/`")


# ── main area ─────────────────────────────────────────────────────────────────
st.title("🛡️ Cadence PII Shield")
st.markdown(
    "Upload confidential documents (PDF / DOCX / PPTX). "
    "The pipeline **extracts text → OCR images → detects PII → redacts → gates** "
    "and produces a safe LLM payload + full audit report."
)

if not uploaded:
    st.info("👈 Upload one or more documents in the sidebar to get started.", icon="📄")
    st.stop()

# ── run pipeline on button click ──────────────────────────────────────────────
if run_btn:
    tmp_paths = []
    with tempfile.TemporaryDirectory(prefix="pii_shield_") as tmp:
        # Save uploaded bytes to temp files with original names
        for uf in uploaded:
            dest = Path(tmp) / uf.name
            dest.write_bytes(uf.read())
            tmp_paths.append(str(dest))

        with st.spinner("🔍 Extracting · OCR · Detecting · Redacting · Gating…"):
            try:
                result = _run_pipeline(tmp_paths, use_ner=use_ner, use_ocr=use_ocr)
            except Exception as exc:
                st.error(f"Pipeline crashed: {exc}")
                st.stop()

        # Write output files
        out_dir = ROOT / "outputs"
        out_dir.mkdir(parents=True, exist_ok=True)
        from redaction.report import build_report, write_report
        report = build_report(result)
        jp, mp = write_report(report, str(out_dir))
        (out_dir / "llm_payload.json").write_text(
            json.dumps(result.llm_payload(), indent=2), encoding="utf-8")
        (out_dir / "redacted_blocks.json").write_text(
            json.dumps([b.to_dict() for b in result.released_blocks()], indent=2),
            encoding="utf-8")

    # Store result in session state so tab switches don't re-run
    st.session_state["report"] = report
    st.session_state["result"] = result
    st.session_state["jp"] = jp
    st.session_state["mp"] = mp
    st.success("✅ Pipeline complete!", icon="🛡️")

# ── display results ───────────────────────────────────────────────────────────
if "report" not in st.session_state:
    st.stop()

report: dict = st.session_state["report"]
result = st.session_state["result"]
jp: Path = st.session_state["jp"]
mp: Path = st.session_state["mp"]
s = report["summary"]
files = report["files"]

# ══ TOP SUMMARY METRICS ══════════════════════════════════════════════════════
st.divider()
st.subheader("📊 Session Summary")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Files processed", s["files_total"])
c2.metric("Allowed to LLM", s["files_allowed"],
          delta=f"-{s['files_blocked']} blocked", delta_color="inverse")
c3.metric("PII items found", s["pii_items_found"])
c4.metric("PII reaching LLM", s["pii_to_llm_with_protection"],
          delta=f"was {s['pii_to_llm_without_protection']} unprotected",
          delta_color="inverse" if s["pii_to_llm_with_protection"] == 0 else "normal")
c5.metric("Vault entries", report["vault"]["entries"],
          delta="🔒 encrypted" if report["vault"]["encrypted"] else "⚠️ unencrypted")

# PII breakdown bar
if s["pii_items_found"]:
    st.markdown("**PII by entity type (all files):**")
    cols = st.columns(len(s["pii_by_entity"]))
    for col, (ent, count) in zip(cols, sorted(s["pii_by_entity"].items(),
                                               key=lambda x: -x[1])):
        emoji = ENTITY_EMOJI.get(ent, "🔑")
        col.metric(f"{emoji} {ent}", count)

# ══ FILE RESULTS TABS ════════════════════════════════════════════════════════
st.divider()
st.subheader("📁 Per-File Results")

tab_labels = [f['file'].split('/')[-1].split('\\')[-1] for f in files]
tabs = st.tabs(tab_labels)

for tab, fr in zip(tabs, files):
    fname = fr["file"].split("/")[-1].split("\\")[-1]
    clf = fr["classification"]
    gate = fr["gate"]
    emoji, _ = LABEL_BADGE.get(clf["label"], ("⚫", "grey"))

    with tab:
        # ── header row ──────────────────────────────────────────────────────
        col_l, col_r = st.columns([3, 1])
        with col_l:
            st.markdown(f"### {fname}")
            st.markdown(
                f"{_badge(clf['label'])}  ·  {_gate_badge(fr['decision'])}  ·  "
                f"**{sum(fr['pii_by_entity'].values())} PII items**  ·  "
                f"Risk score: **{fr['exposure_score_before']} → {fr['exposure_score_after']}**"
            )
        with col_r:
            if gate["reasons"]:
                for r in gate["reasons"]:
                    st.error(f"🚫 {r['code']}: {r['message']}", icon="⛔")
            else:
                st.success("All gate checks passed", icon="✅")

        st.divider()

        # ── two-column layout ────────────────────────────────────────────────
        left, right = st.columns([1, 1], gap="large")

        # LEFT: PII findings
        with left:
            st.markdown("#### 🔍 Detected PII")
            if not fr["findings"]:
                st.success("No PII detected in this file.")
            else:
                by_entity = _entity_rows(fr["findings"])
                for ent, hits in sorted(by_entity.items()):
                    emoji = ENTITY_EMOJI.get(ent, "🔑")
                    tier = hits[0]["tier"]
                    color = TIER_COLOR.get(tier, "#888")
                    with st.expander(
                        f"{emoji} **{ent}** — {len(hits)} hit(s)  "
                        f"· Tier: :{('red' if tier=='HIGH' else 'orange' if tier=='MEDIUM' else 'green')}[**{tier}**]",
                        expanded=True
                    ):
                        for h in hits:
                            rev = "↩️ reversible" if h["reversible"] else "🔒 permanent mask"
                            token = h.get("replacement_token") or "—"
                            st.markdown(
                                f"- Token: `{token}` ({rev})  \n"
                                f"  Detector: `{h['detector']}` · Conf: `{h['confidence']:.0%}` · "
                                f"Page/slide: `{h.get('page_or_slide', '?')}`"
                            )

        # RIGHT: Redacted text
        with right:
            st.markdown("#### ✂️ Redacted Text (LLM payload)")
            llm_text = result.llm_payload().get(
                # match by basename since temp paths differ
                next((k for k in result.llm_payload()
                      if k.split("/")[-1].split("\\")[-1] == fname), ""),
                None
            )
            if fr["decision"] == "BLOCK":
                st.warning(
                    "This file was **BLOCKed** by the gate — its text is withheld from the LLM.",
                    icon="🚫"
                )
                if gate["reasons"]:
                    for r in gate["reasons"]:
                        st.markdown(f"- **{r['code']}**: {r['message']}")
            elif llm_text:
                st.code(llm_text, language=None)
            else:
                st.info("No text blocks released.")

        # ── gate warnings ────────────────────────────────────────────────────
        if gate.get("warnings"):
            with st.expander(f"⚠️ Gate warnings ({len(gate['warnings'])})", expanded=False):
                for w in gate["warnings"]:
                    st.warning(w)

        # ── OCR summary ──────────────────────────────────────────────────────
        ocr = fr.get("ocr") or {}
        if ocr.get("images_total"):
            with st.expander("🖼️ OCR summary", expanded=False):
                oc1, oc2, oc3, oc4 = st.columns(4)
                oc1.metric("Images total", ocr.get("images_total", 0))
                oc2.metric("Scanned", ocr.get("images_scanned", 0))
                oc3.metric("Skipped (tiny)", ocr.get("images_skipped_small", 0))
                oc4.metric("Unreadable", ocr.get("images_unvouched", 0))
                if ocr.get("words_dropped"):
                    st.info(
                        f"{ocr['words_dropped']} low-confidence words dropped · "
                        f"{ocr.get('sweep_fragments', 0)} email-like fragments redacted"
                    )

        # ── extraction warnings ──────────────────────────────────────────────
        if fr.get("extraction_warnings"):
            with st.expander(f"📋 Extraction warnings ({len(fr['extraction_warnings'])})",
                             expanded=False):
                for w in fr["extraction_warnings"]:
                    st.caption(w)

# ══ FULL REPORT + DOWNLOADS ══════════════════════════════════════════════════
st.divider()
st.subheader("📥 Download Outputs")

dl1, dl2, dl3, dl4 = st.columns(4)

with dl1:
    st.download_button(
        label="📄 LLM Payload (JSON)",
        data=(ROOT / "outputs" / "llm_payload.json").read_text(encoding="utf-8"),
        file_name="llm_payload.json",
        mime="application/json",
        use_container_width=True,
    )

with dl2:
    st.download_button(
        label="🔍 Redacted Blocks (JSON)",
        data=(ROOT / "outputs" / "redacted_blocks.json").read_text(encoding="utf-8"),
        file_name="redacted_blocks.json",
        mime="application/json",
        use_container_width=True,
    )

with dl3:
    st.download_button(
        label="📊 Exposure Report (JSON)",
        data=jp.read_text(encoding="utf-8"),
        file_name="exposure_report.json",
        mime="application/json",
        use_container_width=True,
    )

with dl4:
    st.download_button(
        label="📝 Exposure Report (Markdown)",
        data=mp.read_text(encoding="utf-8"),
        file_name="exposure_report.md",
        mime="text/markdown",
        use_container_width=True,
    )

# ── expandable raw JSON report ───────────────────────────────────────────────
with st.expander("🗂️ Raw JSON report", expanded=False):
    st.json(report)

# ── vault status ─────────────────────────────────────────────────────────────
v = report["vault"]
st.divider()
col_v1, col_v2 = st.columns([1, 2])
with col_v1:
    st.markdown("### 🔐 Vault")
    st.markdown(
        f"- Session: `{v['session_id']}`\n"
        f"- Entries: **{v['entries']}**\n"
        f"- Encrypted: {'✅ Yes (Fernet AES)' if v['encrypted'] else '⚠️ No (plain JSON)'}\n"
        f"- Path: `{v['path']}`"
    )
with col_v2:
    st.info(
        "**Reversible tokens** (LOW/MEDIUM tier — names, emails, phones, DOB, addresses) "
        "are stored encrypted in the vault. Call `result.rehydrate(llm_reply)` to swap tokens "
        "back into the LLM's answer before showing it to the end user.\n\n"
        "**Irreversible masks** (HIGH tier — SSN, credit card, PAN, passport) are **never** "
        "stored. Those `[REDACTED:SSN]` placeholders cannot be reversed by design.",
        icon="ℹ️"
    )

st.caption(
    f"Report generated at {report['generated_at']} · "
    f"Session `{report['session_id']}`"
)

