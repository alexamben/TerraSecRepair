# -*- coding: utf-8 -*-
"""IaC-SecRepair Playground — an environment to test the paper's results live.

Run from the project root:
    python -m streamlit run code\\playground_app.py
"""
import json
import os
import re
import sys

import streamlit as st

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from iac_lib.llm import LLMClient
from iac_lib.prompts import SYSTEM, build_prompt
from iac_lib.rag import CardRetriever
from iac_lib.sast import scan_batch, summarize_code

RES = os.path.join(HERE, "assets")
CACHE = os.path.join(HERE, "cache")
os.makedirs(CACHE, exist_ok=True)
MODELS = {
    "gpt-5.6-sol": ("openai/gpt-5.6-sol", False),
    "gpt-4o": ("openai/gpt-4o-2024-11-20", False),
    "llama-4-maverick": ("meta-llama/llama-4-maverick", False),
    "qwen3.8-flash": ("qwen/qwen3.8-flash", True),
}
CONDITIONS = ["baseline", "sast", "rag", "hybrid"]


def extract_json(content):
    content = re.sub(r"```(?:json)?", "", content or "")
    s = content.find("{")
    if s < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(s, len(content)):
        ch = content[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(content[s:i + 1])
                except Exception:
                    return None
    return None


@st.cache_resource
def load_retriever():
    return CardRetriever(os.path.join(RES, "kb_cards.json"), weights=(1.0, 0.0, 0.0))


@st.cache_resource
def load_client():
    return LLMClient(CACHE)


@st.cache_data(show_spinner=False, ttl=3600)
def load_github(url):
    from iac_lib import gh_source
    return gh_source.resolve(url)


def run_audit(code, model_key, mode):
    slug, no_reason = MODELS[model_key]
    fid = "playground"
    scan = scan_batch({fid: code}, workers=1)[fid]
    sast_f = list(scan["findings"].values())
    cards = None
    if mode in ("rag", "hybrid"):
        cards = load_retriever().retrieve(
            summarize_code(code), sast_f if mode == "hybrid" else None, top_k=5)
    sast_for_prompt = sast_f if mode in ("sast", "hybrid") else None
    user = build_prompt(mode, code, sast_for_prompt, cards)
    rec = load_client().chat(slug, [{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": user}],
                             max_tokens=3500, temperature=0.0,
                             disable_reasoning=no_reason)
    obj = extract_json(rec["content"])
    findings = (obj or {}).get("findings") or []
    patch = (obj or {}).get("patched_code") or ""
    patch = re.sub(r"^```(?:hcl)?\s*|\s*```\s*$", "", patch.strip())

    original_failed = set(scan["findings"])
    eliminated, new_issues, parse_ok = set(), set(), None
    if patch:
        try:
            import hcl2
            hcl2.loads(patch)
            parse_ok = True
        except Exception:
            parse_ok = False
        patch_scan = scan_batch({fid: patch}, workers=1)[fid]
        patch_failed = set(patch_scan["findings"])
        eliminated = original_failed - patch_failed
        new_issues = patch_failed - original_failed
    fix_rate = (len(eliminated) / len(original_failed)) if original_failed else 1.0
    pat = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"')
    preserved = ({(m[0], m[1]) for m in pat.findall(code)}
                 .issubset({(m[0], m[1]) for m in pat.findall(patch)}))
    valid = bool(parse_ok) and preserved and not new_issues and original_failed and fix_rate == 1.0
    return {
        "sast": sast_f, "cards": cards or [], "findings": findings, "patch": patch,
        "cost": (rec.get("usage") or {}).get("cost", 0.0), "latency": rec["latency_s"],
        "fix_rate": fix_rate, "new_issues": sorted(new_issues),
        "eliminated": len(eliminated), "n_targets": len(original_failed),
        "parse_ok": parse_ok, "preserved": preserved, "valid": valid,
    }


# ------------------------------------------------------------------ UI
st.set_page_config(page_title="TerraSecRepair Playground", layout="wide")
st.title("TerraSecRepair Playground")
st.caption("Test the paper's results live: audit a Terraform file with any model/mode, "
           "or re-verify the reported claims from the cached study data.")

tab_live, tab_claims = st.tabs(["Live audit (calls the API)", "Claims scoreboard (free, cached)"])

# ------------------------------------------------------------------ live audit tab
with tab_live:
    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        source = st.radio("Terraform source",
                          ["Pick a study test file", "Paste / upload my own", "GitHub URL"],
                          horizontal=True)
    with c2:
        model = st.selectbox("Model", list(MODELS), index=3)
    with c3:
        mode = st.selectbox("Mode (condition)", CONDITIONS, index=3)

    code = None
    label = "custom file"
    if source.startswith("Pick"):
        with open(os.path.join(RES, "test_files.json"), encoding="utf-8") as f:
            test_files = json.load(f)
        opts = {f"{t['file_id'][:8]}  ·  {t['provider']}  ·  {'vulnerable' if t['label'] else 'CLEAN'}"
                f"  ·  {len(t['findings'])} findings": t
                for t in test_files}
        pick = st.selectbox("Study test file", list(opts))
        code = opts[pick]["code"]
        label = opts[pick]["file_id"]
    elif source.startswith("GitHub"):
        url = st.text_input(
            "GitHub URL",
            placeholder="https://github.com/owner/repo  ·  owner/repo@branch  ·  direct .tf URL",
            help="Public repos need no credentials; private repos use a GITHUB_TOKEN env var. "
                 "Repos are fetched as a tarball (no git required).")
        if url:
            try:
                with st.spinner("Fetching Terraform files from GitHub ..."):
                    files = load_github(url)
                names = [n for n, _ in files]
                pick = st.selectbox(f"{len(files)} Terraform file(s) found", names)
                code = dict(files)[pick]
                label = pick
            except Exception as e:  # noqa: BLE001
                st.error(f"GitHub fetch failed: {e}")
    else:
        up = st.file_uploader("Upload .tf", type=["tf"])
        if up is not None:
            code = up.getvalue().decode("utf-8", "replace")
            label = up.name
        else:
            code = st.text_area("…or paste Terraform here", height=200) or None
            label = "pasted"

    if st.button("Run audit", type="primary", disabled=not code):
        with st.spinner("Running pipeline (SAST -> retrieval -> LLM -> validation) ..."):
            res = run_audit(code, model, mode)
        st.subheader("Findings reported by the model")
        st.write(f"{len(res['findings'])} findings · cost ${res['cost']:.5f} · {res['latency']} s")
        if res["findings"]:
            st.dataframe([{"check_id": f.get("check_id"), "title": f.get("title"),
                           "resource": f.get("resource"), "severity": f.get("severity")}
                          for f in res["findings"]], use_container_width=True)
        else:
            st.success("No findings reported (clean report).")
        st.subheader("Patched file")
        if res["patch"]:
            st.code(res["patch"], language="hcl")
        else:
            st.warning("The model did not return a patch.")
        st.subheader("Validation (pinned Checkov re-scan)")
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Fix rate", f"{res['fix_rate']:.0%}", f"{res['eliminated']}/{res['n_targets']} targets")
        k2.metric("New issues", len(res["new_issues"]))
        k3.metric("Parses", "yes" if res["parse_ok"] else "no")
        k4.metric("Resources kept", "yes" if res["preserved"] else "no")
        if res["valid"]:
            st.success("VERDICT: ✓ VALID FIX")
        else:
            st.error("VERDICT: ✗ not a valid fix")
        st.download_button("Download patched file", res["patch"],
                           file_name=f"patched_{model}_{mode}.tf")

    st.info("Cost per audit with a *new* file: ~$0.0003 (Qwen/Llama) to ~$0.015 (GPT-5.6). "
            "Repeating the same file/model/mode is free — responses are cached by prompt hash.")

# ------------------------------------------------------------------ claims tab
with tab_claims:
    st.subheader("Re-verify the paper's claims from the cached study data (no API calls)")
    try:
        runs = None  # study-only artifact, not bundled
        with open(os.path.join(RES, "metrics.json"), encoding="utf-8") as f:
            M = json.load(f)
        with open(os.path.join(RES, "retrieval_recall.json"), encoding="utf-8") as f:
            R = json.load(f)
        with open(os.path.join(RES, "stats.json"), encoding="utf-8") as f:
            S = json.load(f)
    except FileNotFoundError as e:
        st.error(f"Missing results file: {e}")
        st.stop()

    MODELS_ORDER = ["gpt-5.6-sol", "gpt-4o", "llama-4-maverick", "qwen3.8-flash"]
    st.markdown("**Claim 1 — Hybrid detection beats the LLM-only baseline (finding-level F1):**")
    rows = []
    for m in MODELS_ORDER:
        b, h = M[f"{m}/baseline"]["finding_F1"], M[f"{m}/hybrid"]["finding_F1"]
        rows.append({"model": m, "baseline F1": b, "hybrid F1": h, "delta": round(h - b, 3),
                     "holds": h > b})
    st.dataframe(rows, use_container_width=True)
    st.success("HOLDS for all four models" if all(r["holds"] for r in rows) else "CHECK: fails for a model")

    st.markdown("**Claim 2 — Hybrid converts more findings into scanner-validated fixes:**")
    rows = []
    for m in MODELS_ORDER:
        b, h = M[f"{m}/baseline"]["valid_fix_rate"], M[f"{m}/hybrid"]["valid_fix_rate"]
        rows.append({"model": m, "baseline valid-fix": f"{b:.1%}", "hybrid valid-fix": f"{h:.1%}",
                     "holds": h > b})
    st.dataframe(rows, use_container_width=True)
    st.success("HOLDS for all four models" if all(r["holds"] for r in rows) else "CHECK")

    st.markdown("**Claim 3 — Hybrid flags fewer verified-clean files:**")
    rows = []
    for m in MODELS_ORDER:
        b, h = M[f"{m}/baseline"]["clean_fp_rate"], M[f"{m}/hybrid"]["clean_fp_rate"]
        rows.append({"model": m, "baseline clean-FP": f"{b:.1%}", "hybrid clean-FP": f"{h:.1%}",
                     "holds": h < b})
    st.dataframe(rows, use_container_width=True)
    st.success("HOLDS for all four models" if all(r["holds"] for r in rows) else "CHECK")

    st.markdown("**Claim 4 — SAST-anchored retrieval beats structure-only retrieval:**")
    st.write(f"recall@5: structure-only {R['structure_only']['recall@5']:.1%} → "
             f"anchored {R['structure_plus_sast']['recall@5']:.1%}")

    st.markdown("**Claim 5 — Paired statistics favour the hybrid (hybrid vs baseline):**")
    for r in S["comparisons"]:
        if r["a"] == "hybrid" and r["b"] == "baseline":
            lo, hi = r["f1_delta_ci"]
            st.write(f"- {r['model']}: F1 Δ CI [{lo:+.3f}, {hi:+.3f}] "
                     f"{'(excludes 0 ✓)' if lo > 0 or hi < 0 else '(includes 0)'} · "
                     f"Wilcoxon fix-rate p = {r['p_wilcoxon_fixrate']:.2e}")

    st.markdown("**Full metrics table (all 16 runs):**")
    st.dataframe([{"run": k, **{f: v for f, v in v.items() if f.startswith(("finding", "clean", "mean_fix",
                                               "valid_fix", "new_issue", "parse_ok", "mean_cost", "mean_latency"))}}
                  for k, v in M.items()], use_container_width=True)
