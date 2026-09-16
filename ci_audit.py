# -*- coding: utf-8 -*-
"""TerraSecRepair CI auditor: audit Terraform files and gate the merge.

Usage (in GitHub Actions, or locally):
    python ci_audit.py --files a.tf b.tf [--model qwen3.8-flash] [--fail-on high]

Writes a markdown report to $GITHUB_STEP_SUMMARY (if set) and to stdout.
Exit code: 0 = every finding eliminated or below the gate; 1 = unvalidated
findings at or above the gate severity remain.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from iac_lib.llm import LLMClient
from iac_lib.prompts import SYSTEM, build_prompt
from iac_lib.rag import CardRetriever
from iac_lib.sast import scan_batch, summarize_code

ASSETS = os.path.join(HERE, "assets")
CACHE = os.path.join(HERE, "cache")
os.makedirs(CACHE, exist_ok=True)

MODELS = {
    "gpt-5.6-sol": ("openai/gpt-5.6-sol", False),
    "gpt-4o": ("openai/gpt-4o-2024-11-20", False),
    "llama-4-maverick": ("meta-llama/llama-4-maverick", False),
    "qwen3.8-flash": ("qwen/qwen3.8-flash", True),
}
SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", nargs="+", required=True, help=".tf files to audit")
    ap.add_argument("--model", default="qwen3.8-flash", choices=sorted(MODELS))
    ap.add_argument("--mode", default="hybrid", choices=["baseline", "sast", "rag", "hybrid"])
    ap.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "none"],
                    help="gate the merge if unvalidated findings remain at/above this severity")
    args = ap.parse_args()

    slug, no_reason = MODELS[args.model]
    gate = SEV_ORDER[args.fail_on.upper()] if args.fail_on != "none" else 99

    with open(os.path.join(ASSETS, "kb_cards.json"), encoding="utf-8") as f:
        kb = json.load(f)

    client = LLMClient(CACHE)
    retriever = CardRetriever(os.path.join(ASSETS, "kb_cards.json"), weights=(1.0, 0.0, 0.0))

    scan = scan_batch({os.path.abspath(p): open(p, encoding="utf-8").read()
                       for p in args.files}, workers=min(4, len(args.files)))

    md = ["## 🔒 TerraSecRepair audit", ""]
    gate_failures = []
    total_targets = total_eliminated = 0

    for path in args.files:
        code = open(path, encoding="utf-8").read()
        res = scan[os.path.abspath(path)]
        targets = set(res["findings"])
        sast_f = list(res["findings"].values())
        md.append(f"### `{path}` — {len(targets)} candidate findings")
        md.append("")
        if not sast_f:
            md.append("✅ Scanner reports nothing — file is clean, model skipped.")
            md.append("")
            continue

        cards = None
        if args.mode in ("rag", "hybrid"):
            cards = retriever.retrieve(summarize_code(code),
                                       sast_f if args.mode == "hybrid" else None, top_k=5)
        user = build_prompt(args.mode, code, sast_f if args.mode in ("sast", "hybrid") else None, cards)
        rec = client.chat(slug, [{"role": "system", "content": SYSTEM},
                                 {"role": "user", "content": user}],
                          max_tokens=3500, temperature=0.0, disable_reasoning=no_reason)
        obj = extract_json(rec["content"])
        reported = (obj or {}).get("findings") or []
        patch = (obj or {}).get("patched_code") or ""
        cost = (rec.get("usage") or {}).get("cost", 0.0)

        if patch:
            patch_scan = scan_batch({path + ".patched": patch}, workers=1)[path + ".patched"]
            patch_failed = set(patch_scan["findings"])
        else:
            patch_failed = targets  # no patch = everything persists

        eliminated = targets - patch_failed
        new_issues = patch_failed - targets
        fix_rate = len(eliminated) / len(targets)
        total_targets += len(targets)
        total_eliminated += len(eliminated)

        persisting = targets & patch_failed
        md.append(f"- model findings reported: **{len(reported)}** · cost ${cost:.5f} · {rec['latency_s']} s")
        md.append(f"- fix rate: **{len(eliminated)}/{len(targets)} ({fix_rate:.0%})** · "
                  f"new issues: **{len(new_issues)}**")
        for c in sorted(persisting):
            md.append(f"  - ⚠ still failing: `{c}`")
        for c in sorted(new_issues):
            md.append(f"  - ❗ regression: `{c}`")
        md.append("")

        for c in sorted(persisting):
            sev = (kb.get(c, {}) or {}).get("severity", "MEDIUM").upper()
            if SEV_ORDER.get(sev, 1) >= gate:
                gate_failures.append((path, c, sev))

    md.append("---")
    md.append(f"**Totals:** {total_eliminated}/{total_targets} candidate findings eliminated · "
              f"gate: fail on unvalidated **{args.fail_on}+** · "
              f"gate failures: **{len(gate_failures)}**")

    report = "\n".join(md)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report + "\n")

    pr = os.environ.get("PR_NUMBER")
    tok = os.environ.get("GH_TOKEN")
    if pr and tok:
        rp = os.path.join(CACHE, "report.md")
        with open(rp, "w", encoding="utf-8") as f:
            f.write(report)
        subprocess = __import__("subprocess")
        subprocess.run(["gh", "pr", "comment", pr, "--body-file", rp], check=False)

    if gate_failures:
        print(f"GATE: FAIL — {len(gate_failures)} unvalidated finding(s) at/above {args.fail_on}")
        sys.exit(1)
    print("GATE: PASS")


if __name__ == "__main__":
    main()
