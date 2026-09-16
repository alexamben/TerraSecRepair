# -*- coding: utf-8 -*-
"""Demo: audit any Terraform file with the TerraSecRepair pipeline.

Usage (from the code/ folder):
    python demo_audit.py <path\to\file.tf> [--model gpt-5.6-sol] [--mode hybrid]

Modes: baseline | sast | rag | hybrid   (default: hybrid)
Models: gpt-5.6-sol | gpt-4o | llama-4-maverick | qwen3.8-flash

Prints the findings the model reports, writes the patched file next to the
input, then validates the patch with the pinned Checkov re-scan:
  - fix rate       : share of originally-failing checks eliminated
  - new issues     : checks the patch introduced (regressions)
  - parse/preserve : patch parses and keeps all original resources
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from iac_lib.llm import LLMClient
from iac_lib.prompts import SYSTEM, build_prompt
from iac_lib.rag import CardRetriever
from iac_lib.sast import scan_batch, summarize_code

MODELS = {
    "gpt-5.6-sol": ("openai/gpt-5.6-sol", False),
    "gpt-4o": ("openai/gpt-4o-2024-11-20", False),
    "llama-4-maverick": ("meta-llama/llama-4-maverick", False),
    "qwen3.8-flash": ("qwen/qwen3.8-flash", True),
}
CONDITIONS = ("baseline", "sast", "rag", "hybrid")
ASSETS = os.path.join(HERE, "assets")
CACHE = os.path.join(HERE, "cache")
os.makedirs(CACHE, exist_ok=True)


def extract_json(content):
    import re
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
    ap.add_argument("tf_file")
    ap.add_argument("--model", default="qwen3.8-flash", choices=sorted(MODELS))
    ap.add_argument("--mode", default="hybrid", choices=CONDITIONS)
    ap.add_argument("--max-tokens", type=int, default=3500)
    args = ap.parse_args()

    tf_path = os.path.abspath(args.tf_file)
    code = open(tf_path, encoding="utf-8").read()
    fid = os.path.splitext(os.path.basename(tf_path))[0]
    slug, no_reason = MODELS[args.model]

    print(f"[1/5] SAST stage (Checkov 3.3.17) on {os.path.basename(tf_path)} ...")
    scan = scan_batch({fid: code}, workers=1)[fid]
    original_failed = set(scan["findings"])
    sast_findings = list(scan["findings"].values())
    if not sast_findings and args.mode in ("sast", "hybrid"):
        print("      scanner reports nothing -> clean file, model skipped (hybrid policy)")
        return
    for f in sast_findings:
        print(f"      candidate: {f['check_id']}  {f.get('title', '')[:60]}")

    print("[2/5] Retrieval over knowledge base ...")
    retr = CardRetriever(os.path.join(ASSETS, "kb_cards.json"), weights=(1.0, 0.0, 0.0))
    cards = None
    if args.mode in ("rag", "hybrid"):
        cards = retr.retrieve(summarize_code(code), sast_findings if args.mode == "hybrid" else None,
                              top_k=5)
        for c in cards:
            print(f"      card: {c['check_id']}  {c['title'][:55]}")

    print(f"[3/5] LLM call ({slug}, mode={args.mode}) ...")
    client = LLMClient(CACHE)
    user = build_prompt(args.mode, code, sast_findings, cards)
    rec = client.chat(slug, [{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": user}],
                      max_tokens=args.max_tokens, temperature=0.0,
                      disable_reasoning=no_reason)
    obj = extract_json(rec["content"])
    if obj is None:
        print("      ERROR: model did not return parseable JSON:")
        print(rec["content"][:500])
        return
    cost = (rec.get("usage") or {}).get("cost", 0.0)
    print(f"      findings reported: {len(obj.get('findings', []))} | cost ${cost:.5f} "
          f"| latency {rec['latency_s']}s")
    for f in obj.get("findings", []):
        print(f"      finding : {f.get('check_id', '?'):16s} {f.get('title', '')[:60]}")

    print("[4/5] Writing patched file ...")
    patch = (obj.get("patched_code") or "").strip()
    if not patch:
        print("      model returned no patch")
        return
    out_path = os.path.splitext(tf_path)[0] + f".patched.{args.model}.{args.mode}.tf"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(patch)
    print("      wrote", out_path)

    print("[5/5] Validation: pinned re-scan of the patch ...")
    import re as _re
    pat = _re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"')
    preserved = {(m[0], m[1]) for m in pat.findall(code)}.issubset(
        {(m[0], m[1]) for m in pat.findall(patch)})
    patch_scan = scan_batch({fid: patch}, workers=1)[fid]
    patch_failed = set(patch_scan["findings"])
    eliminated = original_failed - patch_failed
    new_issues = patch_failed - original_failed
    fix_rate = len(eliminated) / len(original_failed) if original_failed else 1.0

    try:
        import hcl2
        hcl2.loads(patch)
        parse_ok = True
    except Exception:
        parse_ok = False

    print()
    print("=== VALIDATION REPORT ===")
    print(f"target checks        : {len(original_failed)}")
    print(f"eliminated           : {len(eliminated)}  (fix rate {fix_rate:.0%})")
    print(f"persisting           : {sorted(original_failed & patch_failed) or 'none'}")
    print(f"new issues (regress.): {sorted(new_issues) or 'none'}")
    print(f"patch parses         : {parse_ok}")
    print(f"resources preserved  : {preserved}")
    valid = parse_ok and preserved and not new_issues and fix_rate == 1.0
    print(f"VERDICT              : {'✓ VALID FIX' if valid else '✗ NOT A VALID FIX'}")


if __name__ == "__main__":
    main()
