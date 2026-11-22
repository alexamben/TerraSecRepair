# -*- coding: utf-8 -*-
"""Evaluate all experiment runs: detection metrics + scanner-validated remediation.

Outputs
-------
results/eval_runs.json        : one record per (model, condition, file)
results/metrics.json          : aggregated metrics tables
"""
import json
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sys
# Paths are resolved relative to this file so the harness runs from a
# checkout; override with TSR_EVAL_RESULTS / TSR_EVAL_CACHE if needed.
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)  # repository / artifact root
RES = os.environ.get("TSR_EVAL_RESULTS", os.path.join(BASE, "evaluation", "results"))
CACHE = os.environ.get("TSR_EVAL_CACHE", os.path.join(BASE, "evaluation", "prompt_response_archive"))
if os.path.isdir(os.path.join(BASE, "iac_lib")):
    sys.path.insert(0, BASE)


MODELS = ["gpt-5.6-sol", "gpt-4o", "llama-4-maverick", "qwen3.8-flash"]
CONDITIONS = ["baseline", "sast", "rag", "hybrid"]


def norm_title(s):
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    toks = [t for t in s.split() if t]
    stop = {"the", "a", "an", "of", "to", "for", "is", "are", "that", "and", "or", "in",
            "on", "with", "be", "should", "have", "has", "enable", "enabled", "ensure"}
    return {t for t in toks if t not in stop}


def title_sim(a, b):
    ta, tb = norm_title(a), norm_title(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    return inter / (len(ta) + len(tb) - inter)


def extract_json(content):
    """Extract the outermost JSON object from a model response."""
    if not content:
        return None, "empty"
    # strip markdown fences
    content = re.sub(r"```(?:json)?", "", content)
    s = content.find("{")
    if s < 0:
        return None, "no_brace"
    depth = 0
    in_str = False
    esc = False
    for i in range(s, len(content)):
        ch = content[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    blob = content[s:i + 1]
                    try:
                        return json.loads(blob), None
                    except Exception as e:  # noqa: BLE001
                        return None, f"json_error:{str(e)[:60]}"
    return None, "unterminated"


def res_address_set(code):
    """All resource addresses declared in a Terraform file."""
    pat = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"', re.M)
    return {(m[0], m[1]) for m in pat.findall(code or "")}


def _scan_patch(args):
    key, code = args
    import tempfile
    import warnings

    warnings.filterwarnings("ignore")
    os.environ["CHECKOV_SKIP_UPDATE"] = "true"
    from checkov.runner_filter import RunnerFilter
    from checkov.terraform.runner import Runner

    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "main.tf")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(code)
        try:
            report = Runner().run(root_folder=td, runner_filter=RunnerFilter(framework=["terraform"]))
        except Exception as e:  # noqa: BLE001
            return key, {"scan_error": str(e)[:120], "failed": []}
    return key, {"scan_error": None, "failed": sorted({c.check_id for c in report.failed_checks})}


def main():
    with open(os.path.join(RES, "test_files.json"), encoding="utf-8") as f:
        TEST = {t["file_id"]: t for t in json.load(f)}
    with open(os.path.join(RES, "sast_originals.json"), encoding="utf-8") as f:
        SAST = json.load(f)

    eval_runs = []
    patches_to_scan = []  # (key, code)

    for model in MODELS:
        for cond in CONDITIONS:
            d = os.path.join(RES, "responses", model, cond)
            if not os.path.isdir(d):
                print("MISSING DIR", model, cond)
                continue
            for fid, t in TEST.items():
                p = os.path.join(d, fid + ".json")
                if not os.path.exists(p):
                    continue
                with open(p, encoding="utf-8") as f:
                    rec = json.load(f)
                obj, err = extract_json(rec.get("content", ""))
                run = {
                    "model": model, "condition": cond, "file_id": fid,
                    "label": t["label"], "provider": t["provider"],
                    "latency_s": rec.get("latency_s"),
                    "usage": rec.get("usage", {}),
                    "output_json_ok": obj is not None, "output_err": err,
                    "n_findings": 0, "findings": [], "matched_gt": [],
                    "unmatched_gt": [], "tp": 0, "fp": 0, "fn": 0,
                    "patched_code": None, "patch_changed": None,
                }
                gt = t["findings"]
                gt_by_id = {g["check_id"]: g for g in gt}
                if obj is not None:
                    finds = obj.get("findings") or []
                    if isinstance(finds, dict):
                        finds = list(finds.values())
                    finds = [f for f in finds if isinstance(f, dict)]
                    run["n_findings"] = len(finds)
                    run["findings"] = [
                        {k: f.get(k) for k in ("check_id", "title", "resource", "severity", "explanation")}
                        for f in finds
                    ]
                    # one-to-one greedy matching
                    unmatched = set(gt_by_id)
                    for f in finds:
                        cid = (f.get("check_id") or "").strip()
                        title = f.get("title") or ""
                        match = None
                        if cid in gt_by_id and cid in unmatched:
                            match = cid
                        else:
                            best, best_s = None, 0.0
                            for gid in unmatched:
                                sim = title_sim(title, gt_by_id[gid]["finding_label"])
                                if sim > best_s:
                                    best, best_s = gid, sim
                            if best_s >= 0.5:
                                match = best
                        if match:
                            unmatched.discard(match)
                            run["tp"] += 1
                            run["matched_gt"].append({"pred": cid, "gt": match, "title": title})
                        else:
                            run["fp"] += 1
                    run["unmatched_gt"] = sorted(unmatched)
                    run["fn"] = len(unmatched)
                    # patched code
                    pc = obj.get("patched_code")
                    if isinstance(pc, str) and pc.strip():
                        pc = re.sub(r"^```(?:hcl)?\s*|\s*```\s*$", "", pc.strip())
                        run["patched_code"] = pc
                        run["patch_changed"] = pc.strip() != t["code"].strip()
                        patches_to_scan.append(((model, cond, fid), pc))
                eval_runs.append(run)

    # ---- scan patches (pinned checkov)
    print("scanning", len(patches_to_scan), "patched files ...", flush=True)
    scan_results = {}
    if patches_to_scan:
        with ProcessPoolExecutor(max_workers=6) as ex:
            for key, out in ex.map(_scan_patch, patches_to_scan):
                scan_results[key] = out

    # ---- remediation fields
    for run in eval_runs:
        t = TEST[run["file_id"]]
        key = (run["model"], run["condition"], run["file_id"])
        if not run["label"]:
            # clean file: penalize invented issues by scanning result too
            sc = scan_results.get(key)
            run["clean_new_issues"] = None if not sc else len(sc.get("failed") or [])
            continue
        run["gt_ckv"] = sorted({g["check_id"] for g in t["findings"]
                                if g["check_id"].startswith("CKV") and g.get("reproduced")})
        orig = SAST.get(run["file_id"], {})
        orig_failed = set(orig.get("findings", {}))
        if run["patched_code"] is None or key not in scan_results:
            run["parse_ok"] = None
            continue
        sc = scan_results[key]
        run["scan_error"] = sc.get("scan_error")
        failed = set(sc.get("failed") or [])
        # parse validity: hcl2 parse of patch
        try:
            import hcl2

            hcl2.loads(run["patched_code"])
            run["parse_ok"] = True
        except Exception:  # noqa: BLE001
            run["parse_ok"] = False
        orig_res = res_address_set(t["code"])
        patch_res = res_address_set(run["patched_code"])
        run["resources_preserved"] = orig_res.issubset(patch_res)
        run["n_resources_orig"] = len(orig_res)
        run["n_resources_patch"] = len(patch_res)
        tgt = set(run["gt_ckv"])
        eliminated = tgt - failed
        run["fix_rate"] = len(eliminated) / len(tgt) if tgt else None
        run["target_eliminated"] = sorted(eliminated)
        run["target_persisting"] = sorted(tgt & failed)
        run["new_issues"] = sorted(failed - orig_failed)
        run["valid_fix"] = bool(
            run["parse_ok"] and run["resources_preserved"]
            and not run["new_issues"] and run["fix_rate"] is not None and run["fix_rate"] == 1.0
        )

    with open(os.path.join(RES, "eval_runs.json"), "w", encoding="utf-8") as f:
        json.dump(eval_runs, f)

    # ---- aggregate
    agg = {}
    for model in MODELS:
        for cond in CONDITIONS:
            runs = [r for r in eval_runs if r["model"] == model and r["condition"] == cond]
            if not runs:
                continue
            vuln = [r for r in runs if r["label"]]
            clean = [r for r in runs if not r["label"]]
            tp = sum(r["tp"] for r in vuln)
            fp = sum(r["fp"] for r in vuln)
            fn = sum(r["fn"] for r in vuln)
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            # file-level detection
            det_tp = sum(1 for r in vuln if r["n_findings"] > 0)
            det_fn = sum(1 for r in vuln if r["n_findings"] == 0)
            det_fp = sum(1 for r in clean if r["n_findings"] > 0)
            det_tn = sum(1 for r in clean if r["n_findings"] == 0)
            # remediation
            rem = [r for r in vuln if r.get("fix_rate") is not None]
            fr = [r["fix_rate"] for r in rem]
            valid = [r for r in rem if r["valid_fix"]]
            costs = [r["usage"].get("cost") for r in runs if r["usage"].get("cost") is not None]
            lats = [r["latency_s"] for r in runs if r["latency_s"] is not None]
            agg[f"{model}/{cond}"] = {
                "n_runs": len(runs),
                "finding_P": round(prec, 4), "finding_R": round(rec, 4), "finding_F1": round(f1, 4),
                "tp": tp, "fp": fp, "fn": fn,
                "file_acc": round((det_tp + det_tn) / len(runs), 4) if runs else 0,
                "file_det_prec": round(det_tp / max(1, det_tp + det_fp), 4),
                "file_det_rec": round(det_tp / max(1, det_tp + det_fn), 4),
                "clean_fp_rate": round(det_fp / max(1, len(clean)), 4),
                "clean_flagged": det_fp, "n_clean": len(clean),
                "n_vuln": len(vuln),
                "patch_coverage": round(len(rem) / max(1, len(vuln)), 4),
                "parse_ok_rate": round(sum(1 for r in rem if r["parse_ok"]) / max(1, len(rem)), 4),
                "mean_fix_rate": round(sum(fr) / max(1, len(fr)), 4),
                "valid_fix_rate": round(len(valid) / max(1, len(rem)), 4),
                "n_valid_fix": len(valid),
                "new_issue_rate": round(
                    sum(1 for r in rem if r.get("new_issues")) / max(1, len(rem)), 4),
                "preserve_rate": round(
                    sum(1 for r in rem if r.get("resources_preserved")) / max(1, len(rem)), 4),
                "json_ok_rate": round(sum(1 for r in runs if r["output_json_ok"]) / max(1, len(runs)), 4),
                "mean_cost_usd": round(sum(costs) / max(1, len(costs)), 6),
                "total_cost_usd": round(sum(costs), 4),
                "mean_latency_s": round(sum(lats) / max(1, len(lats)), 2),
            }
    with open(os.path.join(RES, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(agg, f, indent=1)
    print(json.dumps(agg, indent=1))


if __name__ == "__main__":
    main()
