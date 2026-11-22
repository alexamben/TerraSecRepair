# -*- coding: utf-8 -*-
"""Statistical analysis: McNemar, paired bootstrap CIs, Wilcoxon, Holm correction."""
import json
import math
import os
from itertools import combinations

import numpy as np
from scipy import stats as st

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
N_BOOT = 10000
RNG = np.random.default_rng(42)


def mcnemar_exact(b, c):
    """Exact binomial McNemar test on discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = 2.0 * sum(math.comb(n, i) for i in range(0, k + 1)) * 0.5 ** n
    return min(1.0, p)


def paired_bootstrap_ci(x, y, stat_fn, n_boot=N_BOOT):
    """CI of stat_fn(x) - stat_fn(y) under paired resampling of indices."""
    n = len(x)
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    deltas = np.empty(n_boot)
    for i in range(n_boot):
        idx = RNG.integers(0, n, n)
        deltas[i] = stat_fn(x[idx]) - stat_fn(y[idx])
    lo, hi = np.percentile(deltas, [2.5, 97.5])
    return float(lo), float(hi)


def f1_stat(pred_correct_x):
    """Placeholder: we bootstrap F1 differences over files with per-file counts."""

    def f1(counts):
        tp, fp, fn = counts[..., 0], counts[..., 1], counts[..., 2]
        p = np.where(tp + fp > 0, tp / np.maximum(1, tp + fp), 0.0)
        r = np.where(tp + fn > 0, tp / np.maximum(1, tp + fn), 0.0)
        f = np.where(p + r > 0, 2 * p * r / np.maximum(1e-12, p + r), 0.0)
        return f.mean()

    return f1


def per_file_f1_counts(runs, label=True):
    """Map file_id -> (tp, fp, fn) for micro-bootstrap over files."""
    return {r["file_id"]: (r["tp"], r["fp"], r["fn"]) for r in runs if r["label"] == label}


def holm(pvals):
    """Holm-Bonferroni adjusted p-values."""
    m = len(pvals)
    order = np.argsort(pvals)
    adj = np.empty(m)
    running = 0.0
    for rank, i in enumerate(order):
        v = (m - rank) * pvals[i]
        running = max(running, v)
        adj[i] = min(1.0, running)
    return adj


def main():
    with open(os.path.join(RES, "eval_runs.json"), encoding="utf-8") as f:
        runs = json.load(f)

    def get(model, cond):
        return [r for r in runs if r["model"] == model and r["condition"] == cond]

    out = {"mcnemar_file_level": [], "f1_bootstrap": [], "fixrate_wilcoxon": [],
           "descriptive": {}}

    # per model-condition descriptives
    for m in MODELS:
        for c in CONDITIONS:
            rs = get(m, c)
            vuln = [r for r in rs if r["label"]]
            fr = [r["fix_rate"] for r in vuln if r.get("fix_rate") is not None]
            out["descriptive"][f"{m}/{c}"] = {
                "mean_fix_rate": float(np.mean(fr)) if fr else None,
                "median_fix_rate": float(np.median(fr)) if fr else None,
                "n_fix": len(fr),
                "valid_fix_rate": float(np.mean([1.0 if r["valid_fix"] else 0.0 for r in vuln
                                                 if r.get("fix_rate") is not None])) if fr else None,
            }

    # ---- hybrid vs baseline and hybrid vs sast / rag comparisons per model
    comparisons = [("hybrid", "baseline"), ("hybrid", "sast"), ("hybrid", "rag"), ("sast", "baseline")]
    raw_p = []
    comp_rows = []
    for m in MODELS:
        for (a, b) in comparisons:
            ra, rb = get(m, a), get(m, b)
            fa = {r["file_id"]: r for r in ra}
            fb = {r["file_id"]: r for r in rb}
            common = sorted(set(fa) & set(fb))
            if not common:
                continue
            # file-level detection correctness (vuln flagged / clean unflagged)
            def correct(r):
                flagged = r["n_findings"] > 0
                return (flagged and r["label"]) or ((not flagged) and (not r["label"]))
            n01 = sum(1 for f in common if correct(fa[f]) and not correct(fb[f]))
            n10 = sum(1 for f in common if not correct(fa[f]) and correct(fb[f]))
            p_mcn = mcnemar_exact(n10, n01)
            raw_p.append(p_mcn)
            # finding-level F1 bootstrap over files
            ca = np.array([per_file_f1_counts([fa[f]]).get(f, (0, 0, 0)) for f in common], dtype=float)
            cb = np.array([per_file_f1_counts([fb[f]]).get(f, (0, 0, 0)) for f in common], dtype=float)

            def boot(ca_, cb_):
                n = len(ca_)
                d = np.empty(N_BOOT)
                for i in range(N_BOOT):
                    idx = RNG.integers(0, n, n)
                    sa, sb = ca_[idx].sum(0), cb_[idx].sum(0)

                    def f1_of(s):
                        p = s[0] / (s[0] + s[1]) if s[0] + s[1] > 0 else 0.0
                        r = s[0] / (s[0] + s[2]) if s[0] + s[2] > 0 else 0.0
                        return 2 * p * r / (p + r) if p + r > 0 else 0.0

                    d[i] = f1_of(sa) - f1_of(sb)
                return np.percentile(d, [2.5, 97.5])

            lo, hi = boot(ca, cb)
            # fix-rate wilcoxon
            xs = [fa[f].get("fix_rate") for f in common]
            ys = [fb[f].get("fix_rate") for f in common]
            pairs = [(x, y) for x, y in zip(xs, ys) if x is not None and y is not None]
            p_wil = None
            mean_d = None
            if len(pairs) >= 10:
                dx = np.array([x - y for x, y in pairs])
                if np.any(dx != 0):
                    p_wil = float(st.wilcoxon(dx, zero_method="wilcox").pvalue)
                mean_d = float(np.mean(dx))
            comp_rows.append({
                "model": m, "a": a, "b": b, "n_pairs": len(common),
                "mcnemar_01": n01, "mcnemar_10": n10, "p_mcnemar": p_mcn,
                "f1_delta_ci": [round(lo, 4), round(hi, 4)],
                "fixrate_mean_delta": mean_d, "p_wilcoxon_fixrate": p_wil,
            })
    # Holm across all mcnemar tests
    ps = [r["p_mcnemar"] for r in comp_rows if r["p_mcnemar"] is not None]
    adj = holm(ps)
    k = 0
    for r in comp_rows:
        if r["p_mcnemar"] is not None:
            r["p_mcnemar_holm"] = float(adj[k])
            k += 1
    out["comparisons"] = comp_rows

    # ---- per-severity recall for hybrid vs baseline
    sev_out = {}
    with open(os.path.join(RES, "test_files.json"), encoding="utf-8") as f:
        TEST = {t["file_id"]: t for t in json.load(f)}
    for m in MODELS:
        for c in CONDITIONS:
            rs = get(m, c)
            per_sev = {}
            for r in rs:
                if not r["label"]:
                    continue
                t = TEST[r["file_id"]]
                sev = None
                order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
                best = -1
                for g in t["findings"]:
                    s = order.get(g["severity"], 1)
                    if s > best:
                        best, sev = s, g["severity"]
                sev = sev or "MEDIUM"
                rec = per_sev.setdefault(sev, [0, 0])
                # recall proxy: fraction of GT findings matched
                rec[0] += r["tp"]
                rec[1] += r["tp"] + r["fn"]
            sev_out[f"{m}/{c}"] = {k: round(v[0] / max(1, v[1]), 4) for k, v in per_sev.items()}
    out["recall_by_severity"] = sev_out

    with open(os.path.join(RES, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
