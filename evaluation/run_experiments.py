# -*- coding: utf-8 -*-
"""Run the IaC-SecRepair experiment grid: models x conditions x test files."""
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iac_lib.llm import LLMClient
from iac_lib.prompts import SYSTEM, build_prompt
from iac_lib.rag import CardRetriever
from iac_lib.sast import scan_batch, summarize_code

import sys
# Paths are resolved relative to this file so the harness runs from a
# checkout; override with TSR_EVAL_RESULTS / TSR_EVAL_CACHE if needed.
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)  # repository / artifact root
RES = os.environ.get("TSR_EVAL_RESULTS", os.path.join(BASE, "evaluation", "results"))
CACHE = os.environ.get("TSR_EVAL_CACHE", os.path.join(BASE, "evaluation", "prompt_response_archive"))
if os.path.isdir(os.path.join(BASE, "iac_lib")):
    sys.path.insert(0, BASE)


MODELS = {
    "gpt-5.6-sol": {"slug": "openai/gpt-5.6-sol", "display": "GPT-5.6", "no_reason": False},
    "gpt-4o": {"slug": "openai/gpt-4o-2024-11-20", "display": "GPT-4o", "no_reason": False},
    "llama-4-maverick": {"slug": "meta-llama/llama-4-maverick", "display": "Llama-4-Maverick", "no_reason": False},
    "qwen3.8-flash": {"slug": "qwen/qwen3.8-flash", "display": "Qwen3.8-Flash", "no_reason": True},
}
CONDITIONS = ["baseline", "sast", "rag", "hybrid"]


def main():
    with open(os.path.join(RES, "test_files.json"), encoding="utf-8") as f:
        TEST = json.load(f)
    KB = os.path.join(RES, "kb_cards.json")

    for t in TEST:
        t["_summary"] = summarize_code(t["code"])

    SAST_PATH = os.path.join(RES, "sast_originals.json")
    if os.path.exists(SAST_PATH):
        with open(SAST_PATH, encoding="utf-8") as f:
            SAST = json.load(f)
        print("loaded cached SAST:", len(SAST), flush=True)
    else:
        print("running SAST stage on", len(TEST), "files ...", flush=True)
        t0 = time.time()
        SAST = scan_batch({t["file_id"]: t["code"] for t in TEST}, workers=6)
        with open(SAST_PATH, "w", encoding="utf-8") as f:
            json.dump(SAST, f)
        print("SAST done in", round(time.time() - t0, 1), "s", flush=True)

    retr = CardRetriever(KB, weights=(1.0, 0.0, 0.0))  # BM25-only, selected on tuning split
    rec_noSAST = retr.retrieval_recall(TEST, use_sast=None)
    rec_SAST = retr.retrieval_recall(
        TEST, use_sast={fid: list(s["findings"].values()) for fid, s in SAST.items() if s.get("findings")}
    )
    print("retrieval recall (structure):", json.dumps(rec_noSAST), flush=True)
    print("retrieval recall (+SAST):", json.dumps(rec_SAST), flush=True)
    with open(os.path.join(RES, "retrieval_recall.json"), "w", encoding="utf-8") as f:
        json.dump({"structure_only": rec_noSAST, "structure_plus_sast": rec_SAST}, f, indent=1)

    client = LLMClient(CACHE)
    lock = threading.Lock()
    done = {"n": 0}
    TOTAL = len(MODELS) * len(CONDITIONS) * len(TEST)

    def run_one(model_key, cond, t):
        outdir = os.path.join(RES, "responses", model_key, cond)
        os.makedirs(outdir, exist_ok=True)
        outp = os.path.join(outdir, t["file_id"] + ".json")
        if os.path.exists(outp):
            return "cached"
        sast_f = None
        if cond in ("sast", "hybrid"):
            sast_f = list(SAST.get(t["file_id"], {}).get("findings", {}).values())
        cards = None
        if cond in ("rag", "hybrid"):
            sast_for_q = sast_f if cond == "hybrid" else None
            cards = retr.retrieve(t["_summary"], sast_for_q, top_k=5)
        user = build_prompt(cond, t["code"], sast_f, cards)
        rec = client.chat(
            MODELS[model_key]["slug"],
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
            max_tokens=3500,
            temperature=0.0,
            disable_reasoning=MODELS[model_key]["no_reason"],
        )
        with open(outp, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        with lock:
            done["n"] += 1
            if done["n"] % 50 == 0:
                print(f"[{done['n']}/{TOTAL}] {model_key}/{cond} cost={rec['usage'].get('cost')} "
                      f"lat={rec['latency_s']}s", flush=True)
        return "ok"

    t_start = time.time()
    for model_key in MODELS:
        for cond in CONDITIONS:
            errs = 0
            with ThreadPoolExecutor(max_workers=6) as ex:
                futs = [ex.submit(run_one, model_key, cond, t) for t in TEST]
                for fu in as_completed(futs):
                    try:
                        fu.result()
                    except Exception as e:  # noqa: BLE001
                        errs += 1
                        print("ERR", model_key, cond, str(e)[:160], flush=True)
            print(f"== {model_key}/{cond}: done ({errs} errors) elapsed={round(time.time()-t_start)}s",
                  flush=True)

    print("ALL DONE in", round(time.time() - t_start, 1), "s", flush=True)


if __name__ == "__main__":
    main()
