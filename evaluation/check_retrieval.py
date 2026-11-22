# -*- coding: utf-8 -*-
"""Quick retrieval-recall check with the improved structure-only query."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iac_lib.rag import CardRetriever
from iac_lib.sast import summarize_code

import sys
# Paths are resolved relative to this file so the harness runs from a
# checkout; override with TSR_EVAL_RESULTS / TSR_EVAL_CACHE if needed.
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)  # repository / artifact root
RES = os.environ.get("TSR_EVAL_RESULTS", os.path.join(BASE, "evaluation", "results"))
CACHE = os.environ.get("TSR_EVAL_CACHE", os.path.join(BASE, "evaluation", "prompt_response_archive"))
if os.path.isdir(os.path.join(BASE, "iac_lib")):
    sys.path.insert(0, BASE)


with open(os.path.join(RES, "test_files.json"), encoding="utf-8") as f:
    TEST = json.load(f)
for t in TEST:
    t["_summary"] = summarize_code(t["code"])
retr = CardRetriever(os.path.join(RES, "kb_cards.json"), weights=(1.0, 0.0, 0.0))
r1 = retr.retrieval_recall(TEST, use_sast=None)
with open(os.path.join(RES, "sast_originals.json"), encoding="utf-8") as f:
    SAST = json.load(f)
r2 = retr.retrieval_recall(TEST, use_sast={fid: list(s["findings"].values())
                                           for fid, s in SAST.items() if s.get("findings")})
print("structure(+attrs):", json.dumps(r1, indent=1))
print("structure+SAST:", json.dumps(r2, indent=1))
with open(os.path.join(RES, "retrieval_recall.json"), "w", encoding="utf-8") as f:
    json.dump({"structure_only": r1, "structure_plus_sast": r2}, f, indent=1)
