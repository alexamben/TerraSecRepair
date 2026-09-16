# -*- coding: utf-8 -*-
"""Hybrid lexical RAG retriever over scanner knowledge cards (BM25 + TF-IDF, RRF)."""
import json
import os
import re
from collections import defaultdict

from rank_bm25 import BM25Okapi
from sklearn.feature_extraction.text import TfidfVectorizer

_STOP = set(
    "a an and are as at be by for from has have in is it its of on or that the to was were will with without ensure ensure that".split()
)


def _tok(text):
    text = re.sub(r"[_]+", " ", text.lower())
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return [t for t in text.split() if t and t not in _STOP]


class CardRetriever:
    def __init__(self, kb_path, weights=(1.0, 0.3, 0.1)):
        self.weights = weights  # (bm25, tfidf-word, tfidf-char) RRF weights
        with open(kb_path, encoding="utf-8") as f:
            cards = json.load(f)
        self.ids = sorted(cards)
        self.cards = cards
        self.docs = []
        for cid in self.ids:
            c = cards[cid]
            txt = " ".join(
                filter(None, [c["check_id"], c["title"], c.get("description"), c["category"],
                              " ".join(c.get("provider_hint") or [])])
            )
            self.docs.append(txt)
        # char n-grams make the TF-IDF arm robust to snake_case/prose mismatches
        self.tok_docs = [_tok(d) for d in self.docs]
        self.bm25 = BM25Okapi(self.tok_docs)
        self.tfidf = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True)
        self.tfidf_mat = self.tfidf.fit_transform(self.docs)
        self.tfidf_char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
        self.tfidf_char_mat = self.tfidf_char.fit_transform(self.docs)

    def _query_text(self, summary, sast_findings):
        parts = []
        parts.extend(summary.get("resources") or [])
        parts.extend(summary.get("providers") or [])
        parts.extend(summary.get("security_attributes") or [])
        for f in sast_findings or []:
            parts.append(f if isinstance(f, str) else f.get("check_id", ""))
            parts.append((f.get("title") or "") if isinstance(f, dict) else "")
        return " ".join(p for p in parts if p)

    def retrieve(self, summary, sast_findings=None, top_k=5, rrf_k=60):
        q = self._query_text(summary, sast_findings)
        if not q.strip():
            q = "terraform resource security"
        qt = _tok(q)
        bm = self.bm25.get_scores(qt) if qt else [0.0] * len(self.ids)
        import numpy as np

        vec = self.tfidf.transform([q])
        tf = (self.tfidf_mat @ vec.T).toarray().ravel()

        def rrf(rank_list):
            s = defaultdict(float)
            for r, i in enumerate(rank_list):
                s[i] += 1.0 / (rrf_k + r + 1)
            return s

        bm_rank = sorted(range(len(self.ids)), key=lambda i: -bm[i])[:50]
        tf_rank = sorted(range(len(self.ids)), key=lambda i: -tf[i])[:50]
        tfc = self.tfidf_char.transform([q])
        tfc_scores = (self.tfidf_char_mat @ tfc.T).toarray().ravel()
        tfc_rank = sorted(range(len(self.ids)), key=lambda i: -tfc_scores[i])[:50]
        w_bm, w_tf, w_tfc = self.weights
        fused = defaultdict(float)
        for w, rank in ((w_bm, bm_rank), (w_tf, tf_rank), (w_tfc, tfc_rank)):
            if w <= 0:
                continue
            for i, s in rrf(rank).items():
                fused[i] += w * s
        top = sorted(fused.items(), key=lambda kv: -kv[1])[:top_k]
        out = []
        for idx, score in top:
            c = dict(self.cards[self.ids[idx]])
            c["_score"] = round(float(score), 5)
            out.append(c)
        return out

    def retrieval_recall(self, test_files, top_k=5, use_sast=None):
        """Fraction of ground-truth check_ids whose card appears in top-k."""
        import numpy as np

        hits = 0
        total = 0
        per_k = {k: [0, 0] for k in (1, 3, 5, 10)}
        for t in test_files:
            if not t.get("label", True):
                continue
            gt_ids = {fd["check_id"] for fd in t["findings"] if fd["check_id"] in self.cards}
            sf = use_sast.get(t["file_id"]) if use_sast else None
            ranked = self.retrieve(t.get("_summary", {}), sf, top_k=max(per_k))
            rank_of = {c["check_id"]: r for r, c in enumerate(ranked)}
            for gid in gt_ids:
                total += 1
                for k in per_k:
                    if rank_of.get(gid, 10**9) < k:
                        per_k[k][0] += 1
                if gid in rank_of:
                    hits += 1
        return {"recall@1": per_k[1][0] / max(1, total), "recall@3": per_k[3][0] / max(1, total),
                "recall@5": per_k[5][0] / max(1, total), "recall@10": per_k[10][0] / max(1, total),
                "n_gt": total}
