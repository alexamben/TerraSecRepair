# -*- coding: utf-8 -*-
"""OpenRouter chat client with disk cache, retries and cost tracking."""
import hashlib
import json
import os
import time

import requests

BASE = "https://openrouter.ai/api/v1"


def load_key():
    """Resolve the OpenRouter key: env var first, then a .env file in any parent folder."""
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if key:
        return key
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in [os.path.join(here, "..", "..", ".env"), os.path.join(here, "..", ".env"),
                 os.path.join(here, ".env"), ".env"]:
        p = os.path.normpath(cand)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                for line in f:
                    if line.startswith("OPENROUTER_API_KEY="):
                        return line.strip().split("=", 1)[1]
    return None


def _load_key():
    key = load_key()
    if not key:
        raise RuntimeError("no OPENROUTER_API_KEY found (set the env var or a .env file)")
    return key


class LLMClient:
    def __init__(self, cache_dir):
        self.key = _load_key()
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}
        )

    def _cache_path(self, model, messages, max_tokens, temperature, disable_reasoning):
        blob = json.dumps([model, messages, max_tokens, temperature, disable_reasoning],
                          sort_keys=True).encode("utf-8")
        return os.path.join(self.cache_dir, hashlib.sha256(blob).hexdigest()[:32] + ".json")

    def chat(self, model, messages, max_tokens=3500, temperature=0.0,
             disable_reasoning=False, retries=4):
        cp = self._cache_path(model, messages, max_tokens, temperature, disable_reasoning)
        if os.path.exists(cp):
            with open(cp, encoding="utf-8") as f:
                return json.load(f)
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if disable_reasoning:
            payload["reasoning"] = {"enabled": False}
        last = None
        for attempt in range(retries):
            t0 = time.time()
            try:
                r = self.session.post(f"{BASE}/chat/completions", json=payload, timeout=240)
                if r.status_code == 429:
                    wait = 8 * (attempt + 1)
                    time.sleep(wait)
                    last = f"429"
                    continue
                if r.status_code >= 500:
                    time.sleep(5 * (attempt + 1))
                    last = str(r.status_code)
                    continue
                j = r.json()
                if "choices" not in j:
                    # some models reject temperature -> retry without it
                    if "temperature" in payload and str(j.get("error", {}).get("message", "")).find("temperature") >= 0:
                        payload.pop("temperature")
                        continue
                    last = json.dumps(j)[:200]
                    time.sleep(5)
                    continue
                msg = j["choices"][0].get("message") or {}
                content = msg.get("content")
                if not content and msg.get("reasoning"):
                    content = msg["reasoning"]
                rec = {
                    "content": content or "",
                    "usage": j.get("usage", {}),
                    "model": j.get("model", model),
                    "latency_s": round(time.time() - t0, 2),
                    "finish": j["choices"][0].get("finish_reason"),
                }
                with open(cp, "w", encoding="utf-8") as f:
                    json.dump(rec, f)
                return rec
            except Exception as e:  # noqa: BLE001
                last = str(e)[:200]
                time.sleep(5 * (attempt + 1))
        raise RuntimeError(f"llm call failed after retries: {last}")
