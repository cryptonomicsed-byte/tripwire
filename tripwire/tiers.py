"""Tiered scoring stack.

T0 — exact/pattern (cheapest, every prompt)
T1 — obfuscation metrics (statistical, every prompt)
T2 — semantic (optional, gated; only in the 'maybe' band)
T3 — behavioral (session-level counters)

Each tier returns (score, evidence). Scores are 0..1. The stack combines
them into one composite score per prompt.
"""

from __future__ import annotations

import math
import re
import time
from collections import defaultdict

# --- T0: pattern tier -----------------------------------------------------

T0_PATTERNS = [
    re.compile(r"ignore\s+(your|all)\s+(guidelines|instructions|rules|safety)", re.I),
    re.compile(r"don'?t\s+refuse", re.I),
    re.compile(r"do\s+not\s+refuse", re.I),
    re.compile(r"no\s+(safety|guardrails|limits)", re.I),
    re.compile(r"pretend\s+you\s+(are|have)\s+no", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"developer\s+mode", re.I),
    re.compile(r"d\s*a\s*n\s*g\s*e\s*r\s*o\s*u\s*s", re.I),
    re.compile(r"override\s+(your|the)\s+(policy|rules|training)", re.I),
    re.compile(r"unethical\s+mode", re.I),
]


def tier0(raw: str, canonical: str) -> tuple[float, list[str]]:
    """Pattern match over raw + canonical. Hit count -> 0..1 score."""
    hits: list[str] = []
    for pat in T0_PATTERNS:
        if pat.search(raw) or pat.search(canonical):
            hits.append(pat.pattern[:40])
    if not hits:
        return 0.0, []
    # Saturate: 1 hit = 0.6, 2+ = 1.0
    score = 1.0 if len(hits) >= 2 else 0.6
    return score, hits


# --- T1: obfuscation metrics ----------------------------------------------

HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",  # Cyrillic
    "у": "y", "ѕ": "s", "і": "i", "ј": "j",
    "α": "a", "β": "b", "ο": "o", "ρ": "p", "σ": "s",  # Greek
}
HOMOGLYPH_RE = re.compile("[" + "".join(HOMOGLYPHS.keys()) + "]")
B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_TOKEN_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
WEIRD_WS_RE = re.compile(r"[\u00a0\u2000-\u200a\u202f\u205f\u3000]")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _encoded_char_fraction(text: str) -> float:
    """Fraction of characters that belong to b64/hex-shaped tokens."""
    b64_len = sum(len(m) for m in B64_TOKEN_RE.findall(text))
    hex_len = sum(len(m) for m in HEX_TOKEN_RE.findall(text))
    return (b64_len + hex_len) / max(len(text), 1)


def tier1(*views: str) -> tuple[float, dict]:
    """Statistical obfuscation metrics over all views. Best (max) wins."""
    evidence: dict = {}
    for label, text in [("raw", views[0])] + [
        (f"view{i}", v) for i, v in enumerate(views[1:], 1)
    ]:
        if not text:
            continue
        n = len(text)
        entropy = _shannon_entropy(text)
        # Entropy normalized: English prose ~4.2-4.5 bits/char;
        # base64 ~5.6+. Score scales above ~5.2.
        entropy_score = max(0.0, min(1.0, (entropy - 4.6) / 1.2))

        enc_frac = _encoded_char_fraction(text)
        # 40%+ of chars in encoded tokens is a strong obfuscation signal
        encoded_score = min(1.0, enc_frac / 0.4)

        homo = len(HOMOGLYPH_RE.findall(text))
        homo_score = min(1.0, homo / 8.0)

        zw = len(re.findall(r"[\u200b-\u200f\u2060-\u2064\ufeff]", text))
        zw_score = min(1.0, zw / 4.0)

        weird_ws = len(WEIRD_WS_RE.findall(text))
        ws_score = min(1.0, weird_ws / 5.0)

        total = 0.25 * entropy_score + 0.40 * encoded_score + 0.15 * homo_score + 0.10 * zw_score + 0.10 * ws_score
        evidence[label] = {
            "entropy": round(entropy, 3),
            "encoded_char_frac": round(enc_frac, 3),
            "homoglyphs": homo,
            "zero_width": zw,
            "weird_ws": weird_ws,
            "tier1": round(total, 4),
        }
    best = max(evidence.values(), key=lambda d: d["tier1"]) if evidence else {"tier1": 0.0}
    return best["tier1"], evidence


# --- T2: semantic (optional stub, gated) -----------------------------------

class SemanticTier:
    """Embedding-based classification. Off by default; needs a model."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._model = None

    def load(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        if not self.enabled:
            return
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
        except ImportError:
            raise RuntimeError("semantic tier needs sentence-transformers")
        self._model = SentenceTransformer(model_name)

    def score(self, canonical: str) -> tuple[float, str]:
        if not self.enabled or self._model is None:
            return 0.0, "disabled"
        # Placeholder: real impl embeds + compares against labeled corpus.
        return 0.0, "corpus-not-loaded"


# --- T3: behavioral (session-level) ----------------------------------------

class BehavioralTier:
    """Per-session counters: obfuscation rate, retry-after-refusal,
    escalation ladder. Tripwire fires when rates cross thresholds."""

    def __init__(self, window_sec: int = 600, max_obf_attempts: int = 3,
                 max_retries: int = 3, escalation_minutes: int = 10):
        self.window_sec = window_sec
        self.max_obf_attempts = max_obf_attempts
        self.max_retries = max_retries
        self.escalation_minutes = escalation_minutes
        self._sessions: dict[str, dict] = defaultdict(lambda: {
            "events": [], "obf_count": 0, "refusals": 0, "last_obf_ts": 0.0,
        })

    def _prune(self, sid: str) -> None:
        s = self._sessions[sid]
        cutoff = time.time() - self.window_sec
        s["events"] = [e for e in s["events"] if e[0] >= cutoff]

    def observe(self, sid: str, tier1_score: float, was_refused: bool,
                now: float | None = None) -> tuple[float, list[str]]:
        now = now if now is not None else time.time()
        s = self._sessions[sid]
        self._prune(sid)
        s["events"].append((now, tier1_score, was_refused))
        reasons: list[str] = []

        # Obfuscation attempt rate within window
        obf_recent = sum(1 for ts, sc, _ in s["events"] if sc >= 0.55)
        if obf_recent >= self.max_obf_attempts:
            reasons.append(f"obfuscation-rate:{obf_recent}")

        # Retry-after-refusal: same session keeps escalating
        retries = sum(1 for ts, sc, ref in s["events"] if ref)
        if was_refused:
            s["refusals"] += 1
        if s["refusals"] >= self.max_retries:
            reasons.append(f"retry-after-refusal:{s['refusals']}")

        # Escalation ladder: benign -> obfuscated -> encoded quickly
        if len(s["events"]) >= 3:
            scores = [sc for _, sc, _ in s["events"]]
            if scores[-1] >= 0.7 and max(scores[:-1]) <= 0.3:
                span = s["events"][-1][0] - s["events"][0][0]
                if span <= self.escalation_minutes * 60:
                    reasons.append("escalation-ladder")

        # Reset counter after window
        if obf_recent == 0:
            s["obf_count"] = 0
        score = 1.0 if reasons else 0.0
        return score, reasons


# --- Composite --------------------------------------------------------------

class TierStack:
    def __init__(self, semantic: SemanticTier | None = None,
                 behavioral: BehavioralTier | None = None):
        self.semantic = semantic or SemanticTier()
        self.behavioral = behavioral or BehavioralTier()

    def score(self, views: dict, session_id: str, refused_last: bool = False,
              active_tiers: list[int] | None = None) -> dict:
        active = set(active_tiers or [0, 1, 3])
        raw = views.get("raw", "")
        canonical = views.get("canonical", raw)
        other_views = [v for k, v in views.items() if k not in ("raw", "canonical")]

        result: dict = {"tiers": {}, "evidence": {}, "composite": 0.0}

        if 0 in active:
            t0, ev0 = tier0(raw, canonical)
            result["tiers"]["t0"] = t0
            result["evidence"]["t0"] = ev0

        if 1 in active:
            t1, ev1 = tier1(raw, canonical, *other_views)
            result["tiers"]["t1"] = t1
            result["evidence"]["t1"] = ev1

        if 2 in active and self.semantic.enabled:
            t2, ev2 = self.semantic.score(canonical)
            result["tiers"]["t2"] = t2
            result["evidence"]["t2"] = ev2

        if 3 in active:
            t1v = result["tiers"].get("t1", 0.0)
            t3, ev3 = self.behavioral.observe(session_id, t1v, refused_last)
            result["tiers"]["t3"] = t3
            result["evidence"]["t3"] = ev3

        vals = list(result["tiers"].values())
        result["composite"] = max(vals) if vals else 0.0
        return result
