"""Cascade decoder — normalize obfuscated text to a canonical fixpoint.

Single-pass decoding misses double-encoded payloads. We loop decoders to
a fixpoint (max N passes) and keep every intermediate view for evidence.

Views dict shape:
    {"raw": original, "url_0": ..., "b64_1": ..., "canonical": fixpoint}
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
import urllib.parse

ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff]")

# Letter-spacing: "i g n o r e" — a space between two single-character words.
LETTER_SPACED_RE = re.compile(r"(?<=\b\w) (?=\w\b)")

LEET_MAP = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t",
                          "@": "a", "$": "s", "!": "i"})


B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decode_b64_token(match: re.Match) -> str:
    """Decode a single b64-shaped token if it decodes to printable text."""
    token = match.group(0)
    if len(token) % 4 != 0:
        return token
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return token
    if not decoded:
        return token
    printable = sum(1 for c in decoded if c.isprintable()) / len(decoded)
    return decoded if printable > 0.8 else token


def _maybe_b64decode(s: str) -> str:
    """Replace embedded base64-shaped tokens with their decoded text.

    Token-level (not whole-string) so payloads like 'say: aWdub3Jl...'
    get decoded while surrounding text survives untouched. Tokens that
    don't decode to mostly-printable text are left as-is.
    """
    return B64_TOKEN_RE.sub(_decode_b64_token, s)


def _unicode_escape_decode(s: str) -> str:
    """Decode \\uXXXX / \\xNN escapes ONLY when escapes are present.

    Round-tripping through unicode_escape mangles non-ASCII text (Cyrillic
    homoglyphs etc.), so we gate on the presence of a backslash. This
    protects legitimate non-ASCII input while still catching escaped
    payloads like '\\u0069gnore'.
    """
    if "\\" not in s:
        return s
    try:
        # latin-1 keeps byte values 1:1; escapes decode, ASCII survives
        return s.encode("latin-1", errors="ignore").decode("unicode_escape")
    except Exception:
        return s


def _strip_zero_width(s: str) -> str:
    return ZERO_WIDTH_RE.sub("", s)


DECODERS = [
    ("url", lambda s: urllib.parse.unquote_plus(s)),
    ("html", html.unescape),
    ("b64", _maybe_b64decode),
    ("unicode_escape", _unicode_escape_decode),
    ("zero_width", _strip_zero_width),
    # NFKC folds fullwidth (ＡＢＣ -> ABC) and other compatibility forms. Safe to
    # chain: it is idempotent and never turns readable text into gibberish.
    ("nfkc", lambda s: unicodedata.normalize("NFKC", s)),
]

# Ambiguous "decoders": they produce a readable view for SOME inputs and
# gibberish for the rest (rot13 of plain English is still English-looking).
# Chaining them would corrupt every unrelated prompt, so they are emitted as
# extra views and scanned, never fed back into the cascade.
VIEW_DECODERS = [
    ("rot13", lambda s: codecs.encode(s, "rot13")),
    ("reversed", lambda s: s[::-1]),
    ("leet", lambda s: s.translate(LEET_MAP)),
    ("spaced", lambda s: LETTER_SPACED_RE.sub("", s)),
]


def normalize(text: str, max_passes: int = 4) -> dict:
    """Return all decode views plus the canonical fixpoint."""
    views: dict[str, str] = {"raw": text}
    cur = text
    for i in range(max_passes):
        nxt = cur
        for name, fn in DECODERS:
            cand = fn(cur)
            if cand != cur:
                views[f"{name}_{i}"] = cand
                nxt = cand  # chain: feed the changed text through next decoder
        if nxt == cur:
            break
        cur = nxt
    views["canonical"] = cur
    for name, fn in VIEW_DECODERS:
        try:
            cand = fn(cur)
        except Exception:  # noqa: BLE001
            continue
        if cand != cur:
            views[f"view_{name}"] = cand
    return views
