"""Tripwire — normalization-first evasion detection for LLM gateways.

A cascade-decoder normalizer feeds a tiered scoring stack (pattern,
obfuscation metrics, semantic, behavioral). Verdicts are policy-driven
per route; every decision is written to a reversible audit sink.
"""

__version__ = "0.1.0"
