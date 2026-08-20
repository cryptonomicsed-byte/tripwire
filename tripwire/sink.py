"""Audit sink — reversible JSONL records + optional Mycelium trace emission.

Every decision writes: raw prompt (truncated), all views, per-tier scores,
verdict, action, route, session id, timestamp. Replayable from JSONL alone.
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional


class JsonlSink:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def write(self, record: dict) -> None:
        record.setdefault("ts", time.time())
        with open(self.path, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


class TripwireSink:
    """Composite sink: JSONL always; Mycelium/Vantage when reachable."""

    def __init__(self, jsonl_path: str = "tripwire_audit.jsonl",
                 mycelium_url: Optional[str] = None,
                 vantage_url: Optional[str] = None,
                 vantage_key: Optional[str] = None):
        self.jsonl = JsonlSink(jsonl_path)
        self.mycelium_url = mycelium_url
        self.vantage_url = vantage_url
        self.vantage_key = vantage_key

    def emit(self, record: dict) -> None:
        self.jsonl.write(record)
        if self.mycelium_url:
            self._emit_mycelium(record)
        if self.vantage_url:
            self._emit_vantage(record)

    def _emit_mycelium(self, record: dict) -> None:
        # Fire-and-forget; never block the request path on sinks.
        try:
            import urllib.request
            payload = json.dumps({
                "agent": "tripwire",
                "session": record.get("session_id", "?"),
                "kind": "decision",
                "action": "detect",
                "target": record.get("route", "?"),
                "outcome": "success" if record.get("action") == "allow" else "flag",
                "payload": {k: record.get(k) for k in ("action", "composite", "tiers")},
            }).encode()
            req = urllib.request.Request(
                self.mycelium_url, data=payload,
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass  # sink failure must not break the gateway

    def _emit_vantage(self, record: dict) -> None:
        try:
            import urllib.request
            payload = json.dumps({
                "type": "alert",
                "source": "tripwire",
                "severity": "high" if record.get("action") == "block" else "info",
                "message": f"tripwire:{record.get('action')} route={record.get('route')} score={record.get('composite')}",
            }).encode()
            headers = {"Content-Type": "application/json"}
            if self.vantage_key:
                headers["X-Agent-Key"] = self.vantage_key
            req = urllib.request.Request(self.vantage_url, data=payload, headers=headers, method="POST")
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass
