"""ASGI middleware — primary deployment mode.

Insert into any ASGI app (FastAPI/Starlette/Hermes API):

    from tripwire.middleware import TripwireMiddleware
    app.add_middleware(TripwireMiddleware, config_path="config.yaml")

Behavior: run every request body through normalize -> tier stack -> policy.
  allow    -> forward upstream unchanged
  flag     -> forward + emit audit record
  throttle -> forward + audit (rate-limiting handled by behavioral tier)
  block    -> return 403 JSON, do NOT forward, audit record
"""

from __future__ import annotations

import json
from typing import Optional

from .normalizer import normalize
from .policy import Policy, load_config
from .sink import TripwireSink
from .tiers import TierStack

MAX_BODY = 64 * 1024  # 64 KiB cap on inspected bodies


def _extract_text(body: bytes, content_type: str = "") -> str:
    """Pull prompt text out of common LLM gateway request shapes."""
    if not body:
        return ""
    try:
        data = json.loads(body)
    except Exception:
        return body.decode("utf-8", errors="ignore")
    if isinstance(data, dict):
        for key in ("prompt", "messages", "input", "query", "content", "text"):
            if key in data:
                val = data[key]
                if isinstance(val, str):
                    return val
                if isinstance(val, list):
                    parts = []
                    for m in val:
                        if isinstance(m, dict):
                            parts.append(str(m.get("content", "")))
                        else:
                            parts.append(str(m))
                    return "\n".join(parts)
        return json.dumps(data, ensure_ascii=False)
    return json.dumps(data, ensure_ascii=False)


class TripwireMiddleware:
    def __init__(self, app, config_path: Optional[str] = None,
                 route: str = "hermes_api",
                 jsonl_path: str = "tripwire_audit.jsonl",
                 mycelium_url: Optional[str] = None,
                 vantage_url: Optional[str] = None,
                 vantage_key: Optional[str] = None):
        self.app = app
        self.route = route
        self.config = load_config(config_path)
        self.policy = Policy(self.config)
        self.stack = TierStack()
        self.sink = TripwireSink(jsonl_path, mycelium_url, vantage_url, vantage_key)
        self._session_counter = 0

    def _session_id(self, scope: dict) -> str:
        headers = {k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers", [])}
        client = scope.get("client") or ("?", 0)
        return f"{client[0]}:{headers.get('x-agent-key', 'anon')}"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Read request body
        body = b""
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.request":
                body += message.get("body", b"")
                more = message.get("more_body", False)
            else:
                more = False

        content_type = ""
        for name, value in scope.get("headers", []):
            if name == b"content-type":
                content_type = value.decode("latin1")

        text = _extract_text(body[:MAX_BODY], content_type)
        session_id = self._session_id(scope)
        self._session_counter += 1

        record = {
            "session_id": session_id,
            "route": self.route,
            "seq": self._session_counter,
        }

        if text.strip():
            views = normalize(text)
            rc = self.policy.route_config(self.route)
            active_tiers = rc.get("tiers", [0, 1, 3])
            result = self.stack.score(views, session_id, active_tiers=active_tiers)
            verdict = self.policy.verdict(result["composite"], self.route)
            record.update({
                "views": views,
                "tiers": result["tiers"],
                "composite": result["composite"],
                "action": verdict["action"],
            })
        else:
            record["action"] = "allow"
            verdict = {"action": "allow", "score": 0.0}

        # Emit audit (never block the request path on sink failure)
        try:
            self.sink.emit(record)
        except Exception:
            pass

        if verdict["action"] == "block":
            response_body = json.dumps({
                "error": "blocked by tripwire",
                "action": "block",
                "composite": record.get("composite", 0.0),
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({"type": "http.response.body", "body": response_body})
            return

        # Forward upstream — reconstruct the receive stream for the app
        async def receive_wrapper():
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, receive_wrapper, send)
