"""Policy engine — per-route YAML config, verdict mapping.

Default mode is FLAG-ONLY until the eval harness proves FPR acceptable.
"""

from __future__ import annotations

import json
import os

DEFAULT_CONFIG = {
    "routes": {
        "hermes_api": {
            "tiers": [0, 1, 3],
            "actions": {"block": 0.95, "flag": 0.75, "throttle": 0.60},
        },
        "omniroute": {
            "tiers": [0, 1, 3],
            "actions": {"block": 0.95, "flag": 0.70},
        },
        "vantage_workers": {
            "tiers": [0, 1, 2, 3],
            "actions": {"block": 0.90, "flag": 0.60},
        },
    },
    "default_mode": "flag",
}


def _load_yaml(path: str) -> dict | None:
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def load_config(path: str | None = None) -> dict:
    """Load YAML config; fall back to JSON; fall back to defaults."""
    if path and os.path.exists(path):
        data = _load_yaml(path)
        if data is not None:
            return data
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy


class Policy:
    def __init__(self, config: dict | None = None):
        self.config = config or DEFAULT_CONFIG
        self._routes = self.config.get("routes", {})

    def route_config(self, route: str) -> dict:
        return self._routes.get(route, self._routes.get("hermes_api", {}))

    def verdict(self, composite: float, route: str) -> dict:
        rc = self.route_config(route)
        actions = rc.get("actions", {})
        block_at = actions.get("block", 0.95)
        flag_at = actions.get("flag", 0.75)
        throttle_at = actions.get("throttle", 0.60)
        if composite >= block_at:
            return {"action": "block", "score": composite}
        if composite >= flag_at:
            return {"action": "flag", "score": composite}
        if composite >= throttle_at:
            return {"action": "throttle", "score": composite}
        return {"action": "allow", "score": composite}
