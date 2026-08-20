"""Tests for the policy engine and JSONL sink."""

import json
import os
import tempfile

from tripwire.policy import Policy, DEFAULT_CONFIG, load_config
from tripwire.sink import TripwireSink


def test_policy_allow_below_thresholds():
    p = Policy()
    v = p.verdict(0.10, "hermes_api")
    assert v["action"] == "allow"


def test_policy_flag_band():
    p = Policy()
    v = p.verdict(0.80, "hermes_api")
    assert v["action"] == "flag"


def test_policy_block_high():
    p = Policy()
    v = p.verdict(0.98, "hermes_api")
    assert v["action"] == "block"


def test_policy_throttle_band():
    p = Policy()
    v = p.verdict(0.65, "hermes_api")
    assert v["action"] == "throttle"


def test_policy_unknown_route_falls_back():
    p = Policy()
    v = p.verdict(0.98, "nonexistent_route")
    assert v["action"] == "block"  # falls back to hermes_api defaults


def test_load_config_defaults_when_missing():
    cfg = load_config("/nonexistent/path.yaml")
    assert cfg["default_mode"] == "flag"
    assert "hermes_api" in cfg["routes"]


def test_sink_writes_jsonl():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "audit.jsonl")
        sink = TripwireSink(jsonl_path=path)
        sink.emit({"action": "flag", "composite": 0.8, "route": "test", "session_id": "s"})
        with open(path) as f:
            line = json.loads(f.readline())
        assert line["action"] == "flag"
        assert line["composite"] == 0.8
