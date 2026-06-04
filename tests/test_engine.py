"""Tests for the Sigma engine, rules, and end-to-end detection."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.events import EXPECTED_TECHNIQUES, make_events
from engine.sigma import _match_field, evaluate, load_rules


def rules():
    return load_rules(str(ROOT / "rules"))


def test_all_rules_load_with_attack_tags():
    rs = rules()
    assert len(rs) == 5
    for r in rs:
        assert any(t.startswith("attack.t") for t in r.get("tags", []))


def test_every_attack_technique_is_detected():
    alerts = evaluate(rules(), make_events())
    detected = {t for a in alerts for t in a["techniques"]}
    for tech in EXPECTED_TECHNIQUES.values():
        assert tech in detected, f"missed {tech}"


def test_no_false_positives_on_benign_only_stream():
    benign = [e for e in make_events() if e["_scenario"] is None]
    assert evaluate(rules(), benign) == []


def test_exactly_one_alert_per_injected_attack():
    alerts = evaluate(rules(), make_events())
    assert len(alerts) == len(EXPECTED_TECHNIQUES)


def test_field_modifiers():
    assert _match_field({"x": "Hello World"}, "x|contains", "world")
    assert not _match_field({"x": "Hello"}, "x|contains", "bye")
    assert _match_field({"n": 250}, "n|gte", 100)
    assert not _match_field({"n": 50}, "n|gte", 100)
    assert _match_field({"e": "auth_failure"}, "event_type", "auth_failure") is False  # wrong field
    assert _match_field({"event_type": "auth_failure"}, "event_type", "auth_failure")


def test_bruteforce_threshold_is_windowed():
    # 9 failures from one IP must NOT trigger the >=10 rule.
    evts = [{"timestamp": 1000 + i, "event_type": "auth_failure",
             "src_ip": "9.9.9.9", "_scenario": None} for i in range(9)]
    bf = [r for r in rules() if "Brute Force" in r["title"]]
    assert evaluate(bf, evts) == []
