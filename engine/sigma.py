"""A focused, real subset of the Sigma detection-rule spec.

Sigma (https://sigmahq.io) is the SIEM-agnostic detection-as-code standard — the
same rule converts to Splunk SPL, Elastic EQL, Sentinel KQL, etc. This engine
implements the parts these rules use:

  - selection blocks: field equality, `field|contains`, and list values (OR);
    multiple fields in a block are AND-ed.
  - condition: `selection`, `selection and not filter`, and the aggregation
    `selection | count() by <field> >= N` (with an optional `timeframe`).

Each rule carries MITRE ATT&CK technique tags (e.g. `attack.t1110`).
"""
from __future__ import annotations

from pathlib import Path

import yaml


def load_rules(rules_dir: str) -> list[dict]:
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        with open(path, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
            rule["_file"] = path.name
            rules.append(rule)
    return rules


def _match_field(event: dict, key: str, expected) -> bool:
    """Match one `field` or `field|contains` entry. A list value means OR."""
    if "|" in key:
        field, mod = key.split("|", 1)
    else:
        field, mod = key, "equals"
    actual = event.get(field)
    if actual is None:
        return False
    if mod in ("gt", "gte", "lt", "lte"):
        try:
            a, b = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[mod]
    values = expected if isinstance(expected, list) else [expected]
    if mod == "contains":
        return any(str(v).lower() in str(actual).lower() for v in values)
    return any(str(actual) == str(v) for v in values)


def _match_block(event: dict, block: dict) -> bool:
    """All entries in a selection block must match (AND)."""
    return all(_match_field(event, k, v) for k, v in block.items())


def _window_count_ok(timestamps: list[int], threshold: int, timeframe: int) -> bool:
    """True if any sliding window of `timeframe` seconds holds >= threshold events."""
    ts = sorted(timestamps)
    lo = 0
    for hi in range(len(ts)):
        while ts[hi] - ts[lo] > timeframe:
            lo += 1
        if hi - lo + 1 >= threshold:
            return True
    return False


def evaluate(rules: list[dict], events: list[dict]) -> list[dict]:
    """Run every rule over the event stream and return a list of alerts."""
    alerts: list[dict] = []
    for rule in rules:
        det = rule["detection"]
        condition = det["condition"].strip()
        tags = rule.get("tags", [])
        techniques = [t for t in tags if t.startswith("attack.t")]

        # --- Aggregation: "selection | count() by <field> >= N"
        if "|" in condition and "count()" in condition:
            sel_name, agg = [s.strip() for s in condition.split("|", 1)]
            selection = det[sel_name]
            field = agg.split("by", 1)[1].split(">=")[0].strip()
            threshold = int(agg.split(">=")[1].strip())
            timeframe = int(rule["detection"].get("timeframe", 300))
            groups: dict[str, list[int]] = {}
            for e in events:
                if _match_block(e, selection):
                    groups.setdefault(str(e.get(field)), []).append(e["timestamp"])
            for key, tstamps in groups.items():
                if _window_count_ok(tstamps, threshold, timeframe):
                    alerts.append({"rule": rule["title"], "techniques": techniques,
                                   "level": rule.get("level", "medium"),
                                   "group": {field: key}, "count": len(tstamps)})
            continue

        # --- Per-event: "selection" or "selection and not filter"
        negate = None
        sel_name = condition
        if " and not " in condition:
            sel_name, negate = [s.strip() for s in condition.split(" and not ", 1)]
        selection = det[sel_name]
        filt = det.get(negate) if negate else None
        for e in events:
            if _match_block(e, selection) and not (filt and _match_block(e, filt)):
                alerts.append({"rule": rule["title"], "techniques": techniques,
                               "level": rule.get("level", "medium"),
                               "event": {k: v for k, v in e.items() if not k.startswith("_")}})
    return alerts
