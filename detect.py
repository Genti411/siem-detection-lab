"""Run the detection engine over the event stream and report alerts.

Doubles as a smoke test: exits non-zero unless every injected attack technique is
detected AND there are no extra (false-positive) alerts.
"""
import sys

from common.events import EXPECTED_TECHNIQUES, make_events
from engine.sigma import evaluate, load_rules


def main() -> int:
    rules = load_rules("rules")
    events = make_events()
    benign = sum(1 for e in events if e["_scenario"] is None)
    print(f"loaded {len(rules)} Sigma rules; scanning {len(events)} events "
          f"({benign} benign, {len(events) - benign} attack)")

    alerts = evaluate(rules, events)

    print(f"\n=== {len(alerts)} ALERT(S) ===")
    for a in alerts:
        ctx = a.get("group") or a.get("event", {})
        print(f"[{a['level'].upper():8}] {a['rule']}")
        print(f"           {', '.join(a['techniques'])}  ::  {ctx}")

    detected = {t for a in alerts for t in a["techniques"]}
    expected = set(EXPECTED_TECHNIQUES.values())
    missing = expected - detected
    print("\n=== coverage ===")
    for scenario, tech in EXPECTED_TECHNIQUES.items():
        print(f"  {'HIT ' if tech in detected else 'MISS'}  {scenario:18} {tech}")

    # Clean detection = every attack technique fired, and no extra alerts beyond
    # the 5 injected attacks (i.e. zero false positives on benign traffic).
    no_fp = len(alerts) == len(EXPECTED_TECHNIQUES)
    ok = not missing and no_fp
    print(f"\nfalse positives: {0 if no_fp else len(alerts) - len(EXPECTED_TECHNIQUES)}")
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
