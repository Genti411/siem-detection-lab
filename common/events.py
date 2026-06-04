"""Synthetic security-event log with embedded attack scenarios.

Generates a realistic stream of normalized events (ECS-lite). Most are benign;
a handful of labeled attack scenarios are injected so detection rules can be
validated for both true positives (attacks fire) and false positives (benign
traffic stays quiet). Deterministic given a seed.

Each event is a flat dict the detection engine matches against. The hidden
"_scenario" key is ground truth for tests only — rules never reference it.
"""
from __future__ import annotations

import numpy as np

NORMAL_USERS = ["alice", "bob", "carol", "dave"]
NORMAL_IPS = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "203.0.113.8"]
NORMAL_PROCS = ["chrome.exe", "bash", "python.exe", "Code.exe", "explorer.exe"]


def make_events(seed: int = 7, n_benign: int = 2000):
    rng = np.random.default_rng(seed)
    events: list[dict] = []
    t = 1_700_000_000  # base epoch

    def benign(t):
        roll = rng.random()
        if roll < 0.5:
            return {"timestamp": t, "event_type": "auth_success",
                    "user": rng.choice(NORMAL_USERS), "src_ip": rng.choice(NORMAL_IPS),
                    "country": "US", "_scenario": None}
        if roll < 0.8:
            return {"timestamp": t, "event_type": "process_start",
                    "user": rng.choice(NORMAL_USERS), "host": "wks-1",
                    "process": rng.choice(NORMAL_PROCS),
                    "command_line": "normal startup", "_scenario": None}
        return {"timestamp": t, "event_type": "network_flow",
                "user": rng.choice(NORMAL_USERS), "src_ip": rng.choice(NORMAL_IPS),
                "bytes_out": int(rng.integers(1_000, 2_000_000)), "_scenario": None}

    for _ in range(n_benign):
        t += int(rng.integers(1, 20))
        events.append(benign(t))

    # --- Attack scenario 1: brute force (T1110) — 25 failed logins, one IP, ~90s
    bt = 1_700_005_000
    for i in range(25):
        events.append({"timestamp": bt + i * 4, "event_type": "auth_failure",
                       "user": "admin", "src_ip": "198.51.100.66", "country": "RU",
                       "_scenario": "bruteforce"})

    # --- Scenario 2: encoded PowerShell (T1059.001)
    events.append({"timestamp": 1_700_006_000, "event_type": "process_start",
                   "user": "bob", "host": "wks-7", "process": "powershell.exe",
                   "command_line": "powershell -nop -w hidden -EncodedCommand SQBFAFgA",
                   "_scenario": "encoded_powershell"})

    # --- Scenario 3: credential dumping via LSASS access (T1003.001)
    events.append({"timestamp": 1_700_006_500, "event_type": "process_start",
                   "user": "svc", "host": "dc-1", "process": "rundll32.exe",
                   "command_line": "rundll32 comsvcs.dll, MiniDump 612 lsass.dmp full",
                   "_scenario": "cred_dump"})

    # --- Scenario 4: data exfiltration — large outbound transfer (T1048)
    events.append({"timestamp": 1_700_007_000, "event_type": "network_flow",
                   "user": "carol", "src_ip": "10.0.0.13",
                   "bytes_out": 250_000_000, "_scenario": "exfil"})

    # --- Scenario 5: privilege escalation — add user to admins (T1098)
    events.append({"timestamp": 1_700_007_500, "event_type": "process_start",
                   "user": "dave", "host": "wks-3", "process": "net.exe",
                   "command_line": "net localgroup administrators eviluser /add",
                   "_scenario": "priv_esc"})

    events.sort(key=lambda e: e["timestamp"])
    return events


EXPECTED_TECHNIQUES = {
    "bruteforce": "attack.t1110",
    "encoded_powershell": "attack.t1059.001",
    "cred_dump": "attack.t1003.001",
    "exfil": "attack.t1048",
    "priv_esc": "attack.t1098",
}
