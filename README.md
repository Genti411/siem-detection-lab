# SIEM Detection Lab — Sigma Rules + MITRE ATT&CK

A small **detection-engineering** project: a rule engine that evaluates
**Sigma** detection rules against a stream of security logs and raises alerts,
with every rule mapped to a **MITRE ATT&CK** technique. It demonstrates the core
SIEM workflow — *normalize logs → write detections as code → alert → map to
ATT&CK* — without needing a heavyweight Splunk/Elastic deployment to verify.

| Area | What's shown |
|------|--------------|
| **Detection engineering** | Detection-as-code: rules live in version-controlled YAML, tested like software |
| **Sigma** | Real Sigma rules (selection blocks, `\|contains`/`\|gte` modifiers, count aggregation with timeframe) |
| **MITRE ATT&CK** | Every rule tagged with the technique it detects |
| **SIEM concepts** | Normalized events (ECS-lite), windowed correlation (brute force), true/false-positive evaluation |

## Detections

| Rule | Technique | Logic |
|------|-----------|-------|
| Brute Force - Multiple Failed Logins | [T1110](https://attack.mitre.org/techniques/T1110/) | ≥10 `auth_failure` from one `src_ip` within 5 min |
| Encoded PowerShell Command | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | `powershell.exe` with `-EncodedCommand` |
| LSASS Memory Dump | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | process cmdline references `lsass`/`MiniDump`/`comsvcs.dll` |
| Large Outbound Transfer | [T1048](https://attack.mitre.org/techniques/T1048/) | `network_flow` with `bytes_out ≥ 100 MB` |
| User Added to Local Admins | [T1098](https://attack.mitre.org/techniques/T1098/) | `net.exe ... localgroup administrators` (not `/delete`) |

## Run

```bash
docker build -t siem-detection-lab . && docker run --rm siem-detection-lab
# or locally:
pip install -r requirements.txt && python detect.py
```

`detect.py` generates a labeled event stream (2,000 benign events + 5 injected
attack scenarios), runs the engine, prints the alerts and an ATT&CK coverage
table, and exits non-zero unless **every** attack is caught with **zero** false
positives on benign traffic.

## Tests

```bash
python -m pytest tests/
```

Covers rule loading, per-technique detection, the windowed brute-force threshold
(9 failures must *not* fire a ≥10 rule), field modifiers, and the
no-false-positives guarantee on a benign-only stream.

## How these rules reach a real SIEM

The files in `rules/` are **Sigma** — the vendor-neutral detection standard. With
[`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) / pySigma they convert to the
query language of your platform, e.g.:

```bash
sigma convert -t splunk  rules/bruteforce_logins.yml   # -> Splunk SPL
sigma convert -t elastic rules/encoded_powershell.yml  # -> Elastic EQL/Lucene
```

So the same rule that this engine runs is deployable to Splunk, Elastic, or
Microsoft Sentinel unchanged. (The engine here implements a focused subset of the
Sigma spec — enough to run and test these rules end to end.)

## Note on the data

Events are **synthetic** and clearly labeled; the attack scenarios are modeled on
real techniques. The pipeline — normalize → detect → correlate → alert → map to
ATT&CK — is exactly what you'd run against real Sysmon/auth logs; only the log
source changes.

## Layout

```
common/events.py     synthetic ECS-lite event stream with labeled attacks
engine/sigma.py      Sigma-subset rule engine (match, modifiers, windowed count)
rules/*.yml          five Sigma detections, each MITRE ATT&CK-tagged
detect.py            run engine + ATT&CK coverage report (CI smoke test)
tests/test_engine.py pytest
```
