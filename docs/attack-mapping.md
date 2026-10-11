# ATT&CK / Data-Source Mapping

**Deliberately conservative and evidence-based.** This lab modified a *disposable text
file* in `/tmp` with `sed`, as an authorized user. It is a telemetry/detection exercise,
not a demonstration of any adversary technique. The mapping below distinguishes what the
capture **actually evidences** from what it is merely **relevant to**.

## What the capture actually evidences: ATT&CK data sources
The strongest honest statement is coverage of **data sources**, not techniques:

| ATT&CK Data Source | Component | Evidence |
|--------------------|-----------|----------|
| File | File Modification | auditd `PATH`/`SYSCALL` records for every write to the monitored file (serials 11418/11419/11420) |
| Process | Process Creation | `comm`/`exe`/`pid`/`ppid`/`PROCTITLE` for the `sed` processes that performed the writes |

These data sources are what a SOC would use to *detect* file-tampering techniques on real targets.

## Techniques: applicability vs demonstration
| Technique | Status | Rationale |
|-----------|--------|-----------|
| **T1565.001 — Stored Data Manipulation** | *Weak / simulation-level, LOW confidence* | A stored file's contents were altered. This matches the **signature** of stored-data modification, but the target was a benign lab file, so it is a telemetry analogue — **not** proof of adversary data manipulation. |
| T1556 — Modify Authentication Process | **NOT mapped** | No real authentication process exists or was touched; `security.conf` is an invented lab file with invented keys. |
| T1548 — Abuse Elevation Control Mechanism | **NOT mapped** | No elevation occurred — `euid=1000` throughout; the `ELEVATED` flag never fired. |
| T1562.001 — Impair Defenses | **NOT mapped** | No security tooling or logging was impaired or disabled. |
| T1070 — Indicator Removal | **NOT mapped** | No logs or indicators were removed. |

## Honest conclusion
This project demonstrates **detection coverage of the File-Modification and
Process-Creation data sources** via auditd. That coverage *would support* detecting
stored-data-manipulation and config-tampering activity (e.g. T1565.001, and
authentication-weakening behaviour of the kind simulated here) **if applied to real
targets** — but no specific ATT&CK technique is proven by this capture, and none should
be claimed.
