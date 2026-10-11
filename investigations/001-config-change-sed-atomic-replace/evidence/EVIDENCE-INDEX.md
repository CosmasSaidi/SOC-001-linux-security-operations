# Evidence Index — Investigation 001

All files here are **real captured artifacts** from the 2026-10-11 controlled capture
(`~/soc-lab/evidence/soc-001-capture/`), copied unaltered except where a file is clearly
labeled a derived excerpt. No evidence was fabricated or edited to look cleaner.

## ⚠️ Current-run vs historical events (read first)
`raw/detection-output.full.txt` and `raw/ausearch-raw.txt` contain **8 file-write events**,
because the detection was run without time scoping and `--input-logs` reads the whole
audit history. **Only 3 events belong to THIS case:**

| Serial | Time (EAT) | This case? | Change |
|--------|-----------|-----------|--------|
| 11418 | 2026-10-11 14:24:12 | ✅ authorized | `session_timeout_minutes 15 → 20` |
| 11419 | 2026-10-11 14:24:14 | ✅ suspicious sim | `max_login_attempts 5 → 100` |
| 11420 | 2026-10-11 14:24:14 | ✅ suspicious sim | `require_mfa true → false` |
| 517, 518, 1169, 1171, 1173 | 2026-10-02 / 10-03 | ❌ historical | prior lab runs — **not** part of this case |

(Serial 11403 is the ephemeral rule load for this run, not a file write.)
For a clean view, use `current-run/ausearch-current-run.txt`, which contains only this
case's events.

## Files
| Path | What it is | Integrity |
|------|-----------|-----------|
| `MANIFEST.txt` | Timeline of exact capture actions | unaltered original |
| `current-run/ausearch-current-run.txt` | **Derived excerpt**: only serials 11403/11418/11419/11420 | labeled excerpt of raw |
| `raw/ausearch-raw.txt` | Full raw auditd records (all history) | unaltered original |
| `raw/detection-output.full.txt` | Full detection run output (8 events) | unaltered original |
| `raw/detection-output.rerun.txt` | Reproducibility re-run (differs only by `Run time:` header) | unaltered original |
| `config/security.conf.00-initial` | Baseline lab file | unaltered original |
| `config/security.conf.10/11-*authorized` | Before/after the authorized change | unaltered original |
| `config/security.conf.20/21-*suspicious` | Before/after the suspicious simulation | unaltered original |
| `config/security.conf.30-final` | Final lab-file state | unaltered original |
| `config/diff-authorized.txt` | Diff of the authorized change | unaltered original |
| `config/diff-suspicious.txt` | Diff of the suspicious simulation | unaltered original |
| `rule/audit-rule.args.txt` / `.command.txt` | Rule as requested | unaltered original |
| `rule/audit-rule.loaded.txt` | Kernel-expanded loaded rule (shows rename family) | unaltered original |
| `rule/auditd-status.txt` | `auditctl -s` daemon status | unaltered original |

## Provenance & redaction (public copies)
These files are **derived public copies** of the immutable originals captured at
`~/soc-lab/evidence/soc-001-capture/` on the lab host. The only modifications applied to
these public copies are **(1)** redaction of the local home-directory path component (the host
account's `/home/<username>` → `/home/<USER>`) and **(2)** masking of the resolved textual
username in identity fields (the account name resolved from UID 1000 → `<USER>`, e.g.
`auid: <USER> (1000)`). **Nothing else was changed:** timestamps, audit
serials, syscall numbers, PID/PPID, `auid/uid/euid` values, session IDs, inode values,
executable paths (`/usr/bin/sed`), command content, detection results, and event structure
are all preserved exactly as captured — only the textual account name was masked.

## Serial 11403 — setup event, NOT a case event
Serial **11403** (2026-10-11 14:24:12) is an **auditd rule-management / configuration event**:
`comm="auditctl"`, `exe="/usr/sbin/auditctl"`, `syscall=44 (sendto)`, with a `CONFIG_CHANGE
op=add_rule key="soc_sensitive_config"` record — i.e. the moment the monitoring rule itself
was loaded. It is **setup telemetry, not a modification of the monitored file.** The
detection script correctly **excludes** it (its `comm="auditctl"` filter), so 11403 appears
only in the raw/current-run telemetry, never in the detection output. The **case events**
are strictly:

| Serial | Role |
|--------|------|
| 11418 | authorized change |
| 11419 | suspicious simulation |
| 11420 | suspicious simulation |

## Safety note
All changes targeted only the disposable `/tmp/soc-security-lab/security.conf`. No real
system control (`/etc/passwd`, `/etc/shadow`, PAM, SSH, sudoers) was touched. The audit
rule was loaded ephemerally and removed after capture (see `MANIFEST.txt`).
