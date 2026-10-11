# SOC-001 — Linux Security Operations

**auditd telemetry · file-modification detection · investigation of controlled configuration changes**

A detection-and-investigation project demonstrating a complete Linux SOC workflow on a
single, well-evidenced scenario: monitoring a sensitive configuration file with the Linux
Audit subsystem, detecting modifications, and investigating them like a SOC analyst.

> **Scope & honesty.** This is a **lab project**. The investigated "suspicious" change is a
> **controlled suspicious-behavior simulation on a disposable lab configuration file**
> (`/tmp/soc-security-lab/security.conf`). It is **not** a real compromise, not real
> authentication tampering, and not production SOC experience. Claims are limited to what
> the captured evidence proves.

## Evidence maturity: **Level 3**
Working telemetry + detection + investigation, with captured, reproducible evidence and
documented limitations. It is **not** Level 4: no cross-source correlation, no
tuning/regression suite yet, and ATT&CK is honestly only data-source-level (see below).

## SOC workflow demonstrated
```
telemetry → detection → alert → triage → investigation → evidence → assessment → improvement
```
1. **Telemetry** — auditd rule on the monitored file (`telemetry/auditd-config-monitoring.md`).
2. **Detection** — `detect_config_change.sh` parses audit events into layered output.
3. **Alert** — analyst-facing TELEMETRY → DETECTION → ALERT with next steps.
4. **Triage/Investigation** — authorized vs simulated-suspicious change worked end to end.
5. **Evidence** — raw telemetry, before/after configs, diffs, detection output (preserved).
6. **Assessment & improvement** — documented limitations and concrete next steps.

## Architecture
```
SOC-001-linux-security-operations/
├── README.md                     ← this file
├── telemetry/
│   └── auditd-config-monitoring.md
├── detections/
│   └── sensitive-config-modification/
│       ├── detect_config_change.sh      (detection logic, preserved verbatim)
│       ├── 31-soc-security-config.rules (auditd rule)
│       └── README.md
├── investigations/
│   └── 001-config-change-sed-atomic-replace/
│       ├── case.md                      (19-section investigation report)
│       └── evidence/                    (real captured artifacts + index)
└── docs/
    ├── attack-mapping.md
    └── limitations.md
```

## Telemetry source
Linux Audit (`auditd`), queried with `ausearch -k soc_sensitive_config`. The rule uses
`perm=wa`, so the kernel expands it to all write/attribute syscalls **including the rename
family** — which is why atomic `sed -i` edits (ending in `rename()`, syscall 82) are
captured. Details: `telemetry/auditd-config-monitoring.md`.

## Detection logic
`detect_config_change.sh` queries the audit log, splits per-event blocks, skips
`comm="auditctl"` rule-management noise, and for each real write extracts the SYSCALL
fields, decodes the hex `PROCTITLE`, resolves the affected path through rename events
(`nametype=CREATE`), resolves `auid/uid/euid` and the syscall name, applies automated
context flags, and prints **TELEMETRY → DETECTION → ALERT**. It intentionally does **not**
declare a write malicious — context decides. Details: `detections/sensitive-config-modification/README.md`.

## Investigation
`investigations/001-config-change-sed-atomic-replace/` captures an authorized change
(serial 11418) and a simulated-suspicious change (serials 11419/11420) on the disposable
lab file, with full before/after state, diffs, raw auditd records, and detection output.
Precise mechanics (sed atomic replacement, temp-file creation, rename syscall, inode
changes 7721→7724, PATH CREATE/DELETE, PID/PPID, auid/uid/euid, session, CWD, proctitle)
are analysed in `case.md`.

## Validation
- Telemetry reached the detection; all fields parsed correctly; `auditctl` noise filtered.
- Reproducibility: the full run and re-run outputs are **identical except the volatile
  `Run time:` header** — a harness artifact, **not** a detection failure (see limitations).
- Evidence integrity: originals preserved unaltered; a labeled current-run excerpt is
  provided; historical vs current events are annotated (`evidence/EVIDENCE-INDEX.md`).

## ATT&CK (conservative)
The capture evidences **data-source coverage** — *File: File Modification* and *Process:
Process Creation*. Technique mapping is limited to **T1565.001 (Stored Data Manipulation)
at low/simulation confidence**; **T1556, T1548, T1562.001, T1070 are not claimed.**
See `docs/attack-mapping.md`.

## Limitations (summary)
No SIEM ingestion; no cross-source correlation; no validated process-execution telemetry;
time-scoping and a deterministic regression harness are needed; several `classify_event`
branches and alternate editors are untested; inode is in raw telemetry but not extracted.
Full list: `docs/limitations.md`.

## Running it
```bash
# 1. load the rule (lab path):  sudo auditctl -R detections/sensitive-config-modification/31-soc-security-config.rules
# 2. after writes occur:        sudo detections/sensitive-config-modification/detect_config_change.sh --since HH:MM:SS
```
`sudo` is required to read `/var/log/audit/audit.log`.
