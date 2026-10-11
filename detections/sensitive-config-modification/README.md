# Detection: Sensitive Configuration File Modification

**Key:** `soc_sensitive_config` · **Telemetry:** Linux Audit (`auditd`) · **Script:** `detect_config_change.sh`

## Objective
Make every write or attribute change to a monitored configuration file auditable, and
surface a structured, analyst-facing alert. The goal is **visibility**, not automated
verdicts: configuration files are modified legitimately every day, so the detection
forces a human to confirm whether a given change was expected.

> This detection does **not** classify a write as malicious. Context — who, from where,
> at what time, expected or not — determines whether an alert becomes an incident.

## Files
| File | Purpose |
|------|---------|
| `detect_config_change.sh` | Detection logic (query → parse → layered output). Preserved verbatim from the lab. |
| `31-soc-security-config.rules` | The auditd rule that produces the telemetry. |

## Telemetry source
- Subsystem: Linux Audit (`auditd`), queried with `ausearch -k soc_sensitive_config`.
- Rule: `-a always,exit -F arch=b64 -S <write syscalls> -F path=<file> -F perm=wa -F key=soc_sensitive_config`.
- `perm=wa` causes the kernel to expand the syscall set to all write/attribute-change
  calls **including the rename family**, which is why atomic `sed -i` edits are captured.

## Detection logic (as implemented)
1. `ausearch -k soc_sensitive_config --input-logs` → all tagged events.
2. Split output into per-event blocks (`----` separated).
3. Skip blocks with no `SYSCALL` record, and skip `comm="auditctl"` (rule-management noise).
4. Per event: extract SYSCALL fields; decode the hex `PROCTITLE`; choose the affected
   path (prefer `nametype=CREATE` for rename-based writes, else `NORMAL`, else first
   non-`PARENT`); resolve `auid/uid/euid` via `getent`; resolve the syscall number via
   `ausyscall`; annotate automated context flags.
5. Emit three layers: **TELEMETRY** (raw facts) → **DETECTION** (rule match + mapped
   fields) → **ALERT** (analyst summary, context notes, next-step checklist).

## Automated context flags (`classify_event`)
`ELEVATED` (euid=root, auid≠root) · `PRIVILEGE` (euid=root) · `UNTRACED` (auid unset) ·
`NON-INTERACTIVE` (no tty) · `SUSPICIOUS PATH` (exe in /tmp, /dev/shm) · `FAILED` (success≠yes).
None is a verdict; each is a prompt for the analyst.

## Validated behavior (investigation 001)
Against real captured telemetry the script correctly: collected auditd events, resolved
the affected path through `sed -i` rename events, interpreted syscall 82 as `rename`,
decoded `PROCTITLE` to the exact command, resolved `auid/uid/euid`, filtered `auditctl`
rule-management noise, and produced the layered TELEMETRY→DETECTION→ALERT output.
See `../../investigations/001-config-change-sed-atomic-replace/`.

## Usage
```bash
sudo ./detect_config_change.sh                 # all tagged events in the log
sudo ./detect_config_change.sh --since HH:MM:SS # scope to a time window (recommended)
sudo ./detect_config_change.sh --raw            # include raw ausearch block per event
```
`sudo` is required because reading `/var/log/audit/audit.log` needs root.

## Known limitations (summary)
Unscoped runs include historical events; `inode` is present in raw telemetry but not
extracted into the parsed output; the regression comparison is affected by the volatile
`Run time:` header. Full list in `../../docs/limitations.md`.
