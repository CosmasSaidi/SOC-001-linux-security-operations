# Investigation 001 — Configuration Change via `sed -i` Atomic Replacement

> **Nature of this case:** a **controlled lab exercise** on a **disposable configuration
> file** (`/tmp/soc-security-lab/security.conf`). The "suspicious" step is a
> **controlled suspicious-behavior simulation on a disposable lab configuration file** —
> **not** a real compromise, not real authentication tampering, and not production SOC work.

## 1. Case ID
`SOC-001-INV-001` · Detection key `soc_sensitive_config` · Captured 2026-10-11 (EAT).

## 2. Scenario
A monitored sensitive configuration file is modified twice: once as a clearly
**authorized** administrative change, and once as a **simulated suspicious** change that
weakens (fake) security settings. The analyst must determine, from auditd telemetry,
what happened and whether each change warrants escalation.

## 3. Objective
Validate that auditd telemetry + the `sensitive-config-modification` detection can
(a) capture every write to the monitored file, (b) reconstruct who/what/how, and
(c) support a human triage decision — **without** auto-labelling benign writes malicious.

## 4. Environment
- Host: Linux (Kali, kernel 6.19.x), single workstation.
- Telemetry: `auditd` (`enabled 1`, pid 775, backlog_limit 8192 — `evidence/rule/auditd-status.txt`).
- Monitored file (disposable lab): `/tmp/soc-security-lab/security.conf`.
- Actor identity for all writes: `auid=1000 (<USER>)`, `uid=euid=1000`, interactive `tty=pts9`, `ses=917`, `cwd=/home/<USER>`.
- Rule: ephemeral `auditctl` load, key `soc_sensitive_config` (removed after capture).

## 5. Timeline (from `evidence/MANIFEST.txt`, EAT)
| Time | Action | Audit serial |
|------|--------|--------------|
| 14:24:05 | Disposable lab file created (pre-rule) | — |
| 14:24:12 | Ephemeral audit rule loaded | 11403 |
| 14:24:12 | **Authorized** change (`session_timeout 15→20`) | 11418 |
| 14:24:14 | **Suspicious sim** (`max_login_attempts 5→100`) | 11419 |
| 14:24:14 | **Suspicious sim** (`require_mfa true→false`) | 11420 |
| 14:24:16 | Detection run (full + `--raw`) | — |
| 14:24:19 | Reproducibility re-run | — |
| 14:24:20 | Cleanup: rule deleted, lab file removed, evidence retained | — |

> **Serial 11403 is a setup event, not a case event.** It is the `auditctl` rule load
> (`comm="auditctl"`, `syscall=44 sendto`, `CONFIG_CHANGE op=add_rule`) — audit
> configuration-management telemetry, correctly filtered out by the detection. The only
> **case events** are 11418 (authorized), 11419 and 11420 (suspicious simulation).

## 6. Initial telemetry
The rule produces one audit event per write. The authoritative `SYSCALL` record for the
authorized change (serial 11418) shows:
```
syscall=82 (rename) success=yes exit=0 ppid=215445 pid=215499
auid=1000 uid=1000 gid=1000 euid=1000 tty=pts9 ses=917
comm="sed" exe="/usr/bin/sed" key="soc_sensitive_config"
```
Clean telemetry: a login-attributable (`auid=1000`), interactive, non-elevated process.
Full records: `evidence/current-run/ausearch-current-run.txt`.

## 7. Authorized change (serial 11418)
- **Change:** `session_timeout_minutes = 15 → 20` (benign maintenance). Diff: `evidence/config/diff-authorized.txt`.
- **Command (decoded PROCTITLE):** `sed -i s/^session_timeout_minutes = 15/session_timeout_minutes = 20/ /tmp/soc-security-lab/security.conf`
- **Mechanics:** `sed -i` wrote temp `sedrEJ7yV` then `rename()`d it over the target. `PATH` records: `nametype=CREATE` new inode **7722**, `nametype=DELETE` old inode **7721**, plus the temp and `PARENT` entries. `cwd=/home/<USER>`, `pid 215499 / ppid 215445`.
- **Detection:** fired; `classify_event` → "No automated risk indicators — context review still required."
- **Disposition:** consistent with an authorized interactive admin edit; closed as expected activity after diff review.

## 8. Suspicious simulated change (serials 11419, 11420) — disposable lab file
- **Changes (simulation):** `max_login_attempts = 5 → 100` and `require_mfa = true → false`. Diff: `evidence/config/diff-suspicious.txt`.
- **Decoded PROCTITLEs:** `sed -i s/^max_login_attempts = 5/max_login_attempts = 100/ …` and `sed -i s/^require_mfa = true/require_mfa = false/ …`.
- **Mechanics:** two further `rename()` events, inodes **7723** then **7724** (`pid 215515`, `215516`; same `ses=917`, `tty=pts9`).
- **Detection:** fired on both; `classify_event` → "No automated risk indicators."
- **Why this reads as suspicious:** not from any automated flag, but from the **content** (weakening lockout + disabling MFA on a security-settings file). This is exactly the design: telemetry is identical to a benign edit; **context/content decides**.
- **Framing:** a controlled suspicious-behavior simulation on a disposable lab file. No real authentication control exists or was affected.

## 9. Raw evidence
- Clean current-run telemetry: `evidence/current-run/ausearch-current-run.txt` (serials 11403/11418/11419/11420 only).
- Full originals (unaltered): `evidence/raw/ausearch-raw.txt`, `evidence/raw/detection-output.full.txt`, `evidence/raw/detection-output.rerun.txt`.
- ⚠️ The full outputs contain **8** write events; only the 3 above are this case. Serials 517/518/1169/1171/1173 are **historical** prior-run events — see `evidence/EVIDENCE-INDEX.md`.

## 10. Before/after comparison
| Setting | Initial (`.00`) | After authorized (`.11`) | After suspicious (`.21` / `.30`) |
|---------|------|------|------|
| session_timeout_minutes | 15 | **20** | 20 |
| max_login_attempts | 5 | 5 | **100** |
| require_mfa | true | true | **false** |
Snapshots + diffs under `evidence/config/`.

## 11. Detection analysis
The detection correctly: collected the auditd events; resolved the affected path through
the `sed -i` **rename** indirection (preferring `nametype=CREATE`); interpreted syscall
**82 → rename**; decoded each `PROCTITLE` to the exact command; resolved `auid/uid/euid`
`1000 → <USER>`; **filtered `comm="auditctl"` rule-management noise**; and emitted the
layered **TELEMETRY → DETECTION → ALERT** output with analyst next-steps. Of 8 events in
the unscoped run, all 8 were parsed; the 3 current-run events are the subject here.

## 12. Analyst assessment
- **Authorized (11418):** expected administrative change; **no escalation**.
- **Suspicious sim (11419/11420):** on a real host, weakening lockout and disabling MFA
  would be **high-priority** and warrant escalation pending change-management confirmation.
  Here it is a **simulation**; telemetry fidelity (actor, process, exact change, session)
  was sufficient to support that triage decision.
- The detection behaved as a **visibility** control: it surfaced every write for review;
  it did not — and is not designed to — pronounce intent.

## 13. Scope
One monitored file, one host, one interactive session (`ses=917`), one editor (`sed`).
No lateral movement, no other files, no other sessions involved.

## 14. Impact assessment
**None (lab).** Only the disposable `/tmp` file changed. No real security control,
service, account, or data was affected. On a real host, the simulated changes *would*
represent a material authentication-weakening impact — stated here only as context, not
as something that occurred.

## 15. Containment / recovery considerations
Illustrative (not performed on any real system): confirm the change against
change-management; if unauthorized, restore the file from last known-good backup, rotate
exposed credentials if the file governed them, review the full `ses=917` session for
preceding actions, and preserve the audit records as evidence before remediation.

## 16. Limitations
Unscoped run included historical events; `classify_event` risk branches (elevated,
non-interactive, failed) were not exercised; `inode` is in raw telemetry but not parsed;
regression comparison is affected by the volatile `Run time:` header. Full list:
`../../docs/limitations.md`.

## 17. ATT&CK / data-source mapping
Evidence supports **data-source coverage only**: *File: File Modification* and *Process:
Process Creation* (auditd). Technique mapping is deliberately conservative —
**T1565.001 (Stored Data Manipulation)** at low/simulation confidence only; **T1556,
T1548, T1562.001, T1070 are NOT claimed**. See `../../docs/attack-mapping.md`.

## 18. Lessons learned
- `perm=wa` auditing captures atomic `sed -i` because the kernel expands the syscall set
  to include `rename` — path-based auditing survives the inode change, inode-based
  integrity tracking would not (inode moved 7721→7722→7723→7724).
- Identical telemetry can represent authorized or suspicious activity; **content + context
  are the deciding evidence**, which is why structured capture (PROCTITLE, diff, session)
  matters more than an automated verdict.
- Unscoped `ausearch` mixes historical and current events — scope every run.

## 19. Detection improvement opportunities
- Add `--since`/per-run tagging so output is a single-incident view.
- Deterministic regression harness that ignores the volatile `Run time:` header.
- Extract and surface `inode` in the parsed output.
- Add a case that trips a `classify_event` flag (non-interactive or elevated write).
- Validate additional editors (`vi`, `tee`, shell redirection) and multiple files.
- Introduce a legitimate-writer baseline/allowlist for false-positive tuning.

