# Limitations & Known Gaps

This project is honestly scoped as **Level 3** evidence (working telemetry + detection +
investigation). The following limitations are deliberately documented; they define the
path to Level 4 and prevent over-claiming.

## Current limitations
- **No SIEM ingestion.** Detection runs locally against `/var/log/audit/audit.log` via
  `ausearch`. There is no Splunk/Sentinel/Elastic pipeline, no indexing, no dashboards.
- **No cross-source correlation.** Only auditd file/syscall telemetry is used. No
  endpoint↔network, authentication, or process-ancestry correlation across sources.
- **No process-execution telemetry validated.** This capture covered file-write
  (`rename`) events only. A dedicated `execve` detection has **not** been validated here
  (the `process-lab` material is a stub and is intentionally excluded).
- **Time scoping needed.** The detection was run without `--since`, so `--input-logs`
  returned the whole audit history: 8 events, of which only 3 (serials 11418/11419/11420)
  belong to this case. The other 5 (517/518/1169/1171/1173) are historical prior-run
  events. Future runs should scope by time or tag per run.
- **Regression harness timestamp issue.** `detection-output.full.txt` and
  `detection-output.rerun.txt` differ **only** in the volatile `Run time:` header line;
  the 8 event blocks are identical. This is a reproducibility *harness* artifact, **not**
  a detection failure. Fix: compare with the `Run time:` line excluded (e.g.
  `grep -v 'Run time:'`), or add a deterministic/no-header mode for regression tests.
- **classify_event branches not fully exercised.** The ELEVATED, UNTRACED,
  NON-INTERACTIVE, SUSPICIOUS-PATH and FAILED flags did not trigger in this capture
  (all writes were interactive, non-elevated, successful). Those branches remain untested.
- **Single file / single editor.** Only one monitored path and only `sed -i` were tested.
  Other writers/editors (`vi`, `tee`, shell redirection) and multiple files are untested.
- **No legitimate-writer allowlist / tuning.** The detection fires on all writes by
  design; there is no tuned baseline of expected writers for false-positive management.
- **inode not extracted.** Inode data is present in the raw `PATH` records (observed
  7721→7722→7723→7724) but the detection script does not parse it into its output.

## Explicitly NOT claimed
- Not a real compromise, and not real authentication-system tampering.
- Not production SOC experience.
- Not proof of T1556, T1548, T1562.001, or T1070 (see `attack-mapping.md`).
- No SIEM, no cross-source correlation, no validated process-execution telemetry.

## Path to Level 4
Add time-scoped single-incident capture; a deterministic regression harness; at least one
case that trips a `classify_event` flag (e.g. non-interactive or elevated write);
cross-source correlation; and inode extraction. These are enhancements, not fixes to
broken behavior.
