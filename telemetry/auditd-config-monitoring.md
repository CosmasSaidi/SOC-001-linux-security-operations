# Telemetry: auditd Configuration-File Monitoring

How the telemetry behind this project is collected and what each field means.

## Source
- **Subsystem:** Linux Audit (`auditd`) — kernel-level syscall/path auditing.
- **Daemon status (captured):** `enabled 1`, `pid 775`, `backlog_limit 8192` (see
  `../investigations/001-config-change-sed-atomic-replace/evidence/rule/auditd-status.txt`).
- **Query tool:** `ausearch -k soc_sensitive_config` (userspace, from the audit package).
- **Resolution helpers:** `ausyscall` (syscall number → name), `getent` (uid → name).

## The rule
Defined in `../detections/sensitive-config-modification/31-soc-security-config.rules`:

```
-a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate,fallocate,
   write,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,
   chmod,fchmod,chown,fchown,lchown
   -F path=/tmp/soc-security-lab/security.conf -F perm=wa -F key=soc_sensitive_config
```

The kernel expands this (because of `perm=wa`) to a larger write/attribute syscall set
that **includes the rename family**. The expanded, loaded form is preserved at
`evidence/rule/audit-rule.loaded.txt`. This expansion is the reason an atomic `sed -i`
edit — which ends in `rename()` (syscall 82) — triggers the rule.

## Event records produced
A single monitored write typically yields one audit event containing:

| Record | Carries |
|--------|---------|
| `SYSCALL` | authoritative line: syscall number, success/exit, `ppid/pid`, `auid/uid/euid/gid`, `tty`, `ses`, `comm`, `exe`, `key` |
| `PATH` (×N) | affected paths with `nametype` = `CREATE`/`DELETE`/`PARENT` and `inode`/`dev`/`mode` |
| `CWD` | working directory at syscall time |
| `PROCTITLE` | hex-encoded full command line |

## Fields and why they matter for investigation
- **auid** (login UID): who logged in — survives `su`/`sudo`, so it attributes action to a person. Captured value in 001: `1000` (<USER>).
- **uid / euid**: effective identity at syscall time. `euid=root, auid≠root` would indicate a privilege-escalation path (not observed in 001).
- **pid / ppid**: process and parent — enables process-tree reconstruction.
- **ses**: audit session ID — links every action in one login session.
- **tty**: `pts/N` = interactive; `(none)` = cron/service/piped (non-interactive).
- **comm / exe**: process name and on-disk binary (`sed` / `/usr/bin/sed` in 001).
- **CWD**: working directory (`/home/<USER>` in 001).
- **PROCTITLE** (decoded): the exact command, e.g. `sed -i s/^max_login_attempts = 5/max_login_attempts = 100/ …`.
- **PATH nametype / inode**: for rename-based writes, `CREATE` is the new destination inode and `DELETE` the old one — the **inode changes on every `sed -i` write** (observed 7721→7722→7723→7724 in 001), which is why integrity tools that track by inode lose the file after one edit.

## Scope / honesty
This is **local auditd telemetry only**. There is no SIEM ingestion, no forwarding, and
no cross-source correlation in this project. See `../docs/limitations.md`.
