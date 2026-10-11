#!/usr/bin/env bash
# =============================================================================
# detect_config_change.sh
#
# SOC Detection: Sensitive Configuration File Modification
# Project:       Linux SOC Analyst Lab – Project 1, Scenario 2
# Telemetry:     auditd syscall/path events, key=soc_sensitive_config
# Author:        soc-lab
# Created:       2026-10-02
# =============================================================================
#
# WHAT THIS SCRIPT DOES
#   Queries the audit log for all events tagged soc_sensitive_config, extracts
#   structured fields from each SYSCALL record, and emits a layered output:
#
#     TELEMETRY  – raw fact from the audit log (no judgment)
#     DETECTION  – pattern match: "this event satisfies rule conditions"
#     ALERT      – human-readable summary with context notes for a SOC analyst
#
#   It deliberately does NOT declare every matching event malicious.
#   Context (who, from where, at what time, expected or not) determines
#   whether an alert becomes an incident. That judgment belongs to the analyst.
#
# USAGE
#   ./detect_config_change.sh [--since HH:MM:SS] [--raw] [--help]
#
#   --since HH:MM:SS   Only show events from this time today (default: today)
#   --raw              Also dump the raw ausearch block for each event
#   --help             Show this help
#
# DEPENDENCIES
#   ausearch   (part of auditd/audit-userspace – already installed)
#   ausyscall  (part of auditd/audit-userspace – already installed)
#   awk, grep, sed, date, id, getent  (standard POSIX utilities)
#
# EXIT CODES
#   0  One or more events found and processed
#   1  No matching events found
#   2  auditd/ausearch not available
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AUDIT_KEY="soc_sensitive_config"
MONITORED_FILE="/tmp/soc-security-lab/security.conf"
SCRIPT_VERSION="1.0.0"
SEPARATOR="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
SINCE_TIME=""
SHOW_RAW=0

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,2\}//' | head -30
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --since) SINCE_TIME="$2"; shift 2 ;;
        --raw)   SHOW_RAW=1; shift ;;
        --help|-h) usage ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if ! command -v ausearch &>/dev/null; then
    echo "[ERROR] ausearch not found. Is auditd installed?" >&2
    exit 2
fi

if ! systemctl is-active --quiet auditd 2>/dev/null; then
    echo "[WARNING] auditd does not appear to be running. Results may be stale." >&2
fi

# ---------------------------------------------------------------------------
# Helper: resolve numeric uid to username
# ---------------------------------------------------------------------------
resolve_user() {
    local uid="$1"
    # uid 4294967295 = 0xFFFFFFFF = unset/unknown in auditd
    if [[ "$uid" == "4294967295" || "$uid" == "-1" ]]; then
        echo "unset"
        return
    fi
    getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "uid:$uid"
}

# ---------------------------------------------------------------------------
# Helper: resolve syscall number to name
# ---------------------------------------------------------------------------
resolve_syscall() {
    local num="$1"
    # ausyscall returns "syscall_name" from the number
    ausyscall "$num" 2>/dev/null || echo "syscall:$num"
}

# ---------------------------------------------------------------------------
# Helper: classify the event – returns a risk context string
# ---------------------------------------------------------------------------
classify_event() {
    local auid="$1"
    local uid="$2"
    local euid="$3"
    local exe="$4"
    local tty="$5"
    local success="$6"

    local notes=()

    # Privilege context
    if [[ "$euid" == "0" && "$auid" != "0" && "$auid" != "4294967295" ]]; then
        notes+=("ELEVATED: euid=root but auid=$auid (privilege escalation path)")
    elif [[ "$euid" == "0" ]]; then
        notes+=("PRIVILEGE: running as root")
    fi

    # Identity traceability
    if [[ "$auid" == "4294967295" || "$auid" == "unset" ]]; then
        notes+=("UNTRACED: auid is unset — cannot attribute to a login session")
    fi

    # TTY / interactive context
    if [[ "$tty" == "(none)" || "$tty" == "?" ]]; then
        notes+=("NON-INTERACTIVE: no terminal — possible cron/service/script execution")
    fi

    # Executable location
    case "$exe" in
        /usr/bin/*|/bin/*|/usr/sbin/*|/sbin/*) ;;  # standard paths — unremarkable
        /tmp/*|/dev/shm/*|/run/user/*)
            notes+=("SUSPICIOUS PATH: executable launched from $exe") ;;
        *)
            notes+=("UNUSUAL PATH: executable at $exe — verify this is expected") ;;
    esac

    # Outcome
    if [[ "$success" != "yes" ]]; then
        notes+=("FAILED: operation did not succeed — may indicate blocked attempt")
    fi

    if [[ ${#notes[@]} -eq 0 ]]; then
        notes+=("No automated risk indicators — context review still required")
    fi

    printf '%s\n' "${notes[@]}"
}

# ---------------------------------------------------------------------------
# Core: parse one ausearch event block (passed as a temp file path)
# ---------------------------------------------------------------------------
parse_event_block() {
    local block_file="$1"
    local event_num="$2"

    # Extract the SYSCALL line — that is the authoritative record
    local syscall_line
    syscall_line=$(grep '^type=SYSCALL ' "$block_file") || true
    [[ -z "$syscall_line" ]] && return  # skip non-SYSCALL events (e.g. CONFIG_CHANGE)

    # ── Extract raw numeric fields from the SYSCALL line ──────────────────
    local epoch serial syscall_num success exit_code \
          ppid pid auid uid gid euid tty ses comm exe

    # msg=audit(EPOCH.ms:SERIAL)
    epoch=$(echo "$syscall_line"    | grep -oP 'audit\(\K[0-9]+')
    serial=$(echo "$syscall_line"   | grep -oP ':\K[0-9]+(?=\))')
    syscall_num=$(echo "$syscall_line" | grep -oP 'syscall=\K[0-9]+')
    success=$(echo "$syscall_line"  | grep -oP 'success=\K\S+')
    exit_code=$(echo "$syscall_line"| grep -oP ' exit=\K-?[0-9]+')
    ppid=$(echo "$syscall_line"     | grep -oP 'ppid=\K[0-9]+')
    pid=$(echo "$syscall_line"      | grep -oP ' pid=\K[0-9]+')
    auid=$(echo "$syscall_line"     | grep -oP 'auid=\K[0-9]+')
    uid=$(echo "$syscall_line"      | grep -oP ' uid=\K[0-9]+')
    gid=$(echo "$syscall_line"      | grep -oP ' gid=\K[0-9]+')
    euid=$(echo "$syscall_line"     | grep -oP 'euid=\K[0-9]+')
    tty=$(echo "$syscall_line"      | grep -oP 'tty=\K\S+')
    ses=$(echo "$syscall_line"      | grep -oP 'ses=\K[0-9]+')
    comm=$(echo "$syscall_line"     | grep -oP 'comm=\K"[^"]+"' | tr -d '"')
    exe=$(echo "$syscall_line"      | grep -oP 'exe=\K"[^"]+"'  | tr -d '"')

    # ── Resolve numeric values to human-readable ──────────────────────────
    local timestamp auid_name uid_name syscall_name
    timestamp=$(date -d "@${epoch}" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null \
                || date -r "${epoch}" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null \
                || echo "epoch:${epoch}")
    auid_name=$(resolve_user "$auid")
    uid_name=$(resolve_user "$uid")
    euid_name=$(resolve_user "$euid")
    syscall_name=$(resolve_syscall "$syscall_num")

    # ── Extract affected file path from PATH records ───────────────────────
    # For rename operations: item with nametype=CREATE is the final destination.
    # For open/write operations: item with nametype=NORMAL is the target.
    # We prefer CREATE > NORMAL > the first non-PARENT entry.
    local affected_file=""
    affected_file=$(grep '^type=PATH ' "$block_file" \
        | grep 'nametype=CREATE' \
        | grep -oP 'name=\K"[^"]+"' | head -1 | tr -d '"') || true

    if [[ -z "$affected_file" ]]; then
        affected_file=$(grep '^type=PATH ' "$block_file" \
            | grep 'nametype=NORMAL' \
            | grep -oP 'name=\K"[^"]+"' | head -1 | tr -d '"') || true
    fi

    if [[ -z "$affected_file" ]]; then
        affected_file=$(grep '^type=PATH ' "$block_file" \
            | grep -v 'nametype=PARENT' \
            | grep -oP 'name=\K"[^"]+"' | head -1 | tr -d '"') || true
    fi

    [[ -z "$affected_file" ]] && affected_file="(path not recorded)"

    # ── Extract working directory ─────────────────────────────────────────
    local cwd=""
    cwd=$(grep '^type=CWD ' "$block_file" | grep -oP 'cwd=\K"[^"]+"' | tr -d '"') || true

    # ── Extract decoded process title ─────────────────────────────────────
    local proctitle_hex proctitle_decoded=""
    proctitle_hex=$(grep '^type=PROCTITLE ' "$block_file" \
        | grep -oP 'proctitle=\K\S+') || true
    if [[ -n "$proctitle_hex" ]]; then
        # auditd hex-encodes proctitle; decode null bytes as spaces
        proctitle_decoded=$(printf '%s' "$proctitle_hex" \
            | xxd -r -p 2>/dev/null \
            | tr '\0' ' ' \
            | sed 's/[^[:print:] ]//g' \
            | xargs) || proctitle_decoded="$comm"
    fi
    [[ -z "$proctitle_decoded" ]] && proctitle_decoded="$comm"

    # ── Classify event ────────────────────────────────────────────────────
    local risk_notes
    risk_notes=$(classify_event "$auid" "$uid" "$euid" "$exe" "$tty" "$success")

    # =========================================================================
    # OUTPUT LAYER 1: TELEMETRY
    # Raw facts extracted from the audit record. No interpretation.
    # =========================================================================
    echo ""
    echo "$SEPARATOR"
    printf '  [TELEMETRY] Raw audit event #%d\n' "$event_num"
    echo "$SEPARATOR"
    printf '  %-22s %s\n'  "Audit key:"        "$AUDIT_KEY"
    printf '  %-22s %s\n'  "Audit serial:"     "$serial"
    printf '  %-22s %s\n'  "Epoch timestamp:"  "$epoch"
    printf '  %-22s %s\n'  "Syscall number:"   "$syscall_num"
    printf '  %-22s %s\n'  "Exit code:"        "$exit_code"
    printf '  %-22s %s\n'  "auid (numeric):"   "$auid"
    printf '  %-22s %s\n'  "uid  (numeric):"   "$uid"
    printf '  %-22s %s\n'  "euid (numeric):"   "$euid"
    printf '  %-22s %s\n'  "gid  (numeric):"   "$gid"
    printf '  %-22s %s\n'  "ppid / pid:"       "$ppid / $pid"
    printf '  %-22s %s\n'  "tty:"              "$tty"
    printf '  %-22s %s\n'  "session:"          "$ses"
    printf '  %-22s %s\n'  "comm:"             "$comm"
    printf '  %-22s %s\n'  "exe:"              "$exe"
    printf '  %-22s %s\n'  "cwd:"              "${cwd:-(not recorded)}"
    printf '  %-22s %s\n'  "proctitle:"        "$proctitle_decoded"

    if [[ "$SHOW_RAW" -eq 1 ]]; then
        echo ""
        echo "  [RAW AUDIT BLOCK]"
        sed 's/^/    /' "$block_file"
    fi

    # =========================================================================
    # OUTPUT LAYER 2: DETECTION
    # Declares the rule that fired and maps the event to it.
    # =========================================================================
    echo ""
    printf '  [DETECTION] Rule: sensitive-config-modification\n'
    echo "  ─────────────────────────────────────────────────────────────────────"
    printf '  %-22s %s\n'  "Rule matched:"     "soc_sensitive_config (auditd key)"
    printf '  %-22s %s\n'  "Monitored file:"   "$MONITORED_FILE"
    printf '  %-22s %s\n'  "Affected path:"    "$affected_file"
    printf '  %-22s %s\n'  "Syscall:"          "${syscall_name} (${syscall_num})"
    printf '  %-22s %s\n'  "Action:"           "$(echo "$syscall_name" | tr '[:lower:]' '[:upper:]')"
    printf '  %-22s %s\n'  "Result:"           "$success"
    printf '  %-22s %s\n'  "Timestamp:"        "$timestamp"
    printf '  %-22s %s\n'  "auid:"             "${auid_name} (${auid})"
    printf '  %-22s %s\n'  "uid:"              "${uid_name} (${uid})"
    printf '  %-22s %s\n'  "euid:"             "${euid_name} (${euid})"
    printf '  %-22s %s\n'  "executable:"       "$exe"
    printf '  %-22s %s\n'  "command:"          "$proctitle_decoded"

    # =========================================================================
    # OUTPUT LAYER 3: ALERT
    # Analyst-facing summary. Includes context notes and next-step guidance.
    # =========================================================================
    echo ""
    printf '  [ALERT] Event requires analyst review\n'
    echo "  ─────────────────────────────────────────────────────────────────────"
    printf '  %-22s %s\n'  "Summary:" \
        "${auid_name} ran ${exe##*/} at ${timestamp} and ${syscall_name}d ${affected_file}"
    echo ""
    printf '  Automated context notes:\n'
    while IFS= read -r note; do
        printf '    • %s\n' "$note"
    done <<< "$risk_notes"
    echo ""
    printf '  %-22s\n' "Analyst next steps:"
    printf '    1. Was this change authorized? Check change-management records.\n'
    printf '    2. Is %s the expected editor for this file?\n' "${exe##*/}"
    printf '    3. Was %s logged in interactively (tty=%s, ses=%s)?\n' \
        "$auid_name" "$tty" "$ses"
    printf '    4. What changed? Diff the file against last known-good backup.\n'
    printf '    5. Were there preceding suspicious events in session %s?\n' "$ses"
    printf '    6. Confirm no other processes touched the file in this window.\n'
    echo ""
    printf '  NOTE: This detection fires on ALL writes to the monitored file.\n'
    printf '        A match is NOT a confirmed incident. Analyst context decides.\n'
}

# ---------------------------------------------------------------------------
# Global temp paths (declared at script scope so the EXIT trap can reach them)
# ---------------------------------------------------------------------------
_TMPFILE=""
_BLOCK_DIR=""
_cleanup() { rm -f "$_TMPFILE"; rm -rf "$_BLOCK_DIR"; }
trap '_cleanup' EXIT

# ---------------------------------------------------------------------------
# Main: run ausearch, split into per-event blocks, process each
# ---------------------------------------------------------------------------
main() {
    local ausearch_args=(-k "$AUDIT_KEY" --input-logs)
    [[ -n "$SINCE_TIME" ]] && ausearch_args+=(--start "$SINCE_TIME")

    # Write ausearch output to a temp file so we can process it reliably
    _TMPFILE=$(mktemp /tmp/soc_detection.XXXXXXXX)

    # ausearch exits 1 when no results; we handle that explicitly
    if ! ausearch "${ausearch_args[@]}" > "$_TMPFILE" 2>&1; then
        # Check if it was genuinely no results vs a real error
        if grep -q 'no matches' "$_TMPFILE" 2>/dev/null \
            || [[ ! -s "$_TMPFILE" ]]; then
            echo "[INFO] No events found for key '$AUDIT_KEY'."
            echo "       Either no writes have occurred, or the log has been rotated."
            exit 1
        fi
        # Otherwise pass through — ausearch returns stderr notes we want to keep
    fi

    # Filter out only the file-modification SYSCALL events.
    # We exclude pure CONFIG_CHANGE blocks (rule add/remove events) which also
    # carry the key tag — those are auditd housekeeping, not file write events.
    # Strategy: split on '----' separators, keep blocks that have type=SYSCALL
    # AND a PATH record referencing the monitored file (not just auditctl sendto).

    # Split the ausearch output into per-event block files
    _BLOCK_DIR=$(mktemp -d /tmp/soc_blocks.XXXXXXXX)

    awk -v dir="$_BLOCK_DIR" '
        /^----/ {
            if (NR > 1 && block != "") {
                n++
                file = dir "/block_" n ".txt"
                printf "%s", block > file
                close(file)
            }
            block = ""
            next
        }
        { block = block $0 "\n" }
        END {
            if (block != "") {
                n++
                file = dir "/block_" n ".txt"
                printf "%s", block > file
                close(file)
            }
        }
    ' "$_TMPFILE"

    local event_num=0
    local file_events=0

    # Print header
    echo ""
    echo "$SEPARATOR"
    printf '  SOC DETECTION ENGINE  v%s\n' "$SCRIPT_VERSION"
    printf '  Rule:     sensitive-config-modification\n'
    printf '  Key:      %s\n' "$AUDIT_KEY"
    printf '  File:     %s\n' "$MONITORED_FILE"
    printf '  Run time: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "$SEPARATOR"

    for block_file in "$_BLOCK_DIR"/block_*.txt; do
        [[ -f "$block_file" ]] || continue

        # Skip blocks that are only CONFIG_CHANGE (rule management), not file writes.
        # A file-write block will have a PATH record with the monitored file or
        # a path within the monitored directory (not just PARENT entries).
        if ! grep -q '^type=SYSCALL ' "$block_file"; then
            continue
        fi

        # The auditctl CONFIG_CHANGE blocks have comm="auditctl" — skip them.
        local comm_val
        comm_val=$(grep '^type=SYSCALL ' "$block_file" | grep -oP 'comm=\K"[^"]+"' | tr -d '"')
        if [[ "$comm_val" == "auditctl" ]]; then
            continue
        fi

        event_num=$(( event_num + 1 ))
        file_events=$(( file_events + 1 ))
        parse_event_block "$block_file" "$event_num"
    done

    echo ""
    echo "$SEPARATOR"
    if [[ "$file_events" -eq 0 ]]; then
        printf '  RESULT: No file-modification events found for key "%s".\n' "$AUDIT_KEY"
        echo "  CONFIG_CHANGE (rule management) events were present but excluded."
        echo "$SEPARATOR"
        exit 1
    else
        printf '  RESULT: %d file-modification event(s) found and processed.\n' "$file_events"
        printf '  All events require analyst review before declaring an incident.\n'
        echo "$SEPARATOR"
        echo ""
    fi
}

main "$@"
