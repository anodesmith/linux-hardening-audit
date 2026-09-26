#!/usr/bin/env bash
# shellcheck shell=bash
#
# Shared helpers for harden.sh and audit.sh.
#
# Everything that touches the system goes through this file so that a single
# DRY_RUN switch, or a ROOT_PREFIX redirect, changes the behaviour of the whole
# toolset. That is what makes the checks testable off-target: the test suite
# points ROOT_PREFIX at a throwaway directory and exercises the real code paths
# without touching the host.

# Deliberately does NOT set errexit / nounset / pipefail.
#
# Those are set by the entry points (harden.sh, audit.sh) instead. A sourced
# library that flips global shell options changes the behaviour of whatever
# sources it - which silently gave the test suite errexit semantics and aborted
# the whole run on the first non-zero return.

# ----------------------------------------------------------------- locations

# Every filesystem path is built from these. The default of "" means the real root.
ROOT_PREFIX="${ROOT_PREFIX:-}"

# Derives every path from ROOT_PREFIX.
#
# This has to be a function called at source time, not a block of assignments,
# because the paths would otherwise be frozen against whatever ROOT_PREFIX
# happened to be when this file was sourced. The test suite sets ROOT_PREFIX
# after sourcing, which silently left ETC_DIR pointing at the real /etc and
# nearly had the suite write to the host's /etc/passwd.
init_paths() {
    ETC_DIR="${ROOT_PREFIX}/etc"
    SSH_DIR="${ETC_DIR}/ssh"
    MODPROBE_DIR="${ETC_DIR}/modprobe.d"
    SYSCTL_DIR="${ETC_DIR}/sysctl.d"
    SECURITY_DIR="${ETC_DIR}/security"
    AUDIT_DIR="${ETC_DIR}/audit"

    SSHD_CONFIG="${SSH_DIR}/sshd_config"
    SYSCTL_HARDENING="${SYSCTL_DIR}/99-hardening.conf"
    MODPROBE_DISABLE="${MODPROBE_DIR}/99-disable-unused.conf"
    UFW_DEFAULTS="${ETC_DIR}/default/ufw"
}

init_paths

# ----------------------------------------------------------------- behaviour

# 1 = report what would change, change nothing. Safe default for a tool that
# rewrites SSH configuration.
DRY_RUN="${DRY_RUN:-0}"

# 1 = treat a missing tool as SKIP rather than FAIL. Used by the test suite so a
# host without ufw or auditd does not report false failures.
LENIENT="${LENIENT:-0}"

# ------------------------------------------------------------------ reporting

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_BOLD=$'\033[1m'
else
    C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_BOLD=''
fi

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FIXED_COUNT=0
declare -a RESULTS=()

log()     { printf '%s\n' "$*" >&2; }
info()    { printf '%s[info]%s %s\n'  "$C_BLUE"   "$C_RESET" "$*" >&2; }
warn()    { printf '%s[warn]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*" >&2; }
error()   { printf '%s[error]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
section() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RESET" >&2; }

# Record a result. status is one of PASS FAIL SKIP FIXED INFO.
record() {
    local status="$1" id="$2" detail="${3:-}"
    case "$status" in
        PASS)  PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL)  FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP)  SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
        FIXED) FIXED_COUNT=$((FIXED_COUNT + 1)) ;;
    esac
    RESULTS+=("${status}|${id}|${detail}")
}

print_result() {
    local status="$1" id="$2" detail="${3:-}" colour mark
    case "$status" in
        PASS)  colour="$C_GREEN";  mark='PASS ' ;;
        FAIL)  colour="$C_RED";    mark='FAIL ' ;;
        SKIP)  colour="$C_YELLOW"; mark='SKIP ' ;;
        FIXED) colour="$C_GREEN";  mark='FIXED' ;;
        *)     colour="$C_BLUE";   mark='INFO ' ;;
    esac
    printf '  %s%s%s  %-34s %s\n' "$colour" "$mark" "$C_RESET" "$id" "$detail" >&2
}

# Clear recorded results so a single check can be evaluated in isolation.
# Used by the test suite; harmless in normal operation.
reset_results() {
    PASS_COUNT=0
    FAIL_COUNT=0
    SKIP_COUNT=0
    FIXED_COUNT=0
    RESULTS=()
}

# ---------------------------------------------------------------- execution

is_dry_run() { [ "$DRY_RUN" = "1" ]; }

# Print the command that would run, or run it. Centralising this is what makes
# --dry-run trustworthy: no call site can forget to honour it.
run_cmd() {
    if is_dry_run; then
        printf '  %s[dry-run]%s would run: %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2
        return 0
    fi
    "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

# SKIP a check whose tooling is absent, unless LENIENT is off in which case the
# missing tool is itself the failure.
skip_or_fail() {
    local id="$1" tool="$2"
    if [ "$LENIENT" = "1" ]; then
        record SKIP "$id" "$tool not installed"
        print_result SKIP "$id" "$tool not installed"
    else
        record FAIL "$id" "$tool not installed"
        print_result FAIL "$id" "$tool not installed"
    fi
}

# ---------------------------------------------------------------- filesystem

# Read a file, returning 1 if it is absent. Never trips errexit.
read_file() {
    [ -f "$1" ] || return 1
    cat "$1"
}

# Replace a file's contents, creating parent directories as needed. Honours
# DRY_RUN. Prints the path on success.
write_file() {
    local path="$1" mode="${2:-0644}" content="$3"
    local dir
    dir="$(dirname "$path")"

    if is_dry_run; then
        printf '  %s[dry-run]%s would write %s\n' "$C_YELLOW" "$C_RESET" "$path" >&2
        return 0
    fi

    mkdir -p "$dir"
    printf '%s\n' "$content" > "$path"
    chmod "$mode" "$path"
    printf '%s' "$path"
}

# Set a key in an sshd_config-style file, replacing any existing directive with
# the same keyword. Returns 0 if the file already had the exact value.
set_sshd_directive() {
    local key="$1" value="$2" config="${3:-$SSHD_CONFIG}"
    local current

    current="$(read_file "$config" | grep -iE "^[[:space:]]*${key}[[:space:]]" | head -n1 | awk '{print $2}' | tr -d '\r' || true)"

    if [ "$current" = "$value" ]; then
        return 0
    fi

    if is_dry_run; then
        printf '  %s[dry-run]%s would set %s %s in %s\n' "$C_YELLOW" "$C_RESET" "$key" "$value" "$config" >&2
        return 0
    fi

    mkdir -p "$(dirname "$config")"
    if [ -f "$config" ]; then
        # Comment out every existing directive for this keyword, then append.
        local tmp
        tmp="$(mktemp)"
        grep -ivE "^[[:space:]]*${key}[[:space:]]" "$config" > "$tmp" || true
        mv "$tmp" "$config"
    fi
    printf '%s %s\n' "$key" "$value" >> "$config"
    chmod 0600 "$config"
    return 1
}

# Current value of an sshd_config directive, empty if unset.
sshd_value() {
    local key="$1" config="${2:-$SSHD_CONFIG}"
    read_file "$config" | grep -iE "^[[:space:]]*${key}[[:space:]]" | head -n1 | awk '{print $2}' | tr -d '\r' || true
}

# ------------------------------------------------------------------ privilege

require_root() {
    if [ "$(id -u)" -ne 0 ] && [ "$LENIENT" != "1" ]; then
        error "This tool changes system configuration and must run as root."
        error "Re-run with sudo, or pass --dry-run to preview without changes."
        exit 1
    fi
}

# --------------------------------------------------------------------- config

# Load config/cis.conf if present, without clobbering environment overrides.
load_config() {
    local conf="${CIS_CONFIG:-}"
    if [ -z "$conf" ]; then
        conf="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config/cis.conf"
    fi
    if [ -f "$conf" ]; then
        # shellcheck disable=SC1090
        . "$conf"
    fi
}
