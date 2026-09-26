#!/usr/bin/env bash
#
# harden.sh - apply CIS-aligned hardening remediations.
#
# Safe by default: without --apply it runs in dry-run mode and changes nothing.
# A tool that rewrites sshd_config and chmods /etc/shadow has no business
# mutating a host on the strength of being invoked.

set -o errexit
set -o nounset
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
. "${HERE}/lib/common.sh"
# shellcheck source=lib/checks.sh
. "${HERE}/lib/checks.sh"

usage() {
    cat <<'EOF'
Usage: harden.sh [--apply] [options]

Applies CIS-aligned hardening remediations.

  --apply         Actually make changes. Without this flag the run is a preview.
  --config FILE   Load settings from FILE instead of config/cis.conf
  --only ID       Remediate a single check, repeatable
  --force         Do not require root, and do not confirm before changing sshd
  --lenient       Treat a missing tool as SKIP rather than FAIL
  --no-color      Disable ANSI colour
  -h, --help      This text

Exit status:
  0  completed
  1  a remediation failed
  2  usage error

Safety notes:
  * Root is required for --apply unless --force is given.
  * A backup of sshd_config is written before it is modified.
  * PasswordAuthentication is NOT disabled unless at least one key exists in
    authorized_keys somewhere, because otherwise you lock yourself out.
EOF
}

APPLY=0
FORCE=0
ONLY=()

while [ $# -gt 0 ]; do
    case "$1" in
        --apply)   APPLY=1; shift ;;
        --force)   FORCE=1; shift ;;
        --config)  CIS_CONFIG="${2:?--config needs a value}"; shift 2 ;;
        --only)    ONLY+=("${2:?--only needs a value}"); shift 2 ;;
        --lenient) LENIENT=1; shift ;;
        --no-color) export NO_COLOR=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown option: $1"; usage; exit 2 ;;
    esac
done

[ "$APPLY" -eq 1 ] && DRY_RUN=0 || DRY_RUN=1
export DRY_RUN

load_config

if [ "$APPLY" -eq 1 ] && [ "$FORCE" -ne 1 ]; then
    require_root
fi

# ------------------------------------------------------------------ guardrail
#
# Disabling password authentication is the whole point of the SSH key-only
# requirement, and also the fastest way to lock yourself out of a remote host.
# Refuse unless we can see a key that would still let you in.
ssh_keys_present() {
    local d
    for d in "${ROOT_PREFIX}"/root/.ssh/authorized_keys \
             "${ROOT_PREFIX}"/home/*/.ssh/authorized_keys; do
        [ -f "$d" ] && [ -s "$d" ] && return 0
    done
    return 1
}

if [ "$APPLY" -eq 1 ] && [ "$FORCE" -ne 1 ]; then
    if [ "${CIS_SSH_PASSWORD_AUTH:-no}" = "no" ] && ! ssh_keys_present; then
        error 'Refusing to disable PasswordAuthentication: no non-empty authorized_keys found.'
        error 'Place a public key first, or pass --force if you are certain.'
        exit 1
    fi
fi

# ------------------------------------------------------------------- backup
if [ "$APPLY" -eq 1 ] && [ -f "$SSHD_CONFIG" ] && [ "$FORCE" -ne 1 ]; then
    backup="${SSHD_CONFIG}.$(date +%Y%m%d%H%M%S).bak"
    cp -p "$SSHD_CONFIG" "$backup"
    info "Backed up sshd_config to $backup"
fi

if is_dry_run; then
    section 'Hardening preview - no changes will be made'
    warn 'This is a dry run. Re-run with --apply to make these changes.'
else
    section 'Applying hardening remediations'
fi

printf '\n' >&2

# ------------------------------------------------------------- remediations
#
# A dedicated list rather than deriving it from ALL_CHECKS, because not every
# check has a remediation. Checks without one are reported but not changed.
REMEDIABLE=(
    ssh_root_login
    ssh_password_auth
    ssh_max_auth_tries
    ssh_client_alive_interval
    ssh_x11_forwarding
    unused_filesystems
    core_dumps
    file_permissions
)

FAILED=0

remediate_one() {
    local id="$1" fn="remediate_${1}"
    if ! declare -F "$fn" >/dev/null; then
        record INFO "$id" 'no remediation available'
        return 0
    fi
    "$fn" || FAILED=$((FAILED + 1))
}

if [ "${#ONLY[@]}" -gt 0 ]; then
    for id in "${ONLY[@]}"; do
        if ! declare -F "remediate_${id}" >/dev/null; then
            error "Unknown or non-remediable check id: $id"
            exit 2
        fi
        remediate_one "$id"
    done
else
    for id in "${REMEDIABLE[@]}"; do
        remediate_one "$id"
    done
fi

# ------------------------------------------------------------------ reload
#
# A syntax error in sshd_config locks out SSH on reboot, so validate before
# reloading. This is the single most important safety step in the script.
reload_sshd() {
    if [ "$APPLY" -ne 1 ] || is_dry_run; then
        return 0
    fi

    # A sandboxed run must not touch the host's sshd. Validating a throwaway
    # config with the real sshd is meaningless, and on Git Bash the path
    # translation produces a bogus __PROGRAMDATA__ path that fails the test for
    # reasons that have nothing to do with the config.
    if [ -n "$ROOT_PREFIX" ]; then
        record INFO 'ssh_reload' 'skipped: ROOT_PREFIX set, this is not the host'
        return 0
    fi

    if ! have sshd; then
        record INFO 'ssh_reload' 'skipped: sshd binary not found'
        return 0
    fi

    # Validate the file that was actually edited, not the system default, so a
    # non-standard -f path is still checked.
    if ! run_cmd sshd -t -f "$SSHD_CONFIG"; then
        error 'sshd config test FAILED. Not reloading. Restore from the backup.'
        FAILED=$((FAILED + 1))
        return 0
    fi

    if have systemctl && systemctl is-active --quiet ssh 2>/dev/null; then
        run_cmd systemctl reload ssh
        info 'Reloaded ssh service'
    elif have systemctl && systemctl is-active --quiet sshd 2>/dev/null; then
        run_cmd systemctl reload sshd
        info 'Reloaded sshd service'
    else
        warn 'Could not detect a running ssh service. Reload it yourself:'
        warn '  systemctl reload ssh'
    fi
}

# Reload only when SSH settings were actually part of the change set.
if [ "${#ONLY[@]}" -eq 0 ] || printf '%s\n' "${ONLY[@]}" | grep -q '^ssh_'; then
    reload_sshd
fi

# ------------------------------------------------------------------ summary
printf '\n' >&2
for entry in "${RESULTS[@]}"; do
    IFS='|' read -r status id detail <<<"$entry"
    print_result "$status" "$id" "$detail"
done

section 'Summary'
if is_dry_run; then
    printf '  mode       : %sDRY RUN%s - nothing was changed\n' "$C_YELLOW" "$C_RESET" >&2
    printf '  changes    : %d would be applied\n' "$FIXED_COUNT" >&2
    printf '\n' >&2
    printf 'Re-run with %s--apply%s to make them.\n' "$C_BOLD" "$C_RESET" >&2
    exit 0
fi

printf '  applied    : %s%d%s\n' "$C_GREEN" "$FIXED_COUNT" "$C_RESET" >&2
printf '  already ok : %s%d%s\n' "$C_GREEN" "$PASS_COUNT" "$C_RESET" >&2
printf '  failed     : %s%d%s\n' "$C_RED" "$FAILED" "$C_RESET" >&2
printf '\n' >&2

if [ "$FAILED" -gt 0 ]; then
    error "$FAILED remediation(s) failed. Review the output above."
    exit 1
fi

info 'Run ./audit.sh to confirm the result.'
exit 0
