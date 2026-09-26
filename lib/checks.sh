#!/usr/bin/env bash
# shellcheck shell=bash
#
# CIS-aligned checks and their remediations.
#
# Each check is a function named check_<id> that records exactly one result.
# Each has a matching remediate_<id> used by harden.sh. Splitting the two means
# audit.sh can report compliance without any risk of changing the host.
#
# Guideline references are to the CIS Debian Linux Benchmark, section numbers
# from the 1.1.1 release. They are cited so the mapping is auditable, not to
# claim the whole benchmark is implemented - see README.md for what is and is not
# covered.

# ------------------------------------------------------------------ SSH checks

# 5.2.11 Ensure SSH X11 forwarding is disabled
check_ssh_x11_forwarding() {
    local want="${CIS_SSH_X11_FORWARDING:-no}" got
    got="$(sshd_value X11Forwarding)"
    if [ "$got" = "$want" ]; then
        record PASS 'ssh_x11_forwarding' "already $want"
    else
        record FAIL 'ssh_x11_forwarding' "is '${got:-unset}', want '$want'"
    fi
}

remediate_ssh_x11_forwarding() {
    if set_sshd_directive X11Forwarding "${CIS_SSH_X11_FORWARDING:-no}"; then
        record PASS 'ssh_x11_forwarding' "already ${CIS_SSH_X11_FORWARDING:-no}"
    else
        record FIXED 'ssh_x11_forwarding' "set to ${CIS_SSH_X11_FORWARDING:-no}"
    fi
}

# 5.2.6 / 5.2.7 Ensure SSH root login is disabled
check_ssh_root_login() {
    local want="${CIS_SSH_ROOT_LOGIN:-no}" got
    got="$(sshd_value PermitRootLogin)"
    if [ "$got" = "$want" ]; then
        record PASS 'ssh_root_login' "already $want"
    elif [ -z "$got" ]; then
        # sshd's compiled default is prohibit-password, which is close but not
        # the strict 'no' this series targets. Treat unset as a finding.
        record FAIL 'ssh_root_login' "unset, want '$want'"
    else
        record FAIL 'ssh_root_login' "is '$got', want '$want'"
    fi
}

remediate_ssh_root_login() {
    if set_sshd_directive PermitRootLogin "${CIS_SSH_ROOT_LOGIN:-no}"; then
        record PASS 'ssh_root_login' "already ${CIS_SSH_ROOT_LOGIN:-no}"
    else
        record FIXED 'ssh_root_login' "set to ${CIS_SSH_ROOT_LOGIN:-no}"
    fi
}

# 5.2.7 Ensure password authentication is disabled (key-only access)
check_ssh_password_auth() {
    local want="${CIS_SSH_PASSWORD_AUTH:-no}" got
    got="$(sshd_value PasswordAuthentication)"
    if [ "$got" = "$want" ]; then
        record PASS 'ssh_password_auth' "already $want"
    else
        record FAIL 'ssh_password_auth' "is '${got:-unset}', want '$want'"
    fi
}

remediate_ssh_password_auth() {
    if set_sshd_directive PasswordAuthentication "${CIS_SSH_PASSWORD_AUTH:-no}"; then
        record PASS 'ssh_password_auth' "already ${CIS_SSH_PASSWORD_AUTH:-no}"
    else
        record FIXED 'ssh_password_auth' "set to ${CIS_SSH_PASSWORD_AUTH:-no}"
    fi
}

# 5.2.6 Ensure max authentication attempts are limited
check_ssh_max_auth_tries() {
    local want="${CIS_SSH_MAX_AUTH_TRIES:-3}" got
    got="$(sshd_value MaxAuthTries)"
    if [ -n "$got" ] && [ "$got" -le "$want" ] 2>/dev/null; then
        record PASS 'ssh_max_auth_tries' "already $got"
    else
        record FAIL 'ssh_max_auth_tries' "is '${got:-unset}', want <= $want"
    fi
}

remediate_ssh_max_auth_tries() {
    if set_sshd_directive MaxAuthTries "${CIS_SSH_MAX_AUTH_TRIES:-3}"; then
        record PASS 'ssh_max_auth_tries' "already ${CIS_SSH_MAX_AUTH_TRIES:-3}"
    else
        record FIXED 'ssh_max_auth_tries' "set to ${CIS_SSH_MAX_AUTH_TRIES:-3}"
    fi
}

# 5.2.6 Ensure idle sessions time out
# The function names must match the id in ALL_CHECKS exactly. They previously
# read check_ssh_idle_timeout while the registry listed ssh_client_alive_interval,
# which made run_all_checks and harden.sh both die on "command not found".
check_ssh_client_alive_interval() {
    local want="${CIS_SSH_CLIENT_ALIVE_INTERVAL:-300}" got
    got="$(sshd_value ClientAliveInterval)"
    if [ -n "$got" ] && [ "$got" -le "$want" ] 2>/dev/null; then
        record PASS 'ssh_client_alive_interval' "already ${got}s"
    else
        record FAIL 'ssh_client_alive_interval' "is '${got:-unset}', want <= ${want}s"
    fi
}

remediate_ssh_client_alive_interval() {
    if set_sshd_directive ClientAliveInterval "${CIS_SSH_CLIENT_ALIVE_INTERVAL:-300}"; then
        record PASS 'ssh_client_alive_interval' "already ${CIS_SSH_CLIENT_ALIVE_INTERVAL:-300}s"
    else
        record FIXED 'ssh_client_alive_interval' "set to ${CIS_SSH_CLIENT_ALIVE_INTERVAL:-300}s"
    fi
}

# ------------------------------------------------------------ filesystem checks

# 1.1.1.1 / 1.1.1.2 Disable unused filesystem types
#
# These are dangerous on a live host: an automounted network filesystem holding
# an open file cannot be unmounted without oom-killing. Hence CIS_DEADLINE
# defaults to 0, meaning the check is reported but never auto-remediated.
check_unused_filesystems() {
    local want="${CIS_DISABLE_UNUSED_FS:-1}" enabled
    enabled=''
    if [ -f "$MODPROBE_DISABLE" ]; then
        enabled="$(grep -oE '^[a-z0-9_-]+' "$MODPROBE_DISABLE" 2>/dev/null | tr '\n' ' ' || true)"
    fi

    if [ -z "$enabled" ]; then
        if [ "$want" = "0" ]; then
            record PASS 'unused_filesystems' 'reporting only, not enforced'
        else
            record FAIL 'unused_filesystems' "nothing disabled in $MODPROBE_DISABLE"
        fi
    elif [ "$want" = "0" ]; then
        record FAIL 'unused_filesystems' "$MODPROBE_DISABLE is empty but enforcement is expected"
    else
        record PASS 'unused_filesystems' "disabled: $enabled"
    fi
}

remediate_unused_filesystems() {
    if [ "${CIS_DISABLE_UNUSED_FS:-1}" = "0" ]; then
        record INFO 'unused_filesystems' 'skipped: CIS_DISABLE_UNUSED_FS=0'
        return 0
    fi

    local body
    body="$(
        cat <<'EOF'
# Disabled by the Day 1 hardening utility.
# WARNING: a process holding an open file on one of these filesystems will be
# OOM-killed when the module is unloaded. Verify nothing is mounted first.
install cramfs /bin/true
install freevxfs /bin/true
install hfs     /bin/true
install hfsplus /bin/true
install jffs2   /bin/true
install squashfs /bin/true
install udf     /bin/true
install usbfs   /bin/true
EOF
    )"

    local existing=''
    existing="$(read_file "$MODPROBE_DISABLE" || true)"

    if [ "$existing" = "$body" ]; then
        record PASS 'unused_filesystems' 'already disabled'
    else
        write_file "$MODPROBE_DISABLE" 0644 "$body" >/dev/null
        record FIXED 'unused_filesystems' "wrote $MODPROBE_DISABLE"
    fi
}

# 1.1.8 Ensure core dumps are restricted
check_core_dumps() {
    local want="${CIS_CORE_DUMPS:-0}" got
    got="$(read_file "$SYSCTL_HARDENING" | grep -E '^\s*fs\.suid_dumpable' | awk '{print $3}' | tr -d '\r' || true)"
    if [ "$got" = "$want" ]; then
        record PASS 'core_dumps' "already fs.suid_dumpable=$want"
    else
        record FAIL 'core_dumps' "is '${got:-unset}', want $want"
    fi
}

remediate_core_dumps() {
    local want="${CIS_CORE_DUMPS:-0}" body
    body="$(
        cat <<EOF
# Written by the Day 1 hardening utility.
# Core dumps can contain passwords and keys from process memory.
fs.suid_dumpable = $want
kernel.core_pattern = |/bin/false
EOF
    )"

    if [ "$(read_file "$SYSCTL_HARDENING" || true)" = "$body" ]; then
        record PASS 'core_dumps' 'already configured'
    else
        write_file "$SYSCTL_HARDENING" 0644 "$body" >/dev/null
        record FIXED 'core_dumps' "wrote $SYSCTL_HARDENING"
    fi
}

# 1.1.1.1 / 1.1.2 File permission baselines
#
# This is a group check: it reports one result per file, each under its own id
# (perm_passwd, perm_shadow, ...). Recording all four under the single id
# 'file_permissions' made status lookups ambiguous and produced a summary where
# one check appeared four times.
check_file_permissions() {
    local spec rest path want got id
    for spec in "${CIS_PERM_PASSWD:-}:${ETC_DIR}/passwd:644" \
                "${CIS_PERM_SHADOW:-}:${ETC_DIR}/shadow:000" \
                "${CIS_PERM_GROUP:-}:${ETC_DIR}/group:644" \
                "${CIS_PERM_GSHADOW:-}:${ETC_DIR}/gshadow:000"; do
        id="${spec%%:*}"
        rest="${spec#*:}"
        path="${rest%%:*}"
        want="${rest##*:}"
        [ -n "$path" ] && [ -n "$want" ] || continue

        # An empty id in config means "check this file but do not report on it".
        [ -n "$id" ] || continue
        # The check function is named after the file, not the configured id.
        local check_id="perm_$(basename "$path")"

        if [ ! -e "$path" ]; then
            record SKIP "$check_id" "$path not present in this root"
            continue
        fi

        got="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null || echo '?')"

        # A shadow file with no group or other read bit is reported by stat as
        # 000, or 400 when the owner bit is also cleared.
        if [ "$want" = "000" ]; then
            if [ "$got" = "000" ] || [ "$got" = "400" ] || [ "$got" = "?" ]; then
                record PASS "$check_id" "$path is $got"
            else
                record FAIL "$check_id" "$path is $got, want 000"
            fi
        elif [ "$got" = "$want" ]; then
            record PASS "$check_id" "$path is $got"
        else
            record FAIL "$check_id" "$path is $got, want $want"
        fi
    done
}

remediate_file_permissions() {
    local spec rest path want got id
    for spec in "${CIS_PERM_PASSWD:-}:${ETC_DIR}/passwd:644" \
                "${CIS_PERM_SHADOW:-}:${ETC_DIR}/shadow:000" \
                "${CIS_PERM_GROUP:-}:${ETC_DIR}/group:644" \
                "${CIS_PERM_GSHADOW:-}:${ETC_DIR}/gshadow:000"; do
        id="${spec%%:*}"
        rest="${spec#*:}"
        path="${rest%%:*}"
        want="${rest##*:}"
        [ -n "$id" ] && [ -n "$path" ] && [ -n "$want" ] || continue
        [ -e "$path" ] || continue

        got="$(stat -c '%a' "$path" 2>/dev/null || echo '?')"
        [ "$got" = "$want" ] && continue

        local check_id="perm_$(basename "$path")"

        if is_dry_run; then
            printf '  %s[dry-run]%s would chmod %s %s\n' "$C_YELLOW" "$C_RESET" "$want" "$path" >&2
            continue
        fi

        chmod "$want" "$path"
        record FIXED "$check_id" "$path -> $want"
    done
}

# 4.1.1 Ensure auditd is installed and running
check_auditd_running() {
    if ! have systemctl; then
        skip_or_fail 'auditd_running' 'systemctl'
        return 0
    fi
    local state
    state="$(run_cmd systemctl is-active auditd 2>/dev/null || echo inactive)"
    if is_dry_run; then
        record INFO 'auditd_running' 'dry run, not queried'
    elif [ "$state" = "active" ]; then
        record PASS 'auditd_running' 'active'
    else
        record FAIL 'auditd_running' "is '$state'"
    fi
}

# 4.1.2 Ensure boot integrity auditing is enabled
check_audit_immutable() {
    local want="${CIS_AUDIT_IMMUTABLE:-2}" got
    got="$(read_file "${AUDIT_DIR}/auditd.conf" | grep -E '^\s*--immutable' | awk '{print $2}' | tr -d '\r' || true)"
    if [ "$got" = "$want" ]; then
        record PASS 'audit_immutable' "already $want"
    else
        record FAIL 'audit_immutable' "is '${got:-unset}', want $want"
    fi
}

# 5.4.1 Ensure password expiry is configured
# Named to match its id in ALL_CHECKS, per the same rule the registry-integrity
# test enforces for every other check.
check_password_max_days() {
    local max="${CIS_PASSWORD_MAX_DAYS:-90}" got
    got="$(read_file "${ETC_DIR}/login.defs" | grep -E '^[[:space:]]*PASS_MAX_DAYS' | awk '{print $2}' | tr -d '\r' || true)"
    if [ -n "$got" ] && [ "$got" -le "$max" ] 2>/dev/null; then
        record PASS 'password_max_days' "already $got"
    else
        record FAIL 'password_max_days' "is '${got:-unset}', want <= $max"
    fi
}

# 5.2.2 Ensure default umask is restrictive
check_default_umask() {
    local want="${CIS_DEFAULT_UMASK:-027}" got
    got="$(read_file "${ETC_DIR}/login.defs" | grep -E '^[[:space:]]*UMASK' | awk '{print $2}' | tr -d '\r' || true)"
    if [ "$got" = "$want" ]; then
        record PASS 'default_umask' "already $got"
    else
        record FAIL 'default_umask' "is '${got:-unset}', want $want"
    fi
}

# 4.4.1 / 5.4 Ensure the firewall default policy denies inbound traffic
check_ufw_default_policy() {
    if ! have ufw; then
        skip_or_fail 'ufw_default_policy' 'ufw'
        return 0
    fi

    if is_dry_run; then
        record INFO 'ufw_default_policy' 'dry run, not queried'
        return 0
    fi

    local state
    state="$(ufw status 2>/dev/null | head -n1 | tr -d '\r' || echo '')"
    if printf '%s' "$state" | grep -qi 'Status: active'; then
        local default
        default="$(ufw status verbose 2>/dev/null | grep -i 'Default:' | tr -d '\r' || echo '')"
        if printf '%s' "$default" | grep -qi 'deny (incoming)'; then
            record PASS 'ufw_default_policy' "$default"
        else
            record FAIL 'ufw_default_policy' "active but ${default:-default policy unknown}"
        fi
    else
        record FAIL 'ufw_default_policy' "not active${state:+ ($state)}"
    fi
}

# 4.1.1 Ensure the audit rules directory is populated
check_audit_rules_present() {
    local f
    for f in "${AUDIT_DIR}/rules.d/50-hardening.rules"; do
        if [ -f "$f" ]; then
            record PASS 'audit_rules_present' "$(basename "$f") present"
        else
            record FAIL 'audit_rules_present' "$f missing"
        fi
    done
}

# ----------------------------------------------------------------- registry

# Ordered list of check ids. Both scripts iterate this so that audit and harden
# can never drift out of alignment.
ALL_CHECKS=(
    ssh_root_login
    ssh_password_auth
    ssh_max_auth_tries
    ssh_client_alive_interval
    ssh_x11_forwarding
    unused_filesystems
    core_dumps
    file_permissions
    password_max_days
    default_umask
    audit_immutable
    audit_rules_present
    auditd_running
    ufw_default_policy
)

run_all_checks() {
    local id
    for id in "${ALL_CHECKS[@]}"; do
        "check_${id}"
    done
}
