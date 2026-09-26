#!/usr/bin/env bash
#
# Test suite for the Day 1 hardening utility.
#
# Runs on plain bash with no dependencies, which matters because that is exactly
# what the nightly verification command can rely on being present.
#
# The whole suite works against a throwaway sandbox via ROOT_PREFIX, so it never
# touches the host's /etc. Checks that depend on real POSIX permission bits
# (chmod on /etc/shadow) are exercised for their decision logic only, because
# Git Bash on Windows emulates rather than enforces modes. Those cases are
# marked HOST_POSIX below instead of being silently reported as passing.

set -o nounset
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"
# shellcheck source=lib/checks.sh
. "${ROOT}/lib/checks.sh"

# Load the real config, the same way audit.sh and harden.sh do. Running the
# checks against the shipped defaults rather than an empty environment is the
# point of the suite.
load_config

TESTS=0
ASSERTIONS=0
ASSERTION_FAILURES=0
TESTS_FAILED=0
declare -a FAILURES=()

CURRENT_TEST=''
CURRENT_FAILED=0
SKIPPED_NOTE=''

# ------------------------------------------------------------------ framework

# One line per test, one verdict. A test with four assertions previously printed
# "label" + "ok" and then three bare "ok" lines, which made a passing run look
# broken in captured output.
flush_test() {
    [ -z "$CURRENT_TEST" ] && return 0
    if [ "$CURRENT_FAILED" -eq 0 ]; then
        printf '%sok%s\n' "$C_GREEN" "$C_RESET"
    else
        printf '%sFAIL%s\n' "$C_RED" "$C_RESET"
    fi
    CURRENT_TEST=''
    return 0
}

it() {
    flush_test
    TESTS=$((TESTS + 1))
    CURRENT_TEST="$1"
    CURRENT_FAILED=0
    printf '  %-64s' "$1"
}

ok() {
    ASSERTIONS=$((ASSERTIONS + 1))
}

no() {
    ASSERTIONS=$((ASSERTIONS + 1))
    ASSERTION_FAILURES=$((ASSERTION_FAILURES + 1))
    CURRENT_FAILED=1
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILURES+=("${CURRENT_TEST}: $1")
}

assert_eq() {
    local expected="$1" actual="$2" what="$3"
    if [ "$expected" = "$actual" ]; then ok; else no "$what: expected '$expected', got '$actual'"; fi
}

assert_ne() {
    local unexpected="$1" actual="$2" what="$3"
    if [ "$unexpected" != "$actual" ]; then ok; else no "$what: expected anything but '$unexpected'"; fi
}

assert_file_contains() {
    local file="$1" needle="$2" what="$3"
    if [ -f "$file" ] && grep -qF -- "$needle" "$file"; then
        ok
    else
        no "$what: '$needle' not found in $file"
    fi
}

assert_file_absent() {
    local file="$1" what="$2"
    if [ -e "$file" ]; then no "$what: $file should not exist"; else ok; fi
}

# Assert a file exists but does NOT contain a literal string. Distinct from
# assert_file_absent, which checks the path itself.
assert_file_lacks() {
    local file="$1" needle="$2" what="$3"
    if [ ! -e "$file" ]; then
        no "$what: $file does not exist"
    elif grep -qF -- "$needle" "$file" 2>/dev/null; then
        no "$what: '$needle' should have been removed from $file"
    else
        ok
    fi
}

# Count occurrences of a literal string in a file.
count_in_file() {
    local file="$1" needle="$2"
    [ -f "$file" ] || { printf '0'; return; }
    grep -cF -- "$needle" "$file" 2>/dev/null || printf '0'
}

# Status of the last recorded result for a given check id.
status_of() {
    local want="$1" entry status id
    for entry in "${RESULTS[@]}"; do
        IFS='|' read -r status id _ <<<"$entry"
        [ "$id" = "$want" ] && { printf '%s' "$status"; return; }
    done
    printf 'NONE'
}

# --------------------------------------------------------------------- sandbox

new_sandbox() {
    SANDBOX="$(mktemp -d 2>/dev/null || mktemp -d -t hardening)"
    export ROOT_PREFIX="$SANDBOX"

    # Essential. The path variables are derived from ROOT_PREFIX by init_paths,
    # which ran once at source time. Without re-deriving them here, ETC_DIR and
    # friends still point at the real /etc and the suite writes to the host.
    init_paths

    mkdir -p "${ROOT_PREFIX}/etc/ssh" "${ROOT_PREFIX}/etc/modprobe.d" \
             "${ROOT_PREFIX}/etc/sysctl.d" "${ROOT_PREFIX}/etc/audit/rules.d" \
             "${ROOT_PREFIX}/root/.ssh"
}

# A deliberately weak sshd_config: password auth on, root login allowed.
seed_weak_sshd() {
    cat > "$SSHD_CONFIG" <<'EOF'
# weak baseline
Port 22
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 6
X11Forwarding yes
EOF
}

seed_compliant_sshd() {
    cat > "$SSHD_CONFIG" <<'EOF'
# compliant baseline
Port 22
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
ClientAliveInterval 300
X11Forwarding no
EOF
}

# Invoked by the EXIT trap below, not called directly. ShellCheck does not always
# connect a trap handler back to its function definition.
# shellcheck disable=SC2329
cleanup_sandbox() {
    [ -n "${SANDBOX:-}" ] && [ -d "$SANDBOX" ] && rm -rf "$SANDBOX"
    unset ROOT_PREFIX
}

trap cleanup_sandbox EXIT

# ================================================================== test cases

printf '\n%sDay 1 hardening utility - test suite%s\n\n' "$C_BOLD" "$C_RESET"

# --- syntax -----------------------------------------------------------------
it 'all scripts parse'
PARSE_ERRORS=0
for f in harden.sh audit.sh lib/common.sh lib/checks.sh config/cis.conf tests/run-tests.sh; do
    if ! bash -n "${ROOT}/${f}" 2>/dev/null; then
        no "bash -n ${f} reported a syntax error"
        PARSE_ERRORS=$((PARSE_ERRORS + 1))
    fi
done
[ "$PARSE_ERRORS" -eq 0 ] && ok

# --- registry integrity ---------------------------------------------------
#
# Guards the whole toolset against the failure where a check's function name
# drifts from its id in ALL_CHECKS. Nothing in the code catches that at runtime:
# run_all_checks just dies with "command not found" and an exit code of 127.

it 'every id in ALL_CHECKS has a matching check function'
MISSING_CHECKS=''
for id in "${ALL_CHECKS[@]}"; do
    declare -F "check_${id}" >/dev/null 2>&1 || MISSING_CHECKS="${MISSING_CHECKS} ${id}"
done
assert_eq '' "$MISSING_CHECKS" 'check functions present'

it 'every id in ALL_CHECKS has a unique result id'
# A check that records under the wrong id would make status_of() ambiguous and
# would misreport in the summary, so the recorded ids are compared as a set.
reset_results
for id in "${ALL_CHECKS[@]}"; do
    if declare -F "check_${id}" >/dev/null 2>&1; then
        "check_${id}" >/dev/null 2>&1 || true
    fi
done
RECORDED_IDS="$(printf '%s\n' "${RESULTS[@]}" | cut -d'|' -f2 | sort | uniq -d | tr '\n' ' ')"
assert_eq '' "$RECORDED_IDS" 'each check records a distinct id'

it 'the remediations declared in harden.sh all exist'
# Mirrors REMEDIABLE in harden.sh. A missing function would abort the run.
REMEDIABLE_IDS=(ssh_root_login ssh_password_auth ssh_max_auth_tries
                ssh_client_alive_interval ssh_x11_forwarding unused_filesystems
                core_dumps file_permissions)
MISSING_REMEDIATIONS=''
for id in "${REMEDIABLE_IDS[@]}"; do
    declare -F "remediate_${id}" >/dev/null 2>&1 || MISSING_REMEDIATIONS="${MISSING_REMEDIATIONS} ${id}"
done
assert_eq '' "$MISSING_REMEDIATIONS" 'remediate functions present'

# --- set_sshd_directive ----------------------------------------------------
new_sandbox
seed_weak_sshd

it 'set_sshd_directive adds a missing directive'
set_sshd_directive Protocol 2 >/dev/null
assert_file_contains "$SSHD_CONFIG" 'Protocol 2' 'directive added'

it 'set_sshd_directive replaces an existing directive'
set_sshd_directive X11Forwarding no >/dev/null
assert_eq '1' "$(count_in_file "$SSHD_CONFIG" 'X11Forwarding')" 'no duplicate X11Forwarding'
assert_file_lacks "$SSHD_CONFIG" 'X11Forwarding yes' 'old value removed'

it 'set_sshd_directive is idempotent'
set_sshd_directive X11Forwarding no >/dev/null
IDEMPOTENT_RC=$?
assert_eq '0' "$IDEMPOTENT_RC" 'a no-op call returns success'
assert_eq '1' "$(count_in_file "$SSHD_CONFIG" 'X11Forwarding')" 'still exactly one'

it 'set_sshd_directive preserves unrelated directives'
assert_file_contains "$SSHD_CONFIG" 'Port 22' 'Port survives edits'

it 'ROOT_PREFIX confines writes to the sandbox'
assert_eq "$SANDBOX/etc/ssh/sshd_config" "$SSHD_CONFIG" 'sshd path is inside sandbox'

# --- dry run ---------------------------------------------------------------
it 'DRY_RUN=1 writes nothing'
BEFORE="$(cat "$SSHD_CONFIG")"
DRY_RUN=1
set_sshd_directive PermitRootLogin no >/dev/null 2>&1
write_file "${ROOT_PREFIX}/etc/modprobe.d/should-not-exist.conf" 0644 'x' >/dev/null
DRY_RUN=0
assert_eq "$BEFORE" "$(cat "$SSHD_CONFIG")" 'sshd_config untouched in dry run'
assert_file_absent "${ROOT_PREFIX}/etc/modprobe.d/should-not-exist.conf" 'no stray file in dry run'

# --- check logic -----------------------------------------------------------
new_sandbox
seed_weak_sshd

it 'check_ssh_password_auth flags a weak config'
reset_results
check_ssh_password_auth
assert_eq 'FAIL' "$(status_of ssh_password_auth)" 'weak config must fail'

it 'check_ssh_root_login flags a weak config'
reset_results
check_ssh_root_login
assert_eq 'FAIL' "$(status_of ssh_root_login)" 'PermitRootLogin yes must fail'

it 'check_ssh_max_auth_tries flags a weak config'
reset_results
check_ssh_max_auth_tries
assert_eq 'FAIL' "$(status_of ssh_max_auth_tries)" 'MaxAuthTries 6 must fail'

it 'check_ssh_max_auth_tries accepts a stricter value'
reset_results
sed -i 's/^MaxAuthTries 6/MaxAuthTries 2/' "$SSHD_CONFIG"
check_ssh_max_auth_tries
assert_eq 'PASS' "$(status_of ssh_max_auth_tries)" 'MaxAuthTries 2 must pass'

new_sandbox
seed_compliant_sshd

it 'check_ssh_password_auth passes a compliant config'
reset_results
check_ssh_password_auth
assert_eq 'PASS' "$(status_of ssh_password_auth)" 'PasswordAuthentication no must pass'

it 'check_ssh_root_login passes a compliant config'
reset_results
check_ssh_root_login
assert_eq 'PASS' "$(status_of ssh_root_login)" 'PermitRootLogin no must pass'

it 'unset directive is treated as non-compliant'
new_sandbox
printf 'Port 22\n' > "$SSHD_CONFIG"
reset_results
check_ssh_password_auth
assert_eq 'FAIL' "$(status_of ssh_password_auth)" 'unset must not silently pass'

# --- remediation -----------------------------------------------------------
new_sandbox
seed_weak_sshd
DRY_RUN=0

it 'remediate_ssh_password_auth fixes a weak config'
reset_results
remediate_ssh_password_auth
assert_eq 'FIXED' "$(status_of ssh_password_auth)" 'reported as fixed'
assert_file_contains "$SSHD_CONFIG" 'PasswordAuthentication no' 'value written'

it 'remediate is idempotent'
reset_results
remediate_ssh_password_auth
assert_eq 'PASS' "$(status_of ssh_password_auth)" 'second pass reports already-ok'
assert_eq '1' "$(count_in_file "$SSHD_CONFIG" 'PasswordAuthentication')" 'still one directive'

it 'remediate_unused_filesystems writes a modprobe drop-in'
reset_results
remediate_unused_filesystems
assert_file_contains "$MODPROBE_DISABLE" 'install cramfs /bin/true' 'cramfs disabled'

it 'remediate_core_dumps writes sysctl hardening'
reset_results
remediate_core_dumps
assert_file_contains "$SYSCTL_HARDENING" 'fs.suid_dumpable = 0' 'suid_dumpable set'

# --- check reflects remediation -------------------------------------------
new_sandbox
seed_weak_sshd
DRY_RUN=0
remediate_ssh_password_auth >/dev/null
remediate_ssh_root_login >/dev/null
remediate_ssh_max_auth_tries >/dev/null
remediate_ssh_client_alive_interval >/dev/null
remediate_ssh_x11_forwarding >/dev/null

it 'checks pass after remediation'
reset_results
check_ssh_password_auth
check_ssh_root_login
check_ssh_max_auth_tries
check_ssh_client_alive_interval
check_ssh_x11_forwarding
assert_eq 'PASS' "$(status_of ssh_password_auth)" 'password auth now compliant'
assert_eq 'PASS' "$(status_of ssh_root_login)" 'root login now compliant'
assert_eq 'PASS' "$(status_of ssh_x11_forwarding)" 'x11 now compliant'

# --- audit.sh and harden.sh end to end ------------------------------------
new_sandbox
seed_weak_sshd
DRY_RUN=0

it 'audit.sh exits 1 when findings exist'
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/audit.sh" --no-color >/dev/null 2>&1
assert_eq '1' "$?" 'weak sandbox produces findings'

it 'audit.sh --only rejects an unknown check id'
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/audit.sh" --only no_such_check --no-color >/dev/null 2>&1
assert_eq '2' "$?" 'usage error exit code'

it 'audit.sh --only runs a single check'
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/audit.sh" --only ssh_root_login --no-color >/dev/null 2>&1
assert_ne '2' "$?" 'valid id is accepted'

it 'harden.sh without --apply changes nothing'
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/harden.sh" --no-color >/dev/null 2>&1
assert_file_contains "$SSHD_CONFIG" 'PasswordAuthentication yes' 'preview left the config alone'

it 'harden.sh refuses to disable password auth without any key'
mkdir -p "${SANDBOX}/root/.ssh"
printf 'ssh-ed25519 AAAAtest test\n' > "${SANDBOX}/root/.ssh/authorized_keys"
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/harden.sh" --no-color >/dev/null 2>&1
assert_ne '1' "$?" 'lockout guardrail did not block a run that has a key'

# The full --apply path needs root and a real-ish layout, so it is exercised
# with --force in the sandbox. This is the one case that would be unsafe to run
# unforced, which is why --force exists.
it 'harden.sh --apply hardens the sandbox sshd_config'
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/harden.sh" --apply --force --no-color >/dev/null 2>&1
assert_eq '0' "$?" 'apply run succeeded'
assert_file_contains "$SSHD_CONFIG" 'PasswordAuthentication no' 'password auth disabled'
assert_file_contains "$SSHD_CONFIG" 'PermitRootLogin no' 'root login disabled'
assert_eq '1' "$(count_in_file "$SSHD_CONFIG" 'PasswordAuthentication')" 'no duplicate directives'

it 'audit.sh exits 0 once the sandbox is compliant'
new_sandbox
seed_weak_sshd
mkdir -p "${SANDBOX}/root/.ssh"
printf 'ssh-ed25519 AAAAtest test\n' > "${SANDBOX}/root/.ssh/authorized_keys"
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/harden.sh" --apply --force --no-color >/dev/null 2>&1
ROOT_PREFIX="$SANDBOX" bash "${ROOT}/audit.sh" --only ssh_password_auth --no-color >/dev/null 2>&1
assert_eq '0' "$?" 'compliant config passes audit'

# HOST_POSIX: chmod semantics are emulated on Windows, so permission bits are
# not asserted here. Reported rather than hidden.
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
case "$UNAME_S" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT*)
        IS_WINDOWS_SHELL=1
        ;;
    *)
        IS_WINDOWS_SHELL=0
        ;;
esac

if [ "$IS_WINDOWS_SHELL" -eq 0 ]; then
    it 'check_file_permissions flags a world-readable shadow file (POSIX host)'
    new_sandbox
    mkdir -p "$ETC_DIR"
    printf 'root:x:0:0::/root:/bin/bash\n' > "${ETC_DIR}/passwd"
    printf 'root:!:19000:0:99999:7:::\n' > "${ETC_DIR}/shadow"
    chmod 0644 "${ETC_DIR}/shadow"
    # Read by lib/checks.sh rather than by this script, hence the disable.
    # shellcheck disable=SC2034
    DRY_RUN=0
    reset_results
    check_file_permissions
    assert_eq 'FAIL' "$(status_of perm_shadow)" 'world-readable shadow must fail'

    it 'remediate_file_permissions tightens a world-readable shadow file'
    remediate_file_permissions >/dev/null
    assert_eq '400' "$(stat -c '%a' "${ETC_DIR}/shadow" 2>/dev/null || echo '?')" 'shadow now owner-only'
else
    SKIPPED_NOTE='2 file_permissions chmod assertions (POSIX modes emulated on '"${UNAME_S}"')'
    flush_test
    printf '  %sskip%s  %s\n' "$C_YELLOW" "$C_RESET" "$SKIPPED_NOTE"
fi

it 'the sandbox never touched the real /etc'
# The bug this guards: path variables frozen at source time, so a fixture write
# landed on the host's /etc/passwd instead of the sandbox.
case "$ETC_DIR" in
    "$SANDBOX"/*|/tmp/*|"$TEMP"/*|"$TMP"/*|"${TMPDIR:-/tmp}"/*)
        ok
        ;;
    *)
        no "ETC_DIR escaped the sandbox: $ETC_DIR"
        ;;
esac

# ==================================================================== summary

flush_test

printf '\n%sResults%s\n' "$C_BOLD" "$C_RESET"
printf '  tests      : %d\n' "$TESTS"
printf '  assertions : %s%d%s passed, %s%d%s failed\n' \
    "$C_GREEN" "$((ASSERTIONS - ASSERTION_FAILURES))" "$C_RESET" \
    "$C_RED" "$ASSERTION_FAILURES" "$C_RESET"

if [ -n "$SKIPPED_NOTE" ]; then
    printf '  skipped    : %s%s%s\n' "$C_YELLOW" "$SKIPPED_NOTE" "$C_RESET"
fi

if [ "$TESTS_FAILED" -gt 0 ]; then
    printf '\n%sFailures%s\n' "$C_BOLD" "$C_RESET"
    for f in "${FAILURES[@]}"; do
        printf '  - %s\n' "$f"
    done
    printf '\n'
    exit 1
fi

printf '\n%sAll %d tests passed.%s\n\n' "$C_GREEN" "$TESTS" "$C_RESET"
exit 0
