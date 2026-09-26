#!/usr/bin/env bash
#
# audit.sh - report CIS benchmark compliance without changing anything.
#
# Read-only by construction: this script never calls write_file with DRY_RUN off.
# Exit status is 0 when no findings remain, 1 when there are findings, so it can
# gate a CI job or feed a monitoring check.

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
Usage: audit.sh [options]

Reports CIS-aligned hardening compliance. Makes no changes.

Options:
  --config FILE   Load settings from FILE instead of config/cis.conf
  --only ID       Run a single check, repeatable
  --lenient       Report a missing tool as SKIP rather than FAIL
  --no-color      Disable ANSI colour
  -h, --help      This text

Exit status:
  0  no findings
  1  at least one finding
  2  usage error

Environment:
  ROOT_PREFIX   Redirect all /etc reads into a directory tree, for testing.
EOF
}

ONLY=()
while [ $# -gt 0 ]; do
    case "$1" in
        --config) CIS_CONFIG="${2:?--config needs a value}"; shift 2 ;;
        --only)   ONLY+=("${2:?--only needs a value}"); shift 2 ;;
        --lenient) LENIENT=1; shift ;;
        --no-color) export NO_COLOR=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown option: $1"; usage; exit 2 ;;
    esac
done

[ "${NO_COLOR:-}" = "1" ] || true
load_config

section 'CIS hardening audit (read-only)'

if [ "${#ONLY[@]}" -gt 0 ]; then
    for id in "${ONLY[@]}"; do
        if ! declare -F "check_${id}" >/dev/null; then
            error "Unknown check id: $id"
            error "Known ids: ${ALL_CHECKS[*]}"
            exit 2
        fi
        "check_${id}"
    done
else
    run_all_checks
fi

# --------------------------------------------------------------- report
total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
compliance='n/a'
if [ "$total" -gt 0 ]; then
    compliance="$(awk -v p="$PASS_COUNT" -v t="$total" 'BEGIN { printf "%.1f", (p / t) * 100 }')"
fi

printf '\n' >&2
for entry in "${RESULTS[@]}"; do
    IFS='|' read -r status id detail <<<"$entry"
    print_result "$status" "$id" "$detail"
done

section 'Summary'
printf '  checks     : %d\n' "$total"                    >&2
printf '  passed     : %s%d%s\n'  "$C_GREEN"  "$PASS_COUNT"  "$C_RESET" >&2
printf '  findings   : %s%d%s\n'  "$C_RED"    "$FAIL_COUNT"  "$C_RESET" >&2
printf '  skipped    : %s%d%s\n'  "$C_YELLOW" "$SKIP_COUNT" "$C_RESET" >&2
printf '  compliance : %s%%\n'    "$compliance"          >&2
printf '\n' >&2

[ "$FAIL_COUNT" -eq 0 ] || exit 1
exit 0
