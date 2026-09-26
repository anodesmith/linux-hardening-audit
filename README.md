# Day 1 - Linux Hardening & Audit Script

> Day 1 of 14 in the **Zero to Production Infrastructure & Security** series.

An automated Linux hardening utility driven by CIS Benchmark guidelines, paired
with a read-only auditor that reports compliance without touching the host.

| | |
|---|---|
| **Day** | 1 of 14 |
| **Status** | Complete - shellcheck clean, 30 tests, 40 assertions, 0 failures |
| **Verification** | `bash -n ... && shellcheck -x ... && bash tests/run-tests.sh` |
| **Tags** | `bash` `security` `cis-benchmark` `linux` `hardening` |

## Focus

- Disable unused filesystem types
- Enforce SSH key-only authentication
- Normalise file permission baselines
- Configure UFW and iptables rules

## Design decision that shaped everything else

**`harden.sh` does nothing unless you pass `--apply`.**

A tool that rewrites `sshd_config` and `chmod`s `/etc/shadow` has no business
mutating a host on the strength of being invoked. Preview is the default;
change is opt-in. The test suite leans on this: it drives the real code paths
through `--apply --force` against a sandbox, so the tests exercise production
logic rather than a parallel mock implementation.

The other structural choice is that **every** filesystem write goes through two
functions in `lib/common.sh`:

- `run_cmd` - echoes instead of executing when `DRY_RUN=1`
- `write_file` - same, and creates parent directories

No call site can forget to honour dry-run mode, because no call site performs
the write itself. That is what makes the no-op guarantee auditable rather than
aspirational.

## Usage

```bash
# Report compliance. Read-only, safe on a production host.
./audit.sh

# See what hardening would change.
./harden.sh

# Actually do it. Requires root.
sudo ./harden.sh --apply

# One check at a time.
./audit.sh --only ssh_password_auth
sudo ./harden.sh --apply --only ssh_root_login

# Override a setting for a single run.
CIS_SSH_MAX_AUTH_TRIES=2 sudo ./harden.sh --apply
```

`audit.sh` exits 0 when clean and 1 when there are findings, so it can gate a
CI job or feed a monitoring check directly.

## Safety guardrails

These are the failure modes that lock people out of production, and each one has
a specific defence:

| Risk | Defence |
|---|---|
| Locking yourself out over SSH | Refuses to set `PasswordAuthentication no` unless a non-empty `authorized_keys` is found. Override with `--force`. |
| Broken config surviving reboot | Runs `sshd -t -f <the file it edited>` and refuses to reload on failure. |
| Accidental host mutation | `--apply` is required. Everything else is a preview. |
| Unloadable filesystem module | Disabling unused filesystems is reported even when `CIS_DISABLE_UNUSED_FS=0`, and the drop-in carries an OOM-killer warning. |
| No way back | Timestamped `sshd_config` backup before any modification. |

## Layout

```
01-linux-hardening-audit/
  harden.sh              applies remediations (dry run unless --apply)
  audit.sh               reports compliance, read-only
  lib/
    common.sh            logging, dry-run gate, path derivation, sshd_config editing
    checks.sh            the checks and their remediations, plus ALL_CHECKS registry
  config/
    cis.conf             every tunable, overridable from the environment
  tests/
    run-tests.sh         30 tests / 40 assertions, no dependencies beyond bash
```

`ALL_CHECKS` in `lib/checks.sh` is the single ordered registry that both scripts
iterate, so `audit.sh` and `harden.sh` cannot drift out of alignment. The test
suite asserts that every id in it has a matching `check_` function - a mismatch
there is invisible at runtime and manifests only as `command not found` and exit
code 127.

## Tests

Every script is additionally checked with `shellcheck -x`, which is part of the
nightly verification command. It found a genuine defect during development: a
`for` loop over a single quoted path in `check_audit_rules_present` that could
only ever execute once (SC2066).

```bash
bash tests/run-tests.sh
```

30 tests covering 40 assertions, no framework, no dependencies. Coverage is
centred on the parts that can silently do the wrong thing:

- `set_sshd_directive` adds, replaces without duplicating, and is idempotent
- `DRY_RUN=1` writes nothing at all
- `ROOT_PREFIX` confines every write to the sandbox
- Checks flag a weak config, pass a compliant one, and treat an **unset**
  directive as non-compliant rather than silently inheriting sshd's default
- Remediations are idempotent, and checks pass afterwards
- `harden.sh` without `--apply` changes nothing
- `audit.sh` exit codes are correct, including `2` for an unknown check id
- The lockout guardrail fires when there is no key
- The sandbox never escapes to the real `/etc`

### Platform coverage

The suite runs on Git Bash on Windows, where POSIX permission bits are emulated
rather than enforced. Two `chmod` assertions are therefore **skipped and
reported as skipped** in the summary, not quietly counted as passes. Everything
else - all `/etc` text manipulation, dry-run behaviour, idempotency, guardrails,
exit codes - is fully exercised on both Windows and Linux.

## CIS coverage

Fourteen checks, each citing its guideline section from CIS Debian Linux
Benchmark v1.1.1:

| Check | Section |
|---|---|
| `ssh_root_login` | 5.2.6 / 5.2.7 |
| `ssh_password_auth` | 5.2.7 |
| `ssh_max_auth_tries` | 5.2.6 |
| `ssh_client_alive_interval` | 5.2.6 |
| `ssh_x11_forwarding` | 5.2.11 |
| `unused_filesystems` | 1.1.1.1 / 1.1.1.2 |
| `core_dumps` | 1.1.8 |
| `file_permissions` | 1.1.1.1 / 1.1.2 |
| `password_max_days` | 5.4.1 |
| `default_umask` | 5.2.2 |
| `audit_immutable` | 4.1.2 |
| `audit_rules_present` | 4.1.1 |
| `auditd_running` | 4.1.1 |
| `ufw_default_policy` | 4.4.1 |

**This is not the whole benchmark.** It is the subset that can be automated
safely and verified without a live multi-service host. Filesystem ownership
(6.1.x), audit rule content, and network-level controls are out of scope and are
listed in `docs/` as follow-ups rather than being claimed as done.

## Status

Verified on 2026-09-26. See [STATUS.md](STATUS.md) for the machine-written
record and [../_pipeline/PIPELINE_LOG.md](../_pipeline/PIPELINE_LOG.md) for the
nightly history.

## Licence

MIT. See [LICENSE](LICENSE).
