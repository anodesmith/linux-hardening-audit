# Deliberately not implemented

An honest list of what this utility does **not** do, and why. Written because a
hardening tool that quietly skips half the benchmark is worse than one that
never claimed to cover it.

## Excluded, and the reason

### CIS 6.1.x - File permissions and ownership (auditd rules)

`auditd` rules that watch for unauthorised changes to `/etc/passwd`,
`/etc/shadow` and the SSH keys. Not implemented because the rules need to be
validated against a real auditd on the target distribution, and shipping
unvalidated audit rules produces a wall of false positives that trains people to
ignore the SIEM.

**To add:** an `audit/rules.d/50-hardening.rules` file, plus a check that parses
it with `augenrules --check`.

### Password complexity, 5.4.2

`pam_pwquality` configuration. Not implemented because the correct settings are
distribution-specific and a wrong value can lock out every account on the host,
including the one you are logged in as.

**To add:** a `config/pam-pwquality.conf` drop-in, applied only when
`--force` is passed, with the previous file backed up first.

### Kernel tunables beyond sysctl, 4.1.x

Network parameters (`net.ipv4.conf.all.accept_redirects`, `rp_filter`,
`syncookies`) and the `kernel.randomize_va_space` setting. Deliberately kept out
of the first pass: these need a reboot to take effect and a typo produces an
unbootable host, so they want a separate tool with a `--reboot-required` warning
rather than being buried in a general hardening pass.

`fs.suid_dumpable` is the one sysctl that **is** applied, because it takes effect
immediately and cannot prevent a boot.

### IPv6, 5.1.x

Assumed absent. Applying IPv6 hardening to a host with no IPv6 stack is
harmless, but disabling `ipv6` outright breaks Docker, Podman, and some load
balancer health checks, so it needs an explicit opt-in rather than a default.

### AppArmor / SELinux, 5.4

Not implemented. Enforcing a MAC policy is a project in its own right, and
turning on enforcing mode remotely over SSH is how people lose access to hosts.

### CIS 4.4 - Firewall rules beyond the default policy

This utility checks that UFW's **default incoming policy is deny** and that the
firewall is active. It does not author the allow rules, because the correct
allow list depends entirely on what runs on the host and a wrong one silently
breaks the service you deployed it to protect.

**To add:** a per-service profile in `config/` (`config/profiles/web.conf`,
`config/profiles/database.conf`) that adds explicit allow rules on top of the
deny default.

## Known limitations of what *is* implemented

### Unused filesystems are reported, not enforced, by default

`CIS_DISABLE_UNUSED_FS=1` is the default and writes the modprobe drop-in, but
unloading a filesystem module while any process holds an open file on it triggers
the OOM killer. On a live host, verify with `lsof +D` or `fuser -m` for each
mount point first. The drop-in file carries this warning inline.

### `auditd_running` needs a live service

The check queries `systemctl is-active auditd` and reports `SKIP` when
`systemctl` is unavailable. It cannot be meaningfully tested in a sandbox,
because the sandbox has no running auditd and faking one would test the fake.

### `ufw_default_policy` needs a live firewall

Same story. Reported as `SKIP` without `--lenient` when `ufw` is absent, rather
than as a silent pass.

### Group-check result ids differ from the registry id

`file_permissions` is a group check that emits one result per file, under ids
like `perm_passwd` and `perm_shadow`, rather than a single `file_permissions`
result. This is intentional - four files under one id made the summary
ambiguous - but it means the recorded ids are a superset of `ALL_CHECKS`.

## Verifying on a real target

The test suite proves the logic is correct. It does not prove the tool behaves
correctly against a live multi-service host. Before running `--apply` anywhere
that matters:

```bash
# 1. Preview. Read the output, do not skim it.
./harden.sh

# 2. Audit to see the current baseline.
./audit.sh

# 3. Keep a second session open, authenticated, while applying.
#    If SSH dies, that second session is your way back in.
sudo ./harden.sh --apply

# 4. Confirm.
./audit.sh
```

Step 3 is not optional advice. A hardening tool that breaks SSH is a routine
outcome on the first run against a real host, and an already-open second session
is the cheapest insurance available.
