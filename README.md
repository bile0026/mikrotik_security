# mikrotik_security

This Ansible role audits MikroTik RouterOS devices. It looks for signs of compromise, versions with known vulnerabilities, and risky management settings. Every check produces structured findings, and the role turns them into a text report that it can email or post to Slack.

RouterOS 7 is the main target. The `vulnerabilities`, `mikrotrick` and `security_baseline` checks read configuration as JSON, which needs RouterOS 7.13 or newer. On older devices, including RouterOS 6, those checks report `UNKNOWN`, except the version check, which works everywhere. The older `meris` and `unauth_users` checks still work on RouterOS 6.

## Pre-tasks
1. Install the collections with `ansible-galaxy collection install -r collections/requirements.yml`.
2. Connect with `ansible_connection: ansible.netcommon.network_cli` and `ansible_network_os: community.routeros.routeros`. See `security_check.yml` for an example.

## Checks

List the checks to run in `check_type`. They run in the order listed.

```yaml
check_type:          # default
  - vulnerabilities
  - mikrotrick
  - security_baseline
```

| check | what it looks at |
| --- | --- |
| `vulnerabilities` | RouterOS version against the advisories in `routeros_advisories` |
| `mikrotrick` | Evidence of the September 2026 MikroTrick compromise (CVE-2026-67276, CVE-2026-86060, CVE-2026-67277) |
| `security_baseline` | Management exposure: `/ip service`, input firewall, SOCKS, RoMON, MAC server, bandwidth-test, IP Cloud DDNS, DNS, device-mode |
| `meris` | 2021 Meris indicators (kept for history; supports remediation) |
| `unauth_users` | Users not in `authorized_users` (supports remediation) |

Only `meris` and `unauth_users` can change the router, and only when `remediate: true`. The other checks only read.

### Findings

Each check adds entries to the `routeros_security_findings` host fact:

```yaml
- id: mikrotrick.ssh_keys
  check: mikrotrick
  title: SSH keys
  result: CRITICAL
  message: "1 of 2 SSH key(s) need review; resetting passwords does not remove key access"
  evidence:
    - "configured SSH key user: svcnet owner: mtops (key-type=ed25519 bits=256) CRITICAL - key owner matches MikroTrick IoC; ..."
    - "configured SSH key user: ansible owner: ansible-ci (key-type=ed25519 bits=256) PASS"
```

`result` is one of:

| result | meaning |
| --- | --- |
| `PASS` | Checked and fine |
| `INFO` | Worth knowing, not a problem by itself (also used for suppressed findings) |
| `UNKNOWN` | Could not be checked, for example because the RouterOS version is too old or a menu could not be read |
| `WARNING` | Risky configuration, or suspicious behaviour that may be legitimate |
| `CRITICAL` | A known indicator of compromise, or a vulnerable version under active exploitation |

After the report is sent, the role fails any host with a finding at or above `routeros_security_fail_on` (`critical` by default). That way an AWX job shows which routers need attention. Set it to `none` to never fail, or `warning` to fail on warnings too.

To downgrade findings you have reviewed to `INFO`, list their ids (a trailing `*` matches a prefix):

```yaml
routeros_security_suppress:
  - baseline.dns_remote_requests
  - baseline.service.*
```

## How to use - vulnerabilities

`routeros_advisories` in `defaults/main.yml` lists each advisory and the first fixed release on each release train. The check compares versions per train rather than with a single `>=`:
- A version is fixed if its own major.minor train has a listed fix and the version is at or above it.
- A version is also fixed if its train is newer than every listed train of the same major version.

With the MikroTrick fixes (6.49.21, 7.23.4, 7.24.2, 7.25beta3):
- 7.23.4 and 7.25rc1 pass.
- 7.24.1 and 7.22.2 are `CRITICAL`.
- A major version with no listed fix is `UNKNOWN`.

The CVE-2026-52346 entry uses `requires: firewall_tls_host`. That vulnerable code only runs when a firewall rule uses `tls-host`, so on an affected version with no such rule the finding is `INFO`.

To add an advisory, append an entry:

```yaml
routeros_advisories:
  - id: example
    name: Example issue
    cves: [CVE-2026-00000]
    severity: warning            # result when affected
    url: https://mikrotik.com/supportsec/...
    fixed_in:
      - {version: "7.22.3", channel: stable}
      - {version: "7.21.5", channel: long-term}
```

Quote versions so YAML does not turn `7.25` into a number.

## How to use - MikroTrick

> inspired by: https://blog.j2sw.com/netops/mikrotik-router-compromise-forensic-walkthrough/ and https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/

The check looks at these areas. Most of them are `CRITICAL` on an IoC match.

| id | looks at |
| --- | --- |
| `device_flagged` | `/system device-mode` flagged status |
| `known_users` | Users named `svcnet`, `cfgmarket`, `ops`, or containing `cfgmarket` |
| `unauthorized_users` | Users not in `authorized_users`; `CRITICAL` if they can change configuration |
| `ssh_keys` | Every `/user ssh-keys` entry: known key owners (`mtops`), and users not in `authorized_ssh_key_users` |
| `schedulers`, `scripts`, `script_hooks` | Known names, calls to known scripts, C2 addresses, and suspicious command combinations. `script_hooks` covers netwatch, PPP profile and DHCP scripts |
| `files` | Known persistence files such as `mt_setup.rsc` and `mt_pub.key` |
| `c2_addresses` | Known C2 addresses anywhere in the collected configuration (`INFO` when only a drop rule references them) |
| `firewall_comments` | Rules with `cfgmarket` comments |
| `ovpn_clients`, `pptp_clients` | Clients not in `authorized_ovpn_clients` / `authorized_pptp_clients` |
| `ovpn_server`, `pptp_server` | Servers that are enabled although `routeros_expected_features` says they should not be |
| `ppp_secrets` | IoC names, plus `authorized_ppp_users` when that list is set |
| `logs`, `history` | The `-2` username used to exploit CVE-2026-86060, logins from C2 addresses, and changes by known users |

Attackers can rename all of these IoCs, so the behavioural check matters more. A script, scheduler or embedded script that matches at least `mikrotrick_suspicious_min_matches` (default 2) of `mikrotrick_suspicious_script_patterns` is a `WARNING`. The patterns cover `/tool fetch`, `/import`, `/user add|set`, SSH keys, `/ip service`, VPN interfaces, SOCKS, `/system scheduler add` and `/ip cloud`. Legitimate scripts can match: a blocklist loader, for example, runs fetch and import. To skip the name and behaviour checks for a known-good script, list it in `mikrotrick_trusted_script_names`. Trusted scripts are still searched for C2 addresses.

Logs and `/system history` are kept in memory and cleared on reboot, so a clean result there does not prove much.

```yaml
check_type:
  - mikrotrick
authorized_users:
  - admin
  - zbiles
  - ansible
authorized_ssh_key_users:     # defaults to authorized_users
  - zbiles
  - ansible
authorized_ssh_key_owners: ~  # optional list of key comments
authorized_ovpn_clients: []
authorized_pptp_clients: []
authorized_ppp_users: ~       # null skips the allowlist (useful on PPPoE concentrators)
```

The IoC lists (`mikrotrick_known_users`, `mikrotrick_known_scheduler_names`, `mikrotrick_known_c2_addresses` and the rest) are in `defaults/main.yml`, with their sources.

MikroTik recommends upgrading first, then checking for unknown users, scripts and configuration. A compromised router can recreate accounts from schedulers, so remove schedulers and scripts before removing users.

## How to use - security baseline

```yaml
check_type:
  - security_baseline
routeros_management_networks:   # optional
  - 64.90.67.144/29
  - 142.249.21.0/24
routeros_allowed_services:
  - ssh
  - winbox
routeros_expected_features:
  socks: false
  romon: false
  ovpn_server: false
  pptp_server: false
  bandwidth_server: false
  cloud_ddns: false
```

Each `/ip service` entry produces its own finding. An enabled service is a `WARNING` if any of these apply:
- It isn't in `routeros_allowed_services`.
- It's a cleartext protocol (telnet, ftp, www, api).
- It has no address restriction.
- It allows `0.0.0.0/0`.
- `routeros_management_networks` is set and the service allows addresses outside those networks.

```
PASS      Service ssh: ssh is restricted to approved management networks
          - enabled: yes
          - port: 2937
          - allowed-addresses: 64.90.67.144/29,142.249.21.0/24
WARNING   Service ssh: ssh: allowed from 0.0.0.0/0
          - enabled: yes
          - port: 22
          - allowed-addresses: 0.0.0.0/0
```

The firewall check warns in two cases:
- An input-chain accept rule opens management ports to any source.
- No drop rule catches the rest of the input traffic.

It does not evaluate rule order.

## How to use - Meris check

> inspired by: https://unimus.net/blog/validating-security-of-mikrotik-routers-network-wide.html

Set the variable for the check you want to perform, and whether you want to perform remediations.

> **DANGER!**
  I would highly reccomend running without remediation first to see what possibly vulnerabilities you might have. This script has the possibility to delete user accounts or scripts that could be legitimate. Please understand what this playbook does before running remediation.

* FYI, the user check looks for usernames that contain the string "service". If you use that in actual service account names, *DO NOT* run the remediation tasks as that will also remove your legitimate service accounts.

```
check_type:
  - meris
remediate: true/false
```

## How to use - Unauth_users check
Set the variable for `check_type` to `unauth_users`. Also, provide a list of known usernames that should be present. This is the list that will be compared to what's actually on the device. I would highly reccomend running without remediation first to see what possibly vulnerabilities you might have.

> **DANGER!**
    If running with `remediate: true`, this playbook has the possibility of deleting a user account if it's not specified in the `authorized_users` list. Please be extra sure this list is accurate and complete before running remediation. Note, usernames are case-sensitive.

* Note, this will currently only work with usernames that contain letters, numbers, and these special characters `-_@+*.`. If you'd like more added, please open an issue/PR.
* If you run `unauth_users` together with `meris`, list it last. Otherwise its remediation removes the `*service*` users before the Meris check can report them.

```
check_type:
  - unauth_users
remediate: true/false
authorized_users:
  - ansible
  - test
```

# Reports

Reports group findings by host, most severe first, and start with a summary per host. Hosts that were unreachable or failed before the checks finished are listed as `NOT RUN`. Set `routeros_report_show_pass: false` to leave out `PASS` findings, which is worth doing on a large fleet: a clean router still produces around 20 `PASS` lines.

## Report formats

`routeros_report_formats` picks which formats get written. Each one is written next to `report_file` with its own extension, so `Mikrotik Security Report Ansible 2026-09-17.txt` is joined by `.csv` and `.html` versions.

| Format | Layout | Good for |
| ------ | ------ | -------- |
| `txt` | A block of text per host | A couple of routers, or piping into other tools |
| `csv` | One row per finding, with `host,address,routeros_version,board,check,id,result,title,message,evidence` columns | Many routers: sort by severity, filter by check, or pivot in a spreadsheet |
| `html` | A fleet table of one row per host with per-severity counts, linked to per-host detail below | Reading the whole fleet at a glance, and as an email body |

```yaml
routeros_report_formats:
  - csv
  - html
```

In CSV, a finding's evidence lines are joined with ` | ` to keep one finding per row. Every cell is quoted, so commas and quotes in RouterOS values stay intact. In HTML, `PASS` findings collapse into a single row per host listing their titles.

## Email reports

If you wish to have a report emailed to you, include the variables for the email task. Every format listed in `routeros_report_formats` is attached. If `html` is one of them, the report also becomes the message body so it is readable without opening an attachment.

* At this point, it will always email, even if no vulnerabilities were found.

```
generate_report: true
smtp_server: <smtp_server>
smtp_port: <smtp_port>
email_addresses:
  - name@example.com
  - name2@example.com
from_email: email@example.com
```

## Slack Reports
* info on setting up slack bot: https://github.com/ansible/awx/issues/6610#issuecomment-613035465

Include the following variables to send Slack notifications. Slack limits a message section to 3000 characters. The Slack message therefore lists every host's overall result and finding counts first, then the `CRITICAL` findings; the full report goes in the email.

* Note, only public channels seem to work at this time. Will work this out eventually.

```
slack_token: <generate token>
slack_channel: welcome
slack_username: ansible_notifications
```

# How collection works

The v2 checks read each RouterOS menu with `print detail as-value` over the existing SSH (`network_cli`) connection. Settings menus don't accept `detail`, so they fall back to `print as-value`. Each item is serialized to JSON with `:serialize`, base64-encoded with `:convert`, and printed in short marked lines. Ansible decodes them with the filters in `filter_plugins/routeros_security.py`. This format isn't affected by terminal width, and it can't trip the routeros terminal plugin's error patterns.

Collection is read-only and doesn't need the API service. Password-like properties (`password`, `secret`, `private-key` and similar) are replaced with `REDACTED` on the router before they are sent. Collected configuration is hidden from job output unless you set `routeros_security_no_log: false`.

Related settings:
- `routeros_security_collector_chunk_size`: characters per output line (default 64).
- `routeros_security_command_timeout`: per-menu timeout in seconds (default 120).
- `routeros_security_collect_logs` and `routeros_security_collect_ppp_secrets`: set to `false` to skip those menus on very large devices.

# Testing

The detection logic has unit tests:

```
python -m pytest mikrotik_security/tests/unit
```

## Additional Notes
* You should also change usernames and passwords of legitimate accounts on your devices as well as good practice, especially if there were issues found. Do this *AFTER* running remediation!
* Check your `firewall` and `/ip service` settings to make sure you have proper input chain rules to prevent connections from unauthorized IPs. Disable any services not required, and consider changing default ports or adding source IP access lists to services you do need. MikroTik recommends not exposing SSH to untrusted networks and managing routers over a VPN such as WireGuard.
* Update RouterOS to the latest version in your release train. (stable, long-term, etc)
