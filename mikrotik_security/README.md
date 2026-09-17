mikrotik_security
=================

Audits MikroTik RouterOS devices for known compromises (MikroTrick, Meris), vulnerable versions and risky management settings. It reports structured findings by email or Slack.

See the [repository README](../README.md) for checks, variables and examples.

Requirements
------------

- `community.routeros` and `ansible.netcommon` (`network_cli` connection)
- `community.general` for email and Slack reports
- RouterOS 7.13 or newer for the `vulnerabilities` (exposure details), `mikrotrick` and `security_baseline` collectors

Example Playbook
----------------

    - hosts: routers
      gather_facts: false
      connection: ansible.netcommon.network_cli
      vars:
        ansible_network_os: community.routeros.routeros
      roles:
        - role: mikrotik_security
          vars:
            authorized_users: [admin, ansible]
            routeros_management_networks: [192.0.2.0/24]

License
-------

See LICENSE in the repository root.
