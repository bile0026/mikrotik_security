# mikrotik_security

This Ansible role checks MikroTik devices for security vulnerabilities. Multiple checks can be run by including them in the `check_type` list.

## Pre-tasks
1. Install the routeros collection using `ansible-galaxy collection install -r mikrotik_security/collections/requirements.yml`

## Currently supported checks
1. meris vulnerability - checks for indicators of compromise, such as unauthorized users, scripts/files/schedules that are suspected to be leveraged in this attack.
2. Unauthorized users - checks for user accounts that are not supposed to be on the device compared with a list of known good usernames.

# How to use - Meris check

> inspired by: https://unimus.net/blog/validating-security-of-mikrotik-routers-network-wide.html

Set the variable for the check you want to perform, and whether you want to perform remediations.

> **DANGER!**
  I would highly reccomend running without remediation first to see what possibly vulnerabilities you might have. This script has the possibility to delete user accounts or scripts that could be legitimate. Please understand what this playbook does before running remediation.

The `check_type` variable is a list. This way multiple security checks can be run in one run as they are added to the list of supported checks.

* FYI, the user check looks for usernames that contain the string "service". If you use that in actual service account names, *DO NOT* run the remediation tasks as that will also remove your legitimate service accounts.

```
check_type:
  - meris
remediate: true/false
```

Once run is complete. The assert tasks at the end will give you information on each individual check, plus a summary at the end. Check these messages for information on your environment.

# How to use - Unauth_users check
Set the variable for `check_type` to `unuauth_users`. Also, provide a list of known usernames that should be present. This is the list that will be compared to what's actually on the device. I would highly reccomend running without remediation first to see what possibly vulnerabilities you might have.

> **DANGER!**
    If running with `remediation: true`, this playbook has the possibility of deleting a user account if it's not specified in the `authorized_users` list. Please be extra sure this list is accurate and complete before running remediation.

* Note, this will currently only work with usernames that contain only letters and numbers. It will not work correctly if there are special characters in usernames.

```
check_type:
  - unauth_users
remediate:
  - true/false
authorzied_users:
  - ansible
  - test
```

Once run is complete the assert tasks at the end will provide information on whether unauthorized user accounts were found on devices.

## Additional Notes
* You should also change usernames and passwords of legitimate accounts on your devices as well as good practice, especially if there were issues found. Do this *AFTER* running remediation!
* Check your `firewall` and `/ip service` settings to make sure you have proper input chain rules to prevent connections from unauthorized IPs. Disable any services not required, and consider changing default ports or adding source IP access lists to services you do need.
* Update RouterOS to the latest version in your release train. (stable, lts, etc)
