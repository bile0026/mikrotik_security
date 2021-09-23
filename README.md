# mikrotik_security

This Ansible role checks MikroTik devices for security vulnerabilities.

## Pre-tasks
1. Install the routeros collection using `ansible-galaxy collection install -r mikrotik_security/collections/requirements.yml`

## Currently supported checks
1. meris vulnerability

## How to use
Set the variable for the check you want to perform, and whether you want to perform remediations. I would highly reccomend running without remediation first to see what possibly vulnerabilities you might have.

* FYI, the user check looks for usernames that contain the string "service". If you use that in actual service account names, DO NOT run the remediation tasks as that will also remove your legitimate service accounts.

```
check_type: meris
remediate: true/false
```

Once run is complete. The assert tasks at the end will give you information on each individual check, plus a summary at the end. Check these messages for information on your environment.

## Additional Notes
* You should also change usernames and passwords of legitimate accounts on your devices as well as good practice, especially if there were issues found. Do this *after* running remediation!
* Check your `firewall` and `/ip service` settings to make sure you have proper input chain rules to prevent connections from unauthorized IPs. Disable any services not required, and consider changing default ports or adding source IP access lists to services you do need.
* Update RouterOS to the latest version in your release train. (stable, lts, etc)
