# mikrotik_security

This Ansible role checks MikroTik devices for security vulnerabilities. Multiple checks can be run by including them in the `check_type` list.

## Pre-tasks
1. Install the routeros collection using `ansible-galaxy collection install -r collections/requirements.yml`

## Currently supported checks
1. meris vulnerability - checks for indicators of compromise, such as unauthorized users, scripts/files/schedules that are suspected to be leveraged in this attack.
2. Unauthorized users - checks for user accounts that are not supposed to be on the device compared with a list of known good usernames.

## Notes:
* If you are going to run multiple checks this will run them in the order you list them in `check_type`. I suggest if you are going to use the `unauth_users` check, I would run that last. If you run it before other tasks it could wipe out other user accounts that would be indicators of compromise like in the scenario of the meris vulnerability. One of the indicators of compromise with the meris vulnerability is a user created with a name like \*service\*. If you ran `unauth_users` before the meris check with remediate it would wipe out those user accounts prior to the meris checks being performed. Ultimately the same end result is accomplished, but you may not get the indication where you might want to look into those devices more closely.

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
    If running with `remediation: true`, this playbook has the possibility of deleting a user account if it's not specified in the `authorized_users` list. Please be extra sure this list is accurate and complete before running remediation. Note, usernames are case-sensitive.

* Note, this will currently only work with usernames that contain letters, numbers, and these special characters `-_@+*.`. If you'd like more added, please open an issue/PR.

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

# Reports

## Email reports

If you wish to have a report emailed to you, include the variables for the email task. This will email a txt file with a printout of the results of your checks.

* At this point, it will always email, even if no vulnerabilities were found. My plan is to eventually add logic so that an email is only sent if there is a compromise found.

```
generate_report: true
smtp_server: <smtp_server>
port: <smrtp_port>
email_addresses:
  - name@example.com
  - name2@example.com
from_email: email@example.com
```

## Slack Reports
* info on setting up slack bot: https://github.com/ansible/awx/issues/6610#issuecomment-613035465

Include the following variables to run slack notifications. Currently slack notifications have a character limit of 3000, so this might not be the best method if you have a lot of devices.

* Note, only public channels seem to work at this time. Will work this out eventually.

```
slack_token: <generate token>
slack_channel: welcome
slack_username: ansible_notifications
```

## Additional Notes
* You should also change usernames and passwords of legitimate accounts on your devices as well as good practice, especially if there were issues found. Do this *AFTER* running remediation!
* Check your `firewall` and `/ip service` settings to make sure you have proper input chain rules to prevent connections from unauthorized IPs. Disable any services not required, and consider changing default ports or adding source IP access lists to services you do need.
* Update RouterOS to the latest version in your release train. (stable, lts, etc)
