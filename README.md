# mikrotik_security
default structure for ansible

This Ansible role checks MikroTik devices for security vulnerabilities.

## Currently supported checks
1. meris vulnerability

## How to use
Set the variable for the check you want to perform, and whether you want to perform remediations.

```
check_type: meris
remediate: true/false
```
