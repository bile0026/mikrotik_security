# -*- coding: utf-8 -*-
"""Filters for the mikrotik_security role.

Collection, version comparison and evaluation live here instead of in Jinja so
the detection logic can be unit tested without a router.

Every check produces findings shaped like:

    {'id': 'mikrotrick.ssh_keys', 'check': 'mikrotrick', 'title': 'SSH keys',
     'result': 'CRITICAL', 'message': '...', 'evidence': ['...']}

where result is one of PASS, INFO, UNKNOWN, WARNING or CRITICAL.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import binascii
import csv
import io
import ipaddress
import json
import re

from ansible.errors import AnsibleFilterError

LEVELS = ('PASS', 'INFO', 'UNKNOWN', 'WARNING', 'CRITICAL')

# Property names whose values are replaced on the router before they are sent
# back, so credentials never reach Ansible output or AWX job events.
REDACT_KEYS = (
    'password', 'secret', 'private-key', 'preshared-key', 'passphrase',
    'key-passphrase', 'authentication-password', 'encryption-password',
    'secrets', 'contents',
)

# Output markers. The collector script builds them from two string pieces so
# the echoed command text can never contain a marker.
_MARKER_PREFIX = 'RSA'
_MARKER_RE = re.compile(r'RSA(?:(B)\||J:([A-Za-z0-9+/=]*)\||(X)\||(Z)\|)')
_UNSAFE_SCRIPT_CHARS = re.compile(r'["$\\]')

# Flags RouterOS shows in "print" but leaves out of "as-value" output.
_ITEM_FLAGS = ('disabled', 'dynamic', 'invalid')


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _rank(level):
    try:
        return LEVELS.index(str(level).upper())
    except ValueError:
        raise AnsibleFilterError('unknown finding level %r, expected one of %s' % (level, ', '.join(LEVELS)))


def _worst(levels, default='PASS'):
    levels = list(levels)
    return max(levels, key=_rank) if levels else default


def _finding(check, fid, title, result, message, evidence=None):
    return {
        'id': '%s.%s' % (check, fid),
        'check': check,
        'title': title,
        'result': result,
        'message': message,
        'evidence': list(evidence or []),
    }


def _text(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (list, tuple)):
        return ','.join(_text(v) for v in value)
    return str(value)


def _bool(value):
    if isinstance(value, bool):
        return value
    return _text(value).strip().lower() in ('true', 'yes', 'on', 'enabled')


def _list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        values = [_text(v) for v in value]
    else:
        values = re.split(r'[,;]', _text(value))
    return [v.strip() for v in values if v.strip()]


def _lower_set(values):
    return set(_text(v).strip().lower() for v in (values or []) if _text(v).strip())


def _word_re(words):
    words = [w for w in (words or []) if w]
    if not words:
        return None
    return re.compile(r'(?<![\w-])(%s)(?![\w-])' % '|'.join(re.escape(w) for w in words), re.IGNORECASE)


def _address_re(addresses):
    addresses = [a for a in (addresses or []) if a]
    if not addresses:
        return None
    return re.compile(r'(?<![\d.])(%s)(?!\d)' % '|'.join(re.escape(a) for a in addresses))


def _describe(item, *keys):
    """Short 'key=value' description of an item for evidence lines."""
    parts = []
    for key in keys:
        value = item.get(key)
        if value not in (None, '', []):
            parts.append('%s=%s' % (key, _text(value)))
    return ' '.join(parts)


class _Data(object):
    """Accessor for the decoded collector results in routeros_data."""

    def __init__(self, data):
        self._data = data or {}

    def status(self, name):
        entry = self._data.get(name)
        return entry.get('status', 'error') if entry else 'missing'

    def ok(self, name):
        return self.status(name) == 'ok'

    def items(self, name):
        return list(self._data[name].get('items') or []) if self.ok(name) else []

    def one(self, name):
        items = self.items(name)
        return items[0] if items else {}

    def reason(self, *names):
        reasons = []
        for name in names:
            if self.ok(name):
                continue
            entry = self._data.get(name) or {}
            reasons.append('%s: %s' % (name, entry.get('error') or 'not collected'))
        return '; '.join(reasons)

    def names(self):
        return list(self._data)


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------

def routeros_collector_command(collector, chunk_size=64, redact_keys=REDACT_KEYS):
    """Build a RouterOS script that prints a menu as base64-encoded JSON.

    List menus are read with "print detail as-value" (plain as-value omits
    properties such as netwatch up-script). Settings menus reject "detail" and
    return a flat key/value array from "print as-value", which is emitted as a
    single item. "get" is never used: on a list menu it waits for an
    interactive "numbers:" prompt.

    Neither form returns the flag properties, so a disabled /ip service entry
    is indistinguishable from an enabled one. disabled, dynamic and invalid are
    therefore read separately with "find where <flag>" and stamped onto the
    items.

    Each item is serialized separately and printed in short marked lines, so
    terminal wrapping and the error patterns of the routeros terminal plugin
    cannot corrupt it. Paths are resolved with :parse so a menu that does not
    exist on this RouterOS version reports an error marker instead of failing
    the task.

    collector keys: path, and match, an optional mapping of property ->
    RouterOS regex; list items are kept when any of them matches.
    """
    if not isinstance(collector, dict) or not collector.get('path'):
        raise AnsibleFilterError('collector must be a dict with a path, got %r' % (collector,))
    path = collector['path']
    match = collector.get('match') or {}
    for value in [path] + list(match) + list(match.values()):
        if _UNSAFE_SCRIPT_CHARS.search(_text(value)):
            raise AnsibleFilterError('collector %s must not contain quotes, $ or backslashes: %r' % (path, value))
    chunk_size = int(chunk_size)
    if chunk_size < 4:
        raise AnsibleFilterError('chunk_size must be at least 4')

    where = ' || '.join('([:tostr ($r->"%s")] ~ "%s")' % (key, regex) for key, regex in sorted(match.items()))
    redact = ';'.join('"%s"' % key for key in redact_keys)
    # "as-value" never returns the flag properties: a disabled /ip service entry
    # comes back exactly like an enabled one. Each flag is therefore looked up
    # once per menu with "find where <flag>", whose ids are turned into a
    # keyed array so stamping an item is a lookup rather than a scan, which
    # matters on menus with thousands of items. A menu without the property
    # errors out, and the flag is then left off the item rather than written as
    # a misleading false. An empty result is still an array, so "nothing is
    # disabled" is recorded as such.
    find_flags = ' '.join(
        ':local ok{flag} false; :local m{flag} ({{}}); '
        ':do {{:local q{flag} [:parse ":return [{path} find where {flag}]"]; :local a{flag} [$q{flag}]; '
        ':if ([:typeof $a{flag}] = "array") do={{'
        ':foreach v in=$a{flag} do={{:set ($m{flag}->[:tostr $v]) true}}; :set ok{flag} true}}}} '
        'on-error={{}}; '.format(flag=flag, path=path)
        for flag in _ITEM_FLAGS
    )
    stamp_flags = ' '.join(
        ':if ($ok{flag}) do={{:set ($r->"{flag}") false; '
        ':if ([:typeof ($m{flag}->[:tostr ($r->".id")])] != "nothing") do={{:set ($r->"{flag}") true}}}}; '.format(flag=flag)
        for flag in _ITEM_FLAGS
    )
    emit = (
        ':if ([:typeof ($r->".id")] != "nothing") do={%s}; '
        ':foreach k in={%s} do={:if ([:typeof ($r->$k)] != "nothing") do={:set ($r->$k) "REDACTED"}}; '
        ':local s; :do {:set s [$ser $r]} on-error={:set s [:serialize value=$r to=json]}; '
        ':set s [:convert $s from=raw to=base64]; '
        ':put ($p . "B|"); '
        ':local i 0; '
        ':while ($i < [:len $s]) do={:put ($p . "J:" . [:pick $s $i ($i + $c)] . "|"); :set i ($i + $c)}'
    ) % (stamp_flags.strip(), redact)
    # Without json.no-string-conversion (added after 7.13) "22" and "007"
    # serialize as numbers; _text() tidies the floats that produces.
    return (
        ':local p "{marker}"; :local c {chunk}; '
        ':local ser; :do {{:set ser [:parse ":return [:serialize value=\\$1 to=json options=json.no-string-conversion]"]}} on-error={{}}; '
        ':do {{'
        ':local d; '
        '{find_flags}'
        ':do {{:local f [:parse ":return [{path} print detail as-value]"]; :set d [$f]}} '
        'on-error={{:local g [:parse ":return [{path} print as-value]"]; :set d [$g]}}; '
        ':if ([:typeof ($d->0)] = "array") do={{'
        ':foreach x in=$d do={{:local r $x; :if ({where}) do={{{emit}}}}}'
        '}} else={{:if ([:len $d] > 0) do={{:local r $d; {emit}}}}}'
        '}} on-error={{:put ($p . "X|")}}; '
        ':put ($p . "Z|")'
    ).format(marker=_MARKER_PREFIX, chunk=chunk_size, path=path, where=where or 'true', emit=emit,
             find_flags=find_flags)


def routeros_collector_decode(stdout):
    """Decode the output of routeros_collector_command."""
    if isinstance(stdout, (list, tuple)):
        stdout = '\n'.join(_text(s) for s in stdout)
    text = re.sub(r'[\r\n]', '', _text(stdout))
    raw_items = []
    current = None
    errored = complete = malformed = False
    for match in _MARKER_RE.finditer(text):
        begin, chunk, error, end = match.groups()
        if begin:
            if current is not None:
                raw_items.append(current)
            current = []
        elif chunk is not None:
            if current is None:
                malformed = True
            else:
                current.append(chunk)
        elif error:
            errored = True
        elif end:
            complete = True
    if current is not None:
        raw_items.append(current)

    if errored:
        return {'status': 'error', 'error': 'RouterOS could not read this menu on this device', 'items': []}
    if not complete or malformed:
        return {'status': 'error', 'error': 'collector output was incomplete or unreadable', 'items': []}

    items = []
    for index, chunks in enumerate(raw_items):
        try:
            decoded = base64.b64decode(''.join(chunks)).decode('utf-8', 'replace')
            value = json.loads(decoded)
        except (binascii.Error, ValueError) as exc:
            return {'status': 'error', 'error': 'item %d could not be decoded: %s' % (index, exc), 'items': []}
        if not isinstance(value, dict):
            return {'status': 'error', 'error': 'item %d was %s, expected an object' % (index, type(value).__name__), 'items': []}
        for key in REDACT_KEYS:
            if key in value:
                value[key] = 'REDACTED'
        items.append(value)
    return {'status': 'ok', 'items': items}


def routeros_collected_data(results):
    """Turn the registered results of the collector loop into routeros_data entries."""
    data = {}
    for result in results or []:
        if result.get('skipped'):
            continue
        name = result.get(result.get('ansible_loop_var', 'item'))
        if not name:
            continue
        if result.get('failed'):
            data[name] = {'status': 'error', 'error': _text(result.get('msg')) or 'collector task failed', 'items': []}
            continue
        stdout = result.get('stdout') or ['']
        data[name] = routeros_collector_decode(stdout[0])
    return data


def routeros_collectors_unsupported(names, reason):
    """routeros_data entries for collectors that cannot run on this device."""
    return dict((name, {'status': 'unsupported', 'error': reason, 'items': []}) for name in names or [])


# --------------------------------------------------------------------------
# versions
# --------------------------------------------------------------------------

_VERSION_RE = re.compile(r'^\s*v?(\d+)\.(\d+)(?:\.(\d+))?(?:\s*(alpha|beta|rc)\s*(\d+)?)?', re.IGNORECASE)
_PRE_RELEASE_RANK = {'alpha': 0, 'beta': 1, 'rc': 2}


def _parse_version(value):
    match = _VERSION_RE.match(_text(value))
    if not match:
        return None
    major, minor, patch, pre, pre_number = match.groups()
    rank = _PRE_RELEASE_RANK[pre.lower()] if pre else 3
    return (int(major), int(minor), int(patch or 0), rank, int(pre_number or 0))


def routeros_version(value):
    """Normalise '7.24.2 (stable)' to '7.24.2'; returns '' when unparseable."""
    match = _VERSION_RE.match(_text(value))
    return re.sub(r'\s+', '', match.group(0)) if match else ''


def routeros_version_compare(left, operator, right):
    """Compare RouterOS versions, ordering 7.25beta3 < 7.25rc1 < 7.25 < 7.25.1."""
    a, b = _parse_version(left), _parse_version(right)
    if a is None or b is None:
        return False
    ops = {
        '<': a < b, 'lt': a < b,
        '<=': a <= b, 'le': a <= b,
        '==': a == b, '=': a == b, 'eq': a == b,
        '!=': a != b, 'ne': a != b,
        '>=': a >= b, 'ge': a >= b,
        '>': a > b, 'gt': a > b,
    }
    if operator not in ops:
        raise AnsibleFilterError('unsupported version operator %r' % (operator,))
    return ops[operator]


def _fixed_releases(advisory):
    releases = []
    for entry in advisory.get('fixed_in') or []:
        if not isinstance(entry, dict):
            entry = {'version': entry}
        parsed = _parse_version(entry.get('version'))
        if parsed is None:
            raise AnsibleFilterError('advisory %s has an unparseable fixed_in version %r' % (advisory.get('id'), entry.get('version')))
        releases.append((parsed, entry))
    return releases


def _release_label(entry):
    channel = entry.get('channel')
    return '%s (%s)' % (entry['version'], channel) if channel else _text(entry['version'])


def routeros_advisory_status(version, advisory):
    """Work out whether a version contains an advisory's fix.

    MikroTik patches several release trains at once, so a plain ">= x" test is
    wrong: 7.23.4 is fixed while 7.24.1 is not. A version is fixed when its
    own major.minor train has a listed fix and the version is at or above it,
    or when its train is newer than every listed train of the same major.

    Returns a dict with status (fixed, vulnerable, not_affected, unlisted,
    unknown) and upgrade_to, the releases that would fix it.
    """
    current = _parse_version(version)
    if current is None:
        return {'status': 'unknown', 'upgrade_to': []}
    affected_from = advisory.get('affected_from')
    if affected_from and current < _parse_version(affected_from):
        return {'status': 'not_affected', 'upgrade_to': []}

    releases = _fixed_releases(advisory)
    same_major = [(parsed, entry) for parsed, entry in releases if parsed[0] == current[0]]
    if not same_major:
        return {'status': 'unlisted', 'upgrade_to': []}

    train = current[:2]
    for parsed, entry in same_major:
        if parsed[:2] == train:
            if current >= parsed:
                return {'status': 'fixed', 'upgrade_to': []}
            return {'status': 'vulnerable', 'upgrade_to': [_release_label(entry)]}
    if train > max(parsed[:2] for parsed, _ in same_major):
        return {'status': 'fixed', 'upgrade_to': []}
    newer = sorted((p, e) for p, e in same_major if p[:2] > train)
    return {'status': 'vulnerable', 'upgrade_to': [_release_label(e) for _, e in newer]}


# --------------------------------------------------------------------------
# vulnerabilities
# --------------------------------------------------------------------------

_FIREWALL_COLLECTORS = (
    'firewall_filter', 'firewall_nat', 'firewall_mangle', 'firewall_raw',
    'ipv6_firewall_filter', 'ipv6_firewall_mangle',
)

_SERVICE_NAMES = ('telnet', 'ftp', 'www', 'ssh', 'www-ssl', 'api', 'winbox', 'api-ssl')


def _service_entries(d):
    """The configurable /ip service entries, keyed by name.

    RouterOS lists more than the eight built-in services here. Dynamic
    listeners (resolver, dhcp, ntp, snmp, route_BGP, log, zerotier-one) show up
    with a D flag, repeat per protocol, and get a row per established
    connection. None of them can be configured, so only the built-in names are
    real findings.
    """
    items = d.items('services')
    # Prefer the flag, so services added in newer RouterOS releases are still
    # reported. Only when the menu comes back without it anywhere do we fall
    # back to the built-in names, which is enough to drop the dynamic rows.
    flagged = any('dynamic' in service for service in items)
    services = {}
    for service in items:
        name = _text(service.get('name'))
        if not name:
            continue
        if _bool(service.get('dynamic')) if flagged else name not in _SERVICE_NAMES:
            continue
        services.setdefault(name, service)
    return services


def _enabled_service(d, name):
    service = _service_entries(d).get(name)
    if service is not None and not _bool(service.get('disabled')):
        return service
    return None


def _tls_host_rules(d):
    """Return (rules, complete) for firewall rules that use tls-host."""
    rules = []
    complete = True
    for collector in _FIREWALL_COLLECTORS:
        if not d.ok(collector):
            if d.status(collector) != 'missing':
                complete = False
            continue
        for rule in d.items(collector):
            if _text(rule.get('tls-host')).strip():
                rules.append('%s: %s' % (collector, _describe(rule, 'chain', 'action', 'tls-host', 'disabled', 'comment')))
    if not any(d.ok(c) for c in _FIREWALL_COLLECTORS):
        complete = False
    return rules, complete


def _advisory_context(d, advisory):
    evidence = []
    for context in advisory.get('context') or []:
        if context == 'ssh_service' and d.ok('services'):
            ssh = _enabled_service(d, 'ssh')
            if ssh:
                evidence.append('SSH is enabled on port %s, allowed from %s' % (
                    _text(ssh.get('port')), _text(ssh.get('address')) or 'any address'))
            else:
                evidence.append('SSH service is disabled')
        elif context == 'bandwidth_server' and d.ok('bandwidth_server'):
            enabled = _bool(d.one('bandwidth_server').get('enabled'))
            evidence.append('bandwidth-test server is %s' % ('enabled' if enabled else 'disabled'))
    return evidence


def routeros_vulnerability_findings(data, version, advisories):
    d = _Data(data)
    findings = []
    for advisory in advisories or []:
        fid = advisory.get('id')
        if not fid:
            raise AnsibleFilterError('every advisory needs an id: %r' % (advisory,))
        name = advisory.get('name', fid)
        cves = ', '.join(advisory.get('cves') or [])
        label = '%s (%s)' % (name, cves) if cves else name
        severity = _text(advisory.get('severity', 'critical')).upper()
        _rank(severity)
        evidence = []
        if advisory.get('url'):
            evidence.append('Advisory: %s' % advisory['url'])

        status = routeros_advisory_status(version, advisory)
        state = status['status']
        if state == 'unknown':
            result, message = 'UNKNOWN', 'Could not determine the RouterOS version to check %s' % label
        elif state == 'not_affected':
            result, message = 'PASS', 'RouterOS %s predates %s' % (version, label)
        elif state == 'unlisted':
            result = 'UNKNOWN'
            message = 'The %s advisory lists no fixed release for RouterOS %s.x; verify manually' % (name, _text(version).split('.')[0])
        elif state == 'fixed':
            result, message = 'PASS', 'RouterOS %s includes the fix for %s' % (version, label)
        else:
            upgrade = ' or '.join(status['upgrade_to'])
            result = severity
            message = 'RouterOS %s is affected by %s; upgrade to %s' % (version, label, upgrade)
            requirement = advisory.get('requires')
            if requirement == 'firewall_tls_host':
                rules, complete = _tls_host_rules(d)
                if rules:
                    evidence.append('%d firewall rule(s) use tls-host, so the vulnerable code is active' % len(rules))
                    evidence.extend(rules)
                elif complete:
                    result = 'INFO'
                    message = ('RouterOS %s is affected by %s, but no firewall rule uses tls-host so the '
                               'vulnerable code is inactive; upgrade to %s anyway') % (version, label, upgrade)
                else:
                    result = 'WARNING' if _rank(severity) >= _rank('WARNING') else severity
                    message += ' (could not check whether any firewall rule uses tls-host)'
            elif requirement:
                raise AnsibleFilterError('advisory %s has unsupported requires %r' % (fid, requirement))
            evidence.extend(_advisory_context(d, advisory))
        findings.append(_finding('vulnerabilities', fid, name, result, message, evidence))
    return findings


# --------------------------------------------------------------------------
# MikroTrick
# --------------------------------------------------------------------------

# (collector, name property, script properties, label)
_SCRIPT_HOLDERS = (
    ('scripts', 'name', ('source',), 'script'),
    ('schedulers', 'name', ('on-event',), 'scheduler'),
    ('netwatch', 'host', ('up-script', 'down-script', 'test-script'), 'netwatch'),
    ('ppp_profiles', 'name', ('on-up', 'on-down'), 'PPP profile'),
    ('dhcp_clients', 'interface', ('script',), 'DHCP client'),
    ('dhcp_servers', 'name', ('lease-script',), 'DHCP server'),
)

_BLOCKING_ACTIONS = ('drop', 'reject', 'tarpit')


def _unknown(check, fid, title, d, *collectors):
    return _finding(check, fid, title, 'UNKNOWN', 'Not checked (%s)' % d.reason(*collectors))


def _fragment_hit(value, fragments):
    value = _text(value).lower()
    return next((f for f in fragments if f and f in value), None)


class _MikroTrick(object):
    check = 'mikrotrick'

    def __init__(self, data, settings):
        self.d = _Data(data)
        s = settings or {}
        self.authorized_users = set(_text(u) for u in s.get('authorized_users') or [])
        self.authorized_key_users = set(_text(u) for u in s.get('authorized_ssh_key_users') or [])
        owners = s.get('authorized_ssh_key_owners')
        self.authorized_key_owners = None if owners is None else set(_text(o) for o in owners)
        self.authorized_ovpn_clients = set(_text(n) for n in s.get('authorized_ovpn_clients') or [])
        self.authorized_pptp_clients = set(_text(n) for n in s.get('authorized_pptp_clients') or [])
        ppp_users = s.get('authorized_ppp_users')
        self.authorized_ppp_users = None if ppp_users is None else set(_text(n) for n in ppp_users)
        self.expected = s.get('expected_features') or {}
        self.ioc_users = _lower_set(s.get('known_users'))
        self.known_key_owners = _lower_set(s.get('known_ssh_key_owners'))
        self.known_schedulers = _lower_set(s.get('known_scheduler_names'))
        self.known_scripts = _lower_set(s.get('known_script_names'))
        self.known_script_re = _word_re(sorted(self.known_scripts))
        self.known_files = _lower_set(s.get('known_files'))
        self.c2_re = _address_re(s.get('known_c2_addresses'))
        self.ioc_firewall_comments = sorted(_lower_set(s.get('suspicious_firewall_comments')))
        self.fragments = sorted(_lower_set(s.get('known_name_fragments')))
        self.log_res = [re.compile(p, re.IGNORECASE) for p in s.get('log_patterns') or []]
        self.trusted_scripts = set(_text(n) for n in s.get('trusted_script_names') or [])
        patterns = s.get('suspicious_script_patterns') or {}
        self.patterns = [(name, re.compile(regex, re.IGNORECASE | re.MULTILINE)) for name, regex in sorted(patterns.items())]
        self.min_matches = int(s.get('suspicious_min_matches', 2))
        self.collect_logs = _bool(s.get('collect_logs', True))
        self.collect_ppp_secrets = _bool(s.get('collect_ppp_secrets', True))

    def finding(self, fid, title, result, message, evidence=None):
        return _finding(self.check, fid, title, result, message, evidence)

    def known_user_hit(self, name):
        lowered = _text(name).lower()
        if lowered in self.ioc_users:
            return 'known MikroTrick account name'
        fragment = _fragment_hit(lowered, self.fragments)
        if fragment:
            return 'name contains known MikroTrick fragment "%s"' % fragment
        return None

    # -- checks ------------------------------------------------------------

    def device_flagged(self):
        title = 'Device-mode flagged status'
        d = self.d
        if not d.ok('device_mode'):
            return _unknown(self.check, 'device_flagged', title, d, 'device_mode')
        mode = d.one('device_mode')
        if 'flagged' not in mode:
            return self.finding('device_flagged', title, 'INFO',
                                'This RouterOS version does not report a flagged status',
                                [_describe(mode, 'mode')])
        if _bool(mode.get('flagged')):
            return self.finding('device_flagged', title, 'CRITICAL',
                                'RouterOS has flagged this device as compromised; audit the full configuration '
                                'before clearing the flag with /system device-mode update flagged=no',
                                [_describe(mode, 'mode', 'flagged', 'flagging-enabled')])
        return self.finding('device_flagged', title, 'PASS', 'RouterOS has not flagged this device',
                            [_describe(mode, 'mode', 'flagged', 'flagging-enabled')])

    def known_users(self):
        title = 'Known MikroTrick users'
        d = self.d
        if not d.ok('users'):
            return _unknown(self.check, 'known_users', title, d, 'users')
        hits = []
        for user in d.items('users'):
            reason = self.known_user_hit(user.get('name'))
            if reason:
                hits.append('user %s (%s): %s' % (_text(user.get('name')), _describe(user, 'group', 'disabled', 'last-logged-in'), reason))
        if hits:
            return self.finding('known_users', title, 'CRITICAL', 'Found %d user(s) matching MikroTrick IoCs' % len(hits), hits)
        return self.finding('known_users', title, 'PASS', 'No known MikroTrick users found')

    def unauthorized_users(self):
        title = 'Unauthorized users'
        d = self.d
        if not d.ok('users'):
            return _unknown(self.check, 'unauthorized_users', title, d, 'users')
        policies = {}
        for group in d.items('user_groups'):
            policies[_text(group.get('name'))] = set(p for p in _list(group.get('policy')) if not p.startswith('!'))
        levels, evidence = [], []
        for user in d.items('users'):
            name = _text(user.get('name'))
            if name in self.authorized_users:
                continue
            group = _text(user.get('group'))
            policy = policies.get(group, set())
            privileged = group in ('full', 'write') or bool(policy & {'write', 'policy'})
            levels.append('CRITICAL' if privileged else 'WARNING')
            evidence.append('user %s (%s)%s' % (
                name, _describe(user, 'group', 'address', 'disabled', 'last-logged-in'),
                ': can change configuration' if privileged else ''))
        if not evidence:
            return self.finding('unauthorized_users', title, 'PASS', 'All users are in authorized_users')
        return self.finding('unauthorized_users', title, _worst(levels),
                            'Found %d user(s) not in authorized_users' % len(evidence), evidence)

    def ssh_keys(self):
        title = 'SSH keys'
        d = self.d
        if not d.ok('ssh_keys'):
            return _unknown(self.check, 'ssh_keys', title, d, 'ssh_keys')
        keys = d.items('ssh_keys')
        if not keys:
            return self.finding('ssh_keys', title, 'PASS', 'No SSH public keys are installed')
        levels, evidence = [], []
        for key in keys:
            user = _text(key.get('user'))
            # RouterOS 7 shows the public key comment as info; older releases used key-owner.
            owner = _text(key.get('info') or key.get('key-owner') or key.get('comment'))
            problems = []
            level = 'PASS'
            if owner.lower() in self.known_key_owners:
                problems.append('key owner matches MikroTrick IoC')
                level = 'CRITICAL'
            if self.known_user_hit(user):
                problems.append('key user matches MikroTrick IoC')
                level = 'CRITICAL'
            if user not in self.authorized_key_users:
                problems.append('user is not in authorized_ssh_key_users')
                level = 'CRITICAL'
            if self.authorized_key_owners is not None and owner not in self.authorized_key_owners:
                problems.append('key owner is not in authorized_ssh_key_owners')
                level = _worst([level, 'WARNING'])
            levels.append(level)
            line = 'configured SSH key user: %s owner: %s (%s) %s' % (
                user, owner or '-', _describe(key, 'key-type', 'bits', 'disabled'), level)
            if problems:
                line += ' - ' + '; '.join(problems)
            evidence.append(line)
        result = _worst(levels)
        if result == 'PASS':
            message = 'All %d SSH key(s) belong to authorized users' % len(keys)
        else:
            message = '%d of %d SSH key(s) need review; resetting passwords does not remove key access' % (
                len([l for l in levels if l != 'PASS']), len(keys))
        return self.finding('ssh_keys', title, result, message, evidence)

    def _scan_scripts(self, collector, label, name_key, script_keys, known_names):
        """Return (levels, evidence) for items of a collector that hold scripts."""
        levels, evidence = [], []
        for item in self.d.items(collector):
            name = _text(item.get(name_key))
            source = '\n'.join(_text(item.get(k)) for k in script_keys)
            trusted = name in self.trusted_scripts
            reasons = []
            level = 'PASS'
            if not trusted:
                if known_names and name.lower() in known_names:
                    reasons.append('name matches a known MikroTrick %s' % label)
                    level = 'CRITICAL'
                fragment = _fragment_hit(name, self.fragments) or _fragment_hit(item.get('comment'), self.fragments)
                if fragment:
                    reasons.append('name/comment contains "%s"' % fragment)
                    level = 'CRITICAL'
                script = self.known_script_re.search(source) if self.known_script_re else None
                if script:
                    reasons.append('runs known MikroTrick script %s' % script.group(1))
                    level = 'CRITICAL'
            c2 = self.c2_re.search(source) if self.c2_re else None
            if c2:
                reasons.append('references known C2 address %s' % c2.group(1))
                level = 'CRITICAL'
            if not trusted:
                matched = [pname for pname, regex in self.patterns if regex.search(source)]
                if len(matched) >= self.min_matches:
                    reasons.append('contains %s' % ' + '.join(matched))
                    level = _worst([level, 'WARNING'])
            if reasons:
                levels.append(level)
                extra = _describe(item, 'interval', 'start-time', 'disabled', 'comment')
                evidence.append('%s %s%s: %s' % (label, name, ' (%s)' % extra if extra else '', '; '.join(reasons)))
        return levels, evidence

    def _script_finding(self, collector, title, label, script_key, known_names):
        d = self.d
        if not d.ok(collector):
            return _unknown(self.check, collector, title, d, collector)
        levels, evidence = self._scan_scripts(collector, label, 'name', (script_key,), known_names)
        if not evidence:
            return self.finding(collector, title, 'PASS', 'No suspicious %ss found (%d checked)' % (label, len(d.items(collector))))
        return self.finding(collector, title, _worst(levels), 'Found %d suspicious %s(s)' % (len(evidence), label), evidence)

    def schedulers(self):
        return self._script_finding('schedulers', 'Schedulers', 'scheduler', 'on-event', self.known_schedulers)

    def scripts(self):
        return self._script_finding('scripts', 'Scripts', 'script', 'source', self.known_scripts)

    def script_hooks(self):
        """Scripts embedded in netwatch, PPP profiles and DHCP."""
        title = 'Embedded scripts'
        d = self.d
        levels, evidence, missing = [], [], []
        for collector, name_key, keys, label in _SCRIPT_HOLDERS[2:]:
            if not d.ok(collector):
                missing.append(collector)
                continue
            found_levels, found = self._scan_scripts(collector, label, name_key, keys, None)
            levels.extend(found_levels)
            evidence.extend(found)
        if missing:
            levels.append('UNKNOWN')
            evidence.append('not checked: %s' % d.reason(*missing))
        result = _worst(levels)
        if result in ('PASS', 'UNKNOWN') and len(missing) == len(_SCRIPT_HOLDERS) - 2:
            return _unknown(self.check, 'script_hooks', title, d, *missing)
        if result == 'PASS':
            return self.finding('script_hooks', title, 'PASS', 'No suspicious netwatch, PPP profile or DHCP scripts found')
        if result == 'UNKNOWN':
            return self.finding('script_hooks', title, 'UNKNOWN', 'Some embedded scripts could not be checked', evidence)
        return self.finding('script_hooks', title, result,
                            'Found %d suspicious embedded script(s)' % len([l for l in levels if l != 'UNKNOWN']), evidence)

    def files(self):
        title = 'Known MikroTrick files'
        d = self.d
        if not d.ok('files'):
            return _unknown(self.check, 'files', title, d, 'files')
        hits = []
        for item in d.items('files'):
            name = _text(item.get('name'))
            if name.rsplit('/', 1)[-1].lower() in self.known_files:
                hits.append('file %s (%s)' % (name, _describe(item, 'size', 'creation-time', 'last-modified')))
        if hits:
            return self.finding('files', title, 'CRITICAL', 'Found %d file(s) left by MikroTrick persistence' % len(hits), hits)
        return self.finding('files', title, 'PASS', 'No known MikroTrick files found')

    def c2_addresses(self):
        title = 'Known C2 addresses'
        d = self.d
        if not self.c2_re:
            return self.finding('c2_addresses', title, 'INFO', 'No C2 addresses configured')
        levels, evidence = [], []
        searched = 0
        for collector in sorted(d.names()):
            if collector in ('logs', 'history') or not d.ok(collector):
                continue
            searched += 1
            for item in d.items(collector):
                blob = json.dumps(item, sort_keys=True)
                match = self.c2_re.search(blob)
                if not match:
                    continue
                label = _text(item.get('name') or item.get('comment') or item.get('.id'))
                if collector in _FIREWALL_COLLECTORS and _text(item.get('action')) in _BLOCKING_ACTIONS:
                    levels.append('INFO')
                    evidence.append('%s %s blocks %s (%s)' % (collector, label, match.group(1), _describe(item, 'chain', 'action')))
                else:
                    levels.append('CRITICAL')
                    evidence.append('%s %s references %s' % (collector, label, match.group(1)))
        if not searched:
            return self.finding('c2_addresses', title, 'UNKNOWN', 'No configuration was collected to search for C2 addresses')
        result = _worst(levels)
        if result == 'CRITICAL':
            message = 'Configuration references known MikroTrick C2 infrastructure'
        elif evidence:
            message = 'C2 addresses only appear in blocking firewall rules'
        else:
            message = 'No known C2 addresses found in %d configuration menus' % searched
        return self.finding('c2_addresses', title, result, message, evidence)

    def firewall_comments(self):
        title = 'Suspicious firewall rules'
        d = self.d
        collected = [c for c in _FIREWALL_COLLECTORS if d.ok(c)]
        if not collected:
            return _unknown(self.check, 'firewall_comments', title, d, *_FIREWALL_COLLECTORS[:2])
        hits = []
        for collector in collected:
            for rule in d.items(collector):
                comment = _text(rule.get('comment'))
                fragment = _fragment_hit(comment, self.ioc_firewall_comments) or _fragment_hit(comment, self.fragments)
                if fragment:
                    hits.append('%s rule "%s" (%s)' % (collector, comment, _describe(rule, 'chain', 'action', 'src-address', 'dst-port', 'disabled')))
        if hits:
            return self.finding('firewall_comments', title, 'CRITICAL', 'Found %d firewall rule(s) with MikroTrick comments' % len(hits), hits)
        return self.finding('firewall_comments', title, 'PASS', 'No firewall rules carry known MikroTrick comments')

    def _vpn_clients(self, collector, fid, title, allowed, allow_var):
        d = self.d
        if not d.ok(collector):
            return _unknown(self.check, fid, title, d, collector)
        levels, evidence = [], []
        for client in d.items(collector):
            name = _text(client.get('name'))
            reasons = []
            level = 'PASS'
            if name not in allowed:
                reasons.append('not in %s' % allow_var)
                level = 'WARNING'
            hit = self.known_user_hit(client.get('user')) or _fragment_hit(name, self.fragments) or _fragment_hit(client.get('comment'), self.fragments)
            if hit:
                reasons.append('matches MikroTrick IoC (%s)' % hit)
                level = 'CRITICAL'
            if self.c2_re and self.c2_re.search(_text(client.get('connect-to'))):
                reasons.append('connects to known C2 address')
                level = 'CRITICAL'
            if reasons:
                levels.append(level)
                evidence.append('%s (%s): %s' % (name, _describe(client, 'connect-to', 'port', 'user', 'verify-server-certificate', 'disabled'), '; '.join(reasons)))
        if not evidence:
            count = len(d.items(collector))
            return self.finding(fid, title, 'PASS', 'No unexpected clients (%d configured)' % count if count else 'No clients configured')
        return self.finding(fid, title, _worst(levels), 'Found %d unexpected client(s)' % len(evidence), evidence)

    def ovpn_clients(self):
        return self._vpn_clients('ovpn_clients', 'ovpn_clients', 'OpenVPN clients', self.authorized_ovpn_clients, 'authorized_ovpn_clients')

    def pptp_clients(self):
        return self._vpn_clients('pptp_clients', 'pptp_clients', 'PPTP clients', self.authorized_pptp_clients, 'authorized_pptp_clients')

    def _server(self, fid, title, collector, feature):
        d = self.d
        if not d.ok(collector):
            return _unknown(self.check, fid, title, d, collector)
        # Settings menus report enabled=; the multi-server list in newer releases reports disabled=.
        enabled = [s for s in d.items(collector)
                   if (_bool(s['enabled']) if 'enabled' in s else not _bool(s.get('disabled')))]
        if not enabled:
            return self.finding(fid, title, 'PASS', '%s is disabled' % title)
        evidence = [_describe(s, 'name', 'port', 'protocol', 'mode', 'default-profile', 'authentication') for s in enabled]
        if _bool(self.expected.get(feature)):
            return self.finding(fid, title, 'PASS', '%s is enabled as expected' % title, evidence)
        return self.finding(fid, title, 'WARNING',
                            '%s is enabled but routeros_expected_features.%s is false' % (title, feature), evidence)

    def ovpn_server(self):
        return self._server('ovpn_server', 'OpenVPN server', 'ovpn_server', 'ovpn_server')

    def pptp_server(self):
        return self._server('pptp_server', 'PPTP server', 'pptp_server', 'pptp_server')

    def ppp_secrets(self):
        title = 'PPP secrets'
        d = self.d
        if not self.collect_ppp_secrets:
            return self.finding('ppp_secrets', title, 'INFO', 'PPP secret collection is disabled (routeros_security_collect_ppp_secrets)')
        if not d.ok('ppp_secrets'):
            return _unknown(self.check, 'ppp_secrets', title, d, 'ppp_secrets')
        secrets = d.items('ppp_secrets')
        levels, evidence = [], []
        for secret in secrets:
            name = _text(secret.get('name'))
            hit = self.known_user_hit(name) or _fragment_hit(secret.get('comment'), self.fragments)
            if hit:
                levels.append('CRITICAL')
                evidence.append('secret %s (%s): %s' % (name, _describe(secret, 'service', 'profile', 'disabled'), hit))
            elif self.authorized_ppp_users is not None and name not in self.authorized_ppp_users:
                levels.append('WARNING')
                evidence.append('secret %s (%s): not in authorized_ppp_users' % (name, _describe(secret, 'service', 'profile', 'disabled')))
        if not evidence:
            return self.finding('ppp_secrets', title, 'PASS', 'No suspicious PPP secrets (%d configured)' % len(secrets))
        return self.finding('ppp_secrets', title, _worst(levels), 'Found %d suspicious PPP secret(s)' % len(evidence), evidence)

    def _match_entries(self, text):
        reasons = [regex.pattern for regex in self.log_res if regex.search(text)]
        if self.c2_re and self.c2_re.search(text):
            reasons.append('C2 address %s' % self.c2_re.search(text).group(1))
        for user in sorted(self.ioc_users):
            # log lines say "user ops ..."; history redo commands say name=ops or user=ops
            if re.search(r'(?:\buser\s+|\b(?:name|user)="?)%s(?![\w-])' % re.escape(user), text, re.IGNORECASE):
                reasons.append('known user %s' % user)
        return reasons

    def logs(self):
        title = 'Log review'
        d = self.d
        if not self.collect_logs:
            return self.finding('logs', title, 'INFO', 'Log collection is disabled (routeros_security_collect_logs)')
        if not d.ok('logs'):
            return _unknown(self.check, 'logs', title, d, 'logs')
        levels, evidence = [], []
        for entry in d.items('logs'):
            message = _text(entry.get('message'))
            topics = _text(entry.get('topics'))
            reasons = self._match_entries(message)
            if reasons:
                levels.append('CRITICAL')
            elif 'critical' in topics and 'flagged' in message.lower():
                reasons = ['device flagged']
                levels.append('CRITICAL')
            if reasons:
                evidence.append('%s %s: %s [%s]' % (_text(entry.get('time')), topics, message, ', '.join(reasons)))
        if evidence:
            return self.finding('logs', title, _worst(levels), 'Found %d log entr%s matching MikroTrick activity' % (
                len(evidence), 'y' if len(evidence) == 1 else 'ies'), evidence)
        return self.finding('logs', title, 'PASS',
                            'No MikroTrick activity in %d collected log entries (logs may have rotated)' % len(d.items('logs')))

    def history(self):
        title = 'Configuration history'
        d = self.d
        if not d.ok('history'):
            return _unknown(self.check, 'history', title, d, 'history')
        evidence = []
        for entry in d.items('history'):
            # trace holds the session (e.g. ssh:-2@203.0.113.5); redo holds the command
            # and may contain secrets, so it is searched but never reported.
            summary = '%s by %s via %s' % (_text(entry.get('action')), _text(entry.get('by')), _text(entry.get('trace')) or '-')
            reasons = self._match_entries('%s\n%s' % (summary, _text(entry.get('redo'))))
            if self.known_user_hit(entry.get('by')):
                reasons.append('made by known MikroTrick user')
            if reasons:
                evidence.append('%s %s [%s]' % (_text(entry.get('time')), summary, ', '.join(sorted(set(reasons)))))
        if evidence:
            return self.finding('history', title, 'CRITICAL', 'Found %d configuration change(s) matching MikroTrick activity' % len(evidence), evidence)
        return self.finding('history', title, 'PASS',
                            'No MikroTrick changes in %d history entries (history is cleared on reboot)' % len(d.items('history')))

    def run(self):
        return [
            self.device_flagged(),
            self.known_users(),
            self.unauthorized_users(),
            self.ssh_keys(),
            self.schedulers(),
            self.scripts(),
            self.script_hooks(),
            self.files(),
            self.c2_addresses(),
            self.firewall_comments(),
            self.ovpn_clients(),
            self.ovpn_server(),
            self.pptp_clients(),
            self.pptp_server(),
            self.ppp_secrets(),
            self.logs(),
            self.history(),
        ]


def routeros_mikrotrick_findings(data, settings):
    return _MikroTrick(data, settings).run()


# --------------------------------------------------------------------------
# security baseline
# --------------------------------------------------------------------------

_CLEARTEXT_SERVICES = ('telnet', 'ftp', 'www', 'api')

# Firewall properties that do not restrict which packets a rule matches.
_NON_MATCHERS = frozenset((
    '.id', '.nextid', '.about', 'chain', 'action', 'comment', 'disabled', 'dynamic', 'invalid',
    'log', 'log-prefix', 'bytes', 'packets', 'reject-with', 'jump-target', 'address-list',
    'address-list-timeout', 'to-addresses', 'to-ports', 'hw-offload', 'passthrough', 'place-before',
))
_SOURCE_MATCHERS = frozenset((
    'src-address', 'src-address-list', 'in-interface', 'in-interface-list', 'connection-state',
    'connection-nat-state', 'ipsec-policy', 'src-mac-address', 'src-address-type', 'in-bridge-port',
    'in-bridge-port-list', 'dst-address', 'dst-address-list', 'dst-address-type', 'limit', 'dst-limit',
    'connection-limit', 'psd',
))


def _networks(values):
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    return networks


def _ports(value):
    ports = set()
    for part in _list(value):
        if '-' in part:
            low, _, high = part.partition('-')
            if low.isdigit() and high.isdigit():
                ports.update(range(int(low), int(high) + 1))
        elif part.isdigit():
            ports.add(int(part))
    return ports


class _Baseline(object):
    check = 'baseline'

    def __init__(self, data, settings):
        self.d = _Data(data)
        s = settings or {}
        self.management = _networks(_list(s.get('management_networks')))
        self.allowed_services = set(_text(n) for n in s.get('allowed_services') or [])
        self.expected = s.get('expected_features') or {}

    def finding(self, fid, title, result, message, evidence=None):
        return _finding(self.check, fid, title, result, message, evidence)

    def services(self):
        d = self.d
        if not d.ok('services'):
            return [_unknown(self.check, 'services', 'Services', d, 'services')]
        services = _service_entries(d)
        order = dict((name, index) for index, name in enumerate(_SERVICE_NAMES))
        names = sorted(services, key=lambda name: (order.get(name, len(order)), name))
        return [self.service(name, services[name]) for name in names]

    def service(self, name, service):
        fid = 'service.%s' % name
        title = 'Service %s' % name
        addresses = _list(service.get('address'))
        evidence = [
            'enabled: %s' % ('no' if _bool(service.get('disabled')) else 'yes'),
            'port: %s' % _text(service.get('port')),
            'allowed-addresses: %s' % (','.join(addresses) or 'any'),
        ]
        if _bool(service.get('disabled')):
            return self.finding(fid, title, 'PASS', '%s is disabled' % name, evidence)
        problems = []
        if name not in self.allowed_services:
            problems.append('enabled but not in routeros_allowed_services')
        if name in _CLEARTEXT_SERVICES:
            problems.append('sends credentials in cleartext')
        if not addresses:
            problems.append('no address restriction; reachable from anywhere the firewall allows')
        else:
            networks = _networks(addresses)
            open_nets = [str(n) for n in networks if n.prefixlen == 0]
            if open_nets:
                problems.append('allowed from %s' % ', '.join(open_nets))
            elif self.management:
                outside = [str(n) for n in networks
                           if not any(n.version == m.version and n.subnet_of(m) for m in self.management)]
                if outside:
                    problems.append('allows %s outside routeros_management_networks' % ', '.join(outside))
        if problems:
            return self.finding(fid, title, 'WARNING', '%s: %s' % (name, '; '.join(problems)), evidence)
        return self.finding(fid, title, 'PASS', '%s is restricted to approved management networks' % name, evidence)

    def _feature(self, fid, title, collector, feature, enabled_key='enabled', describe=()):
        d = self.d
        if not d.ok(collector):
            return _unknown(self.check, fid, title, d, collector)
        item = d.one(collector)
        evidence = [_describe(item, enabled_key, *describe)]
        if not _bool(item.get(enabled_key)):
            return self.finding(fid, title, 'PASS', '%s is disabled' % title, evidence)
        if _bool(self.expected.get(feature)):
            return self.finding(fid, title, 'PASS', '%s is enabled as expected' % title, evidence)
        return self.finding(fid, title, 'WARNING',
                            '%s is enabled but routeros_expected_features.%s is false' % (title, feature), evidence)

    def socks(self):
        return self._feature('socks', 'SOCKS proxy', 'socks', 'socks', describe=('port', 'version', 'auth-method'))

    def romon(self):
        return self._feature('romon', 'RoMON', 'romon', 'romon', describe=('id',))

    def bandwidth_server(self):
        finding = self._feature('bandwidth_server', 'Bandwidth-test server', 'bandwidth_server', 'bandwidth_server',
                                describe=('authenticate',))
        if finding['result'] == 'WARNING':
            finding['message'] += ' (the service is exposed to CVE-2026-67277 on unpatched versions)'
        return finding

    def cloud_ddns(self):
        return self._feature('cloud_ddns', 'IP Cloud DDNS', 'cloud', 'cloud_ddns', enabled_key='ddns-enabled',
                             describe=('dns-name', 'public-address'))

    def mac_access(self):
        title = 'MAC server access'
        d = self.d
        if not (d.ok('mac_server') or d.ok('mac_winbox')):
            return _unknown(self.check, 'mac_access', title, d, 'mac_server', 'mac_winbox')
        problems, evidence = [], []
        for collector, label in (('mac_server', 'mac-telnet'), ('mac_winbox', 'mac-winbox')):
            if not d.ok(collector):
                continue
            allowed = _text(d.one(collector).get('allowed-interface-list'))
            evidence.append('%s allowed-interface-list: %s' % (label, allowed or '-'))
            if allowed == 'all':
                problems.append(label)
        if problems:
            return self.finding('mac_access', title, 'WARNING',
                                '%s accept connections on all interfaces' % ' and '.join(problems), evidence)
        return self.finding('mac_access', title, 'PASS', 'MAC access is limited to specific interfaces', evidence)

    def dns(self):
        title = 'DNS remote requests'
        d = self.d
        if not d.ok('dns'):
            return _unknown(self.check, 'dns_remote_requests', title, d, 'dns')
        dns = d.one('dns')
        if _bool(dns.get('allow-remote-requests')):
            return self.finding('dns_remote_requests', title, 'INFO',
                                'The router answers DNS for other hosts; make sure the input chain drops port 53 from untrusted networks',
                                [_describe(dns, 'allow-remote-requests', 'servers')])
        return self.finding('dns_remote_requests', title, 'PASS', 'The router does not answer remote DNS requests')

    def device_mode(self):
        title = 'Device-mode'
        d = self.d
        if not d.ok('device_mode'):
            return _unknown(self.check, 'device_mode', title, d, 'device_mode')
        mode = d.one('device_mode')
        evidence = [_describe(mode, 'mode', 'flagging-enabled', 'scheduler', 'socks', 'fetch', 'pptp', 'romon', 'bandwidth-test')]
        if 'flagging-enabled' in mode and not _bool(mode.get('flagging-enabled')):
            return self.finding('device_mode', title, 'WARNING',
                                'Compromise flagging is disabled, so RouterOS will not flag suspicious configuration', evidence)
        return self.finding('device_mode', title, 'PASS', 'Device-mode is %s' % (_text(mode.get('mode')) or 'set'), evidence)

    def firewall_input(self):
        title = 'Firewall input chain'
        d = self.d
        if not d.ok('firewall_filter'):
            return _unknown(self.check, 'firewall_input', title, d, 'firewall_filter')
        rules = [r for r in d.items('firewall_filter')
                 if _text(r.get('chain')) == 'input' and not _bool(r.get('disabled')) and not _bool(r.get('invalid'))]
        if not rules:
            return self.finding('firewall_input', title, 'WARNING', 'The input chain has no rules, so every enabled service is reachable')
        management_ports = set()
        for service in _service_entries(d).values():
            if not _bool(service.get('disabled')) and _text(service.get('port')).isdigit():
                management_ports.add(int(_text(service.get('port'))))
        default_drop = False
        evidence = []
        for rule in rules:
            action = _text(rule.get('action'))
            matchers = set(k for k, v in rule.items() if k not in _NON_MATCHERS and v not in (None, '', False, []))
            if action in _BLOCKING_ACTIONS and matchers <= {'in-interface', 'in-interface-list'}:
                default_drop = True
            if action != 'accept' or matchers & _SOURCE_MATCHERS:
                continue
            protocol = _text(rule.get('protocol'))
            if protocol and protocol not in ('tcp', 'udp', '6', '17'):
                continue
            ports = _ports(rule.get('dst-port'))
            if not ports and not protocol:
                evidence.append('accepts all traffic from any source: %s' % _describe(rule, 'action', 'comment'))
            elif not ports or ports & management_ports:
                evidence.append('accepts management ports from any source: %s' % _describe(rule, 'protocol', 'dst-port', 'comment'))
        if not default_drop:
            evidence.insert(0, 'no drop rule catches the remaining input traffic')
        if evidence:
            return self.finding('firewall_input', title, 'WARNING', 'The input chain may expose management services', evidence)
        return self.finding('firewall_input', title, 'PASS',
                            'The input chain ends in a drop rule and no rule opens management ports to any source')

    def run(self):
        return self.services() + [
            self.firewall_input(),
            self.socks(),
            self.romon(),
            self.mac_access(),
            self.bandwidth_server(),
            self.cloud_ddns(),
            self.dns(),
            self.device_mode(),
        ]


def routeros_baseline_findings(data, settings):
    return _Baseline(data, settings).run()


# --------------------------------------------------------------------------
# legacy checks and reporting
# --------------------------------------------------------------------------

def routeros_assert_finding(assert_result, check, fid, title, failed_level='CRITICAL', evidence=None):
    """Convert a registered assert result (from meris/unauth_users) into a finding."""
    assert_result = assert_result or {}
    if assert_result.get('skipped') or not assert_result:
        return _finding(check, fid, title, 'UNKNOWN', 'Check did not run')
    if not assert_result.get('failed'):
        return _finding(check, fid, title, 'PASS', _text(assert_result.get('msg')))
    if 'assertion' not in assert_result:
        # the assert task itself errored (e.g. a templating error), so nothing was verified
        return _finding(check, fid, title, 'UNKNOWN', 'Check failed to run: %s' % _text(assert_result.get('msg')))
    return _finding(check, fid, title, failed_level, _text(assert_result.get('msg')), evidence)


def routeros_findings_suppress(findings, suppressed):
    """Downgrade suppressed finding ids (or 'check.*' prefixes) to INFO."""
    suppressed = [_text(s) for s in suppressed or []]
    out = []
    for finding in findings or []:
        finding = dict(finding)
        fid = finding.get('id', '')
        hit = any(fid == s or (s.endswith('*') and fid.startswith(s[:-1])) for s in suppressed)
        if hit and _rank(finding['result']) > _rank('INFO'):
            finding['message'] = '%s (suppressed %s)' % (finding['message'], finding['result'])
            finding['result'] = 'INFO'
        out.append(finding)
    return out


def routeros_findings_at_least(findings, level):
    if _text(level).lower() in ('', 'none', 'never'):
        return []
    threshold = _rank(level)
    return [f for f in findings or [] if _rank(f['result']) >= threshold]


def routeros_findings_sort(findings):
    """Most severe first, keeping check order within a level."""
    indexed = list(enumerate(findings or []))
    indexed.sort(key=lambda pair: (-_rank(pair[1]['result']), pair[0]))
    return [f for _, f in indexed]


def routeros_findings_summary(findings):
    counts = dict((level, 0) for level in LEVELS)
    for finding in findings or []:
        counts[finding['result']] = counts.get(finding['result'], 0) + 1
    return {'result': _worst([f['result'] for f in findings or []]), 'counts': counts}


def routeros_csv_row(values):
    """Render one CSV row, quoted so commas, quotes and newlines stay intact."""
    if not isinstance(values, (list, tuple)):
        raise AnsibleFilterError('routeros_csv_row expects a list, got %r' % (values,))
    buf = io.StringIO()
    # QUOTE_ALL keeps every cell quoted whether or not it needs it, and an empty
    # lineterminator leaves the newline to the template. Empty cells are kept so
    # the columns stay aligned.
    csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator='').writerow(
        [_text(value) for value in values]
    )
    return buf.getvalue()


class FilterModule(object):
    def filters(self):
        return {
            'routeros_csv_row': routeros_csv_row,
            'routeros_collector_command': routeros_collector_command,
            'routeros_collector_decode': routeros_collector_decode,
            'routeros_collected_data': routeros_collected_data,
            'routeros_collectors_unsupported': routeros_collectors_unsupported,
            'routeros_version': routeros_version,
            'routeros_version_compare': routeros_version_compare,
            'routeros_advisory_status': routeros_advisory_status,
            'routeros_vulnerability_findings': routeros_vulnerability_findings,
            'routeros_mikrotrick_findings': routeros_mikrotrick_findings,
            'routeros_baseline_findings': routeros_baseline_findings,
            'routeros_assert_finding': routeros_assert_finding,
            'routeros_findings_suppress': routeros_findings_suppress,
            'routeros_findings_at_least': routeros_findings_at_least,
            'routeros_findings_sort': routeros_findings_sort,
            'routeros_findings_summary': routeros_findings_summary,
        }
