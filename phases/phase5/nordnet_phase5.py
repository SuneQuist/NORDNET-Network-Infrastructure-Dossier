#!/usr/bin/env python3
"""NORDNET Phase 5: add UNIV and HEALTH single-site isolated MPLS L3VPN customers.

Default: render only. --build: add two CE nodes/links. --apply: add + configure.
--verify: collect BGP/VRF isolation and preserved MUNI/underlay evidence.

Requires existing healthy NORDNET-Core-POC Phase 4 lab on GNS3 2.2,
Python 3.12 for the local, plaintext Telnet-console operations.
"""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from getpass import getpass
import ipaddress
import json
from pathlib import Path
import re
import sys
import time

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from ios_console import command, console_host, open_console

BASE = Path(__file__).resolve().parent
BASE_NODES = {'PE1', 'P1', 'PE2', 'P2', 'CE-MUNI-HQ', 'CE-MUNI-BR'}
NEW_NODES = {'CE-UNIV', 'CE-HEALTH'}
ALL_NODES = BASE_NODES | NEW_NODES
CUSTOMER_EXPECTED = {
    'UNIV': ('PE1', 'CE-UNIV', 'Gi0/3', 'Gi0/0', '172.21.0.9', '172.21.0.10', 65210, '65000:2001', '65000:200', '10.20.10.0/24', '10.20.10.1'),
    'HEALTH': ('PE2', 'CE-HEALTH', 'Gi0/3', 'Gi0/0', '172.21.0.13', '172.21.0.14', 65310, '65000:3002', '65000:300', '10.30.10.0/24', '10.30.10.1'),
}
OLD_LINKS = {
    frozenset({('PE1', 'Gi0/0'), ('P1', 'Gi0/0')}),
    frozenset({('P1', 'Gi0/1'), ('PE2', 'Gi0/0')}),
    frozenset({('PE1', 'Gi0/1'), ('CE-MUNI-HQ', 'Gi0/0')}),
    frozenset({('PE2', 'Gi0/1'), ('CE-MUNI-BR', 'Gi0/0')}),
    frozenset({('PE1', 'Gi0/2'), ('P2', 'Gi0/0')}),
    frozenset({('P2', 'Gi0/1'), ('PE2', 'Gi0/2')}),
}


def norm_port(name):
    return name.replace('GigabitEthernet', 'Gi')


def utc_stamp():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def validate_inventory(inv):
    if inv['project'] != os.environ.get('NORDNET_TARGET_PROJECT', 'NORDNET-Core-POC') or inv['compute'] != 'vm' or inv['provider_asn'] != 65000:
        raise ValueError('Unexpected project, compute or provider ASN: refusing modification')
    if set(inv['customers']) != set(CUSTOMER_EXPECTED):
        raise ValueError('Expected exactly UNIV and HEALTH customers')
    got_old = {frozenset({(a, norm_port(ai)), (b, norm_port(bi))}) for a, ai, b, bi in inv['links_existing']}
    if got_old != OLD_LINKS:
        raise ValueError('Existing working Phase 4 links differ from the approved design')
    addresses, rd_set, rt_set, lan_networks = set(), set(), set(), []
    for name, c in inv['customers'].items():
        observed = (c['pe'], c['ce'], norm_port(c['pe_interface']), norm_port(c['ce_interface']),
                    c['pe_ip'], c['ce_ip'], c['ce_asn'], c['rd'], c['rt'], c['lan_prefix'], c['lan_ip'])
        if observed != CUSTOMER_EXPECTED[name] or c['vrf'] != name or c['mask'] != '255.255.255.252':
            raise ValueError(f'{name}: addresses/ASNs/ports/VRF differ from approved Phase 5 design')
        segment = ipaddress.IPv4Network(f"{c['pe_ip']}/30", strict=False)
        if ipaddress.IPv4Address(c['ce_ip']) not in segment:
            raise ValueError(f'{name}: CE address not in PE /30')
        lan = ipaddress.IPv4Network(c['lan_prefix'])
        if ipaddress.IPv4Address(c['lan_ip']) not in lan:
            raise ValueError(f'{name}: LAN address outside /24')
        for value in (c['pe_ip'], c['ce_ip'], c['lan_ip']):
            if value in addresses:
                raise ValueError(f'Duplicate interface address: {value}')
            addresses.add(value)
        rd_set.add(c['rd']); rt_set.add(c['rt']); lan_networks.append(lan)
    if len(rd_set) != 2 or len(rt_set) != 2 or lan_networks[0].overlaps(lan_networks[1]):
        raise ValueError('Overlapping or duplicate VPN allocations')
    return True


def render(inv):
    env = Environment(loader=FileSystemLoader(BASE / 'templates'), undefined=StrictUndefined,
                      trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    output_dir = BASE / 'generated'
    output_dir.mkdir(parents=True, exist_ok=True)
    generated = {}
    for c in inv['customers'].values():
        for node_name, template_name in ((c['pe'], 'pe_customer.j2'), (c['ce'], 'ce_customer.j2')):
            contents = env.get_template(template_name).render(customer=c, provider_asn=inv['provider_asn'])
            target = output_dir / f'{node_name}.cfg'
            target.write_text(contents, encoding='utf-8')
            generated[node_name] = contents
            print(f'Rendered generated/{node_name}.cfg')
    return generated


class GNS3:
    def __init__(self, url, username, password):
        self.url = url.rstrip('/')
        self.s = requests.Session()
        self.s.auth = (username, password)
        self.s.headers['Accept'] = 'application/json'

    def call(self, method, path, data=None):
        response = self.s.request(method, self.url + path, json=data, timeout=40)
        if not response.ok:
            raise RuntimeError(f'GNS3 {method} {path}: HTTP {response.status_code}: {response.text[:500]}')
        return response.json() if response.content else None


def project(api, inv):
    hits = [p for p in api.call('GET', '/v2/projects') if p.get('name') == inv['project']]
    if len(hits) != 1:
        raise RuntimeError(f"Expected precisely one existing project {inv['project']!r}; nothing created")
    p = hits[0]
    base = '/v2/projects/' + p['project_id']
    if p['status'] != 'opened':
        api.call('POST', base + '/open', {})
    computes = {c['compute_id']: c for c in api.call('GET', '/v2/computes')}
    vm = computes.get(inv['compute'])
    if not vm or not vm.get('connected') or 'qemu' not in vm.get('capabilities', {}).get('node_types', []):
        raise RuntimeError('The GNS3 VM compute is offline or does not support QEMU')
    return base, vm['host']


def get_nodes(api, base):
    data = api.call('GET', base + '/nodes')
    if len(data) != len({node['name'] for node in data}):
        raise RuntimeError('Duplicate device names; refusing modifications')
    return {node['name']: node for node in data}


def endpoint(node, iface):
    candidates = [p for p in node.get('ports', []) if norm_port(p['name']) == norm_port(iface)]
    if len(candidates) != 1:
        raise RuntimeError(f"{node['name']}: expected port {iface}; found { [p['name'] for p in node.get('ports', [])] }")
    port = candidates[0]
    return {'node_id': node['node_id'], 'adapter_number': port['adapter_number'], 'port_number': port['port_number']}


def ep_key(e):
    return (e['node_id'], e['adapter_number'], e['port_number'])


def link_key(nodes, link):
    a, ai, b, bi = link
    return frozenset({ep_key(endpoint(nodes[a], ai)), ep_key(endpoint(nodes[b], bi))})


def validate_nodes(nodes, inv, require_new=False):
    if not BASE_NODES.issubset(nodes):
        raise RuntimeError(f'Missing Phase 4 devices: {sorted(BASE_NODES - set(nodes))}')
    if set(nodes) - ALL_NODES:
        raise RuntimeError(f'Unexpected devices in project: {sorted(set(nodes) - ALL_NODES)}')
    if require_new and not NEW_NODES.issubset(nodes):
        raise RuntimeError('New customer CEs missing; run --build')
    for n in nodes.values():
        if n.get('compute_id') != inv['compute'] or n.get('node_type') != 'qemu':
            raise RuntimeError(f"{n['name']}: unexpected compute or appliance type")
    for c in inv['customers'].values():
        endpoint(nodes[c['pe']], c['pe_interface'])


def expected_new_links(inv):
    return [(c['pe'], c['pe_interface'], c['ce'], c['ce_interface']) for c in inv['customers'].values()]


def build(api, base, inv, change_allowed):
    nodes = get_nodes(api, base)
    validate_nodes(nodes, inv)
    # Validate all pre-existing links *before* creating anything new. This is
    # important because an existing port collision must not leave extra nodes.
    initial_links = api.call('GET', base + '/links')
    initial_actual = {frozenset(ep_key(e) for e in link['nodes']) for link in initial_links}
    initial_base = {link_key(nodes, ln) for ln in inv['links_existing']}
    if not initial_base.issubset(initial_actual):
        raise RuntimeError('Original Phase 4 connections differ from approved topology')
    initial_new = {link_key(nodes, ln) for ln in expected_new_links(inv)} if NEW_NODES.issubset(nodes) else set()
    if initial_actual - (initial_base | initial_new):
        raise RuntimeError('Unexpected GNS3 links; refusing topology modification')
    if not NEW_NODES.issubset(nodes):
        if not change_allowed:
            raise RuntimeError('Phase 5 customer routers missing; run --build')
        templates = [t for t in api.call('GET', '/v2/templates')
                     if t.get('name') == inv['template_name'] and t.get('template_type') == 'qemu']
        if len(templates) != 1:
            raise RuntimeError('Cisco IOSv QEMU template not found uniquely; check inventory.template_name')
        template = templates[0]
        if template.get('compute_id') not in (None, inv['compute']):
            raise RuntimeError('Cisco IOSv template assigned to a different compute')
        for c in inv['customers'].values():
            if c['ce'] not in nodes:
                print(f"Creating {c['ce']} on compute {inv['compute']} ...")
                api.call('POST', base + '/templates/' + template['template_id'],
                         {'name': c['ce'], 'compute_id': inv['compute'], 'x': c['node_x'], 'y': c['node_y']})
        nodes = get_nodes(api, base)
    validate_nodes(nodes, inv, require_new=True)
    actual_links = api.call('GET', base + '/links')
    current = {frozenset(ep_key(e) for e in lnk['nodes']) for lnk in actual_links}
    baseline = {link_key(nodes, ln) for ln in inv['links_existing']}
    proposed = {link_key(nodes, ln) for ln in expected_new_links(inv)}
    if not baseline.issubset(current):
        raise RuntimeError('Original Phase 4 connections differ from approved topology')
    if current - (baseline | proposed):
        raise RuntimeError('Unexpected GNS3 links; refusing to make further changes')
    used = set().union(*current) if current else set()
    for ln in expected_new_links(inv):
        a, ai, b, bi = ln
        pair = link_key(nodes, ln)
        if pair in current:
            print(f'Exists: {a}:{ai} <-> {b}:{bi}')
            continue
        if not change_allowed:
            raise RuntimeError(f'Missing {a}:{ai} <-> {b}:{bi}; run --build')
        ea, eb = endpoint(nodes[a], ai), endpoint(nodes[b], bi)
        if any(ep_key(e) in used for e in (ea, eb)):
            raise RuntimeError(f'Port already occupied: {a}:{ai} <-> {b}:{bi}')
        api.call('POST', base + '/links', {'nodes': [ea, eb]})
        used.update({ep_key(ea), ep_key(eb)})
        print(f'Created: {a}:{ai} <-> {b}:{bi}')
    return get_nodes(api, base)


def running_stanza(config, command_header):
    lines = config.replace('\r', '').splitlines()
    found = False
    result = []
    for line in lines:
        if line.strip() == command_header:
            found = True
            continue
        if found:
            if line.startswith('!') or (line and not line.startswith(' ')):
                break
            result.append(line.strip())
    return result if found else None


def preflight_config(running, name, c, role):
    # Permit empty or partially applied *matching* configuration, reject conflicting features.
    iface_name = c['pe_interface'] if role == 'pe' else c['ce_interface']
    expected_ip = c['pe_ip'] if role == 'pe' else c['ce_ip']
    stanza = running_stanza(running, f'interface {iface_name}')
    if stanza is None:
        raise RuntimeError(f'{name}: {iface_name} is missing from running configuration')
    addresses = [line for line in stanza if line.startswith('ip address ')]
    if any(line != f"ip address {expected_ip} {c['mask']}" for line in addresses):
        raise RuntimeError(f'{name}: {iface_name} contains unexpected IP configuration: {addresses}')
    expected_vrf = ('ip vrf forwarding ' + c['vrf']) if role == 'pe' else None
    vrf_lines = [line for line in stanza if line.startswith(('ip vrf forwarding ', 'vrf forwarding '))]
    if vrf_lines and (role != 'pe' or any(line != expected_vrf for line in vrf_lines)):
        raise RuntimeError(f'{name}: {iface_name} has conflicting VRF configuration: {vrf_lines}')
    if any(line.startswith('encapsulation dot1Q') for line in stanza):
        raise RuntimeError(f'{name}: {iface_name} contains an 802.1Q configuration; refusing overwrite')
    if role == 'pe':
        vrf = running_stanza(running, f"ip vrf {c['vrf']}")
        if vrf is not None:
            required = {'rd ' + c['rd'], 'route-target export ' + c['rt'], 'route-target import ' + c['rt']}
            existing = [l for l in vrf if l.startswith(('rd ', 'route-target '))]
            if any(line not in required for line in existing):
                raise RuntimeError(f'{name}: existing {c["vrf"]} VRF has incompatible RD/RT: {existing}')
    else:
        loop = running_stanza(running, 'interface Loopback10')
        # Loopback10 does not exist yet on a freshly booted CE.
        addresses = [line for line in (loop or []) if line.startswith('ip address ')]
        if any(line != f"ip address {c['lan_ip']} 255.255.255.0" for line in addresses):
            raise RuntimeError(f'{name}: Loopback10 has unexpected existing IP configuration: {addresses}')
        match_asn = re.search(r'(?m)^router bgp\s+(\d+)\s*$', running)
        if match_asn and int(match_asn.group(1)) != c['ce_asn']:
            raise RuntimeError(f'{name}: existing BGP ASN differs from proposed {c["ce_asn"]}')
    return True


def cli_output(node, host, commands):
    tn = open_console(console_host(node, host), node['console'])
    try:
        return {cmd: command(tn, cmd, timeout=65) for cmd in commands}
    finally:
        tn.close()


def save_evidence(kind, outputs, summary):
    folder = BASE / 'evidence'
    folder.mkdir(exist_ok=True)
    stamp = utc_stamp()
    rawfile = folder / f'{stamp}_{kind}.txt'
    lines = []
    for device, responses in outputs.items():
        for cli, output in responses.items():
            lines.append(f'\n\n===== {datetime.now(timezone.utc).isoformat()} :: {device} :: {cli} =====\n{output}')
    rawfile.write_text(''.join(lines), encoding='utf-8')
    jsonfile = folder / f'{stamp}_{kind}.json'
    jsonfile.write_text(json.dumps({'created_utc': datetime.now(timezone.utc).isoformat(), 'type': kind, **summary}, indent=2) + '\n', encoding='utf-8')
    print(f'Evidence: {rawfile.relative_to(BASE)}, {jsonfile.relative_to(BASE)}')


def deploy_one(node, host, name, c, role):
    tn = open_console(console_host(node, host), node['console'])
    try:
        running = command(tn, 'show running-config', timeout=100)
        preflight_config(running, name, c, role)
        private = BASE / 'evidence' / 'prechange'
        private.mkdir(parents=True, exist_ok=True)
        (private / f'{utc_stamp()}_{name}.txt').write_text(running, encoding='utf-8')
        rendered = (BASE / 'generated' / (name + '.cfg')).read_text(encoding='utf-8')
        instructions = [s for s in rendered.splitlines() if s.strip() and not s.lstrip().startswith('!')]
        print(f'Configuring {name}: {len(instructions)} IOS commands')
        command(tn, 'configure terminal')
        for line in instructions:
            command(tn, line, timeout=45)
        command(tn, 'end')
        command(tn, 'write memory', timeout=100)
    finally:
        tn.close()


def parse_bgp_peer(result, ip):
    for line in result.splitlines():
        cols = line.split()
        if cols and cols[0] == ip and len(cols) >= 10 and cols[-1].isdigit():
            return True
    return False


def check_ospf_neighbors(result, expected):
    peers = set(re.findall(r'(?m)^\s*(172\.20\.255\.\d+)\s+\d+\s+FULL/', result))
    return set(expected).issubset(peers)


def check_ldp_neighbors(result, expected):
    active = set()
    for block in re.split(r'(?=\s*Peer LDP Ident:)', result):
        m = re.search(r'Peer LDP Ident:\s*(172\.20\.255\.\d+):0', block)
        if m and re.search(r'State:\s*Oper\b', block):
            active.add(m.group(1))
    return set(expected).issubset(active)


def routed_prefixes(result):
    """Read installed IPv4 prefixes from IOS 15.x `show ip route` output.

    IOS displays same-length subnet groups without repeating their masks:

        10.0.0.0/24 is subnetted, 2 subnets
    B        10.10.10.0 [200/0] via ...

    In this case 10.10.10.0 is a /24. IOS also prints explicit masks in
    variably-subnetted groups. For an unmasked entry without an unambiguous
    fixed-length heading, the entry is deliberately *not* inferred.
    """
    prefixes = set()
    fixed_length = None
    header_fixed = re.compile(r'^\s*(?:\d{1,3}\.){3}\d{1,3}/(\d{1,2})\s+is subnetted,', re.I)
    header_variable = re.compile(r'^\s*(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\s+is variably subnetted,', re.I)
    route_line = re.compile(
        r'^\s*(?:B|C|R|S|O|D|L|i)(?:\s+(?:IA|E1|E2|N1|N2|EX))?\*?\s+'
        r'((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?(?=\s|$)'
    )
    for line in result.splitlines():
        group = header_fixed.match(line)
        if group:
            fixed_length = int(group.group(1))
            continue
        if header_variable.match(line):
            fixed_length = None
            continue
        matched = route_line.match(line)
        if matched:
            mask = int(matched.group(2)) if matched.group(2) else fixed_length
            if mask is not None:
                try:
                    network = ipaddress.IPv4Network(f'{matched.group(1)}/{mask}', strict=False)
                except (ValueError, ipaddress.AddressValueError):
                    continue
                prefixes.add(str(network))
    return prefixes


def ping_is_success(result):
    m = re.search(r'Success rate is\s+(\d+)\s+percent\s*\((\d+)/(\d+)\)', result)
    return bool(m and int(m.group(1)) == 100 and int(m.group(2)) == int(m.group(3)) and int(m.group(3)) > 0)


def ping_is_blocked(result):
    m = re.search(r'Success rate is\s+(\d+)\s+percent\s*\((\d+)/(\d+)\)', result)
    return bool(m and int(m.group(1)) == 0 and int(m.group(2)) == 0 and int(m.group(3)) > 0)


VERIFY_CMDS = {
    'PE1': [
        'show ip ospf neighbor', 'show mpls ldp neighbor', 'show ip route 172.20.255.2',
        'show ip bgp vpnv4 all summary', 'show ip route vrf MUNI', 'show ip route vrf UNIV',
        'show ip bgp vpnv4 all labels'
    ],
    'PE2': [
        'show ip ospf neighbor', 'show mpls ldp neighbor', 'show ip bgp vpnv4 all summary',
        'show ip route vrf MUNI', 'show ip route vrf HEALTH', 'show ip bgp vpnv4 all labels'
    ],
    'P1': ['show ip ospf neighbor', 'show mpls ldp neighbor'],
    'P2': ['show ip ospf neighbor', 'show mpls ldp neighbor'],
    'CE-MUNI-HQ': ['ping 10.11.10.1 source 10.10.10.1'],
    'CE-MUNI-BR': ['ping 10.10.10.1 source 10.11.10.1'],
    'CE-UNIV': ['show ip bgp summary', 'show ip route',
                'ping 10.10.10.1 source 10.20.10.1', 'ping 10.30.10.1 source 10.20.10.1'],
    'CE-HEALTH': ['show ip bgp summary', 'show ip route',
                  'ping 10.10.10.1 source 10.30.10.1', 'ping 10.20.10.1 source 10.30.10.1'],
}


def verify_checks(data):
    failures = []
    full = {
        'PE1': {'172.20.255.3', '172.20.255.4'},
        'PE2': {'172.20.255.3', '172.20.255.4'},
        'P1': {'172.20.255.1', '172.20.255.2'},
        'P2': {'172.20.255.1', '172.20.255.2'},
    }
    for name, peers in full.items():
        if not check_ospf_neighbors(data[name]['show ip ospf neighbor'], peers):
            failures.append(f'{name}: OSPF FULL adjacencies missing')
        if not check_ldp_neighbors(data[name]['show mpls ldp neighbor'], peers):
            failures.append(f'{name}: LDP operational adjacencies missing')
    route = data['PE1']['show ip route 172.20.255.2']
    if '172.20.0.2' not in route or 'GigabitEthernet0/0' not in route:
        failures.append('PE1: preferred path to PE2 is not through P1 (restore Phase 4 first)')
    if not parse_bgp_peer(data['PE1']['show ip bgp vpnv4 all summary'], '172.20.255.2'):
        failures.append('PE1: MP-BGP VPNv4 session missing')
    if not parse_bgp_peer(data['PE2']['show ip bgp vpnv4 all summary'], '172.20.255.1'):
        failures.append('PE2: MP-BGP VPNv4 session missing')
    for ce, pe_ip in (('CE-UNIV', '172.21.0.9'), ('CE-HEALTH', '172.21.0.13')):
        if not parse_bgp_peer(data[ce]['show ip bgp summary'], pe_ip):
            failures.append(f'{ce}: CE-to-PE eBGP session is not established')
    for pe, peer in (('PE1', '172.21.0.10'), ('PE2', '172.21.0.14')):
        if not parse_bgp_peer(data[pe]['show ip bgp vpnv4 all summary'], peer):
            failures.append(f'{pe}: customer eBGP adjacency not established')
    for pe, vrf, wanted in (('PE1', 'UNIV', '10.20.10.0/24'), ('PE2', 'HEALTH', '10.30.10.0/24')):
        text = data[pe][f'show ip route vrf {vrf}']
        routes = routed_prefixes(text)
        if wanted not in routes:
            failures.append(f'{pe} {vrf}: expected {wanted} missing from parsed VRF RIB (found: {sorted(routes)})')
        for forbidden in ('10.10.10.0/24', '10.11.10.0/24',
                          '10.20.10.0/24' if vrf == 'HEALTH' else '10.30.10.0/24'):
            if forbidden in routes:
                failures.append(f'{pe} {vrf}: foreign route leaked ({forbidden})')
        if 'Gateway of last resort is not set' not in text:
            failures.append(f'{pe} {vrf}: unexpected default route; review before relying on isolation')
    for pe in ('PE1', 'PE2'):
        routes = routed_prefixes(data[pe]['show ip route vrf MUNI'])
        if not {'10.10.10.0/24', '10.11.10.0/24'}.issubset(routes):
            failures.append(f'{pe} MUNI: previously working municipal prefixes missing from parsed VRF RIB (found: {sorted(routes)})')
        if {'10.20.10.0/24', '10.30.10.0/24'} & routes:
            failures.append(f'{pe} MUNI: customer route leak into municipality VPN')
    for ce in ('CE-MUNI-HQ', 'CE-MUNI-BR'):
        ping = next(x for cmd, x in data[ce].items() if cmd.startswith('ping '))
        if not ping_is_success(ping):
            failures.append(f'{ce}: working municipality VPN connectivity regressed')
    for ce in ('CE-UNIV', 'CE-HEALTH'):
        routes = routed_prefixes(data[ce]['show ip route'])
        if {'10.10.10.0/24', '10.11.10.0/24',
            '10.20.10.0/24' if ce == 'CE-HEALTH' else '10.30.10.0/24'} & routes:
            failures.append(f'{ce}: unexpected foreign customer route learned')
        for cmd, output in data[ce].items():
            if cmd.startswith('ping ') and not ping_is_blocked(output):
                failures.append(f'{ce}: cross-customer isolation probe was not explicitly 0/5: {cmd}')
    return failures


def verify(nodes, host, timeout=150):
    if any(n['status'] != 'started' for n in nodes.values()):
        raise RuntimeError('All eight routers must be started for Phase 5 verification')
    start = time.monotonic()
    attempts = 0
    last_data, last_failures = {}, []
    while True:
        attempts += 1
        outputs = {}
        for name, cmds in VERIFY_CMDS.items():
            print(f'Collecting {name} verification commands ...')
            outputs[name] = cli_output(nodes[name], host, cmds)
        failures = verify_checks(outputs)
        last_data, last_failures = outputs, failures
        if not failures:
            break
        elapsed = time.monotonic() - start
        print(f'Validation attempt {attempts}: {len(failures)} issue(s), elapsed {elapsed:.1f}s')
        if elapsed >= timeout:
            break
        time.sleep(min(10, max(1, timeout - elapsed)))
    save_evidence('phase5_verification', last_data,
                  {'passed': not last_failures, 'attempts': attempts, 'failures': last_failures,
                   'note': 'Isolation tests verify current route state and failed ICMP probes only; not a firewall certification.'})
    if last_failures:
        for failure in last_failures:
            print('FAIL:', failure)
        raise RuntimeError(f'Phase 5 validation failed: {len(last_failures)} issue(s); see evidence folder')
    print('PASS: redundant OSPF/LDP; VPNv4; UNIV/HEALTH eBGP and VRF routes;')
    print('      MUNI site-to-site pings; absent cross-customer routes; four blocked CE ICMP probes')


def precheck_existing(nodes, host):
    """Do not change provider infrastructure if existing municipality service is already broken."""
    for ce, command_text in (('CE-MUNI-HQ', 'ping 10.11.10.1 source 10.10.10.1'),
                             ('CE-MUNI-BR', 'ping 10.10.10.1 source 10.11.10.1')):
        ping = cli_output(nodes[ce], host, [command_text])[command_text]
        if not ping_is_success(ping):
            raise RuntimeError(f'{ce}: municipal VPN baseline failed; fix Phase 4 before applying Phase 5')
    route = cli_output(nodes['PE1'], host, ['show ip route 172.20.255.2'])['show ip route 172.20.255.2']
    if '172.20.0.2' not in route:
        raise RuntimeError('PE1 is not using preferred P1 core path; restore Phase 4 first')
    print('Baseline passed: municipal pings and preferred backbone path')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--build', action='store_true', help='Create two CE nodes/links only')
    group.add_argument('--apply', action='store_true', help='Build and apply additive customer configuration')
    group.add_argument('--verify', action='store_true', help='Read-only verification and evidence generation')
    parser.add_argument('--timeout', type=int, default=150, help='Verification convergence-polling timeout, 30–600 sec')
    parser.add_argument('--url', default='http://127.0.0.1:3080', help='Windows local GNS3 controller URL')
    parser.add_argument('--user', default='admin', help='GNS3 controller username')
    args = parser.parse_args()
    if not 30 <= args.timeout <= 600:
        raise ValueError('--timeout must be between 30 and 600 seconds')
    inv = yaml.safe_load((BASE / 'inventory.yaml').read_text(encoding='utf-8'))
    inv['project'] = os.environ.get('NORDNET_TARGET_PROJECT', 'NORDNET-Core-POC')
    validate_inventory(inv)
    render(inv)
    if not (args.build or args.apply or args.verify):
        print('Render-only: no GNS3 connection and no router changes. Review generated/*.cfg first.')
        return
    if (args.apply or args.verify) and sys.version_info[:2] != (3, 12):
        raise RuntimeError('Cisco Telnet console support requires Python 3.12; use py -3.12')
    api = GNS3(args.url, args.user, getpass('GNS3 controller API password: '))
    print('GNS3:', api.call('GET', '/v2/version').get('version'))
    base, vm_host = project(api, inv)
    nodes = build(api, base, inv, change_allowed=args.apply or args.build)
    if args.build:
        print('Phase 5 topology ready: two new customer CEs, two links, zero IOS changes.')
        return
    if args.apply:
        if any(nodes[n]['status'] != 'started' for n in BASE_NODES):
            raise RuntimeError('All six Phase 4 routers must be running before Phase 5 deployment')
        precheck_existing(nodes, vm_host)
        for c in inv['customers'].values():
            if nodes[c['ce']]['status'] != 'started':
                print(f"Starting {c['ce']} ...")
                api.call('POST', base + f"/nodes/{nodes[c['ce']]['node_id']}/start", {})
        nodes = get_nodes(api, base)
        for c in inv['customers'].values():
            print(f"Applying {c['vrf']} customer service on {c['pe']} ...")
            deploy_one(nodes[c['pe']], vm_host, c['pe'], c, role='pe')
        for c in inv['customers'].values():
            print(f"Applying config on {c['ce']} ...")
            deploy_one(nodes[c['ce']], vm_host, c['ce'], c, role='ce')
        print('Phase 5 configured. Run --verify to capture routing and isolation evidence.')
    elif args.verify:
        verify(nodes, vm_host, timeout=args.timeout)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, AssertionError, requests.RequestException, KeyboardInterrupt) as exc:
        print('ERROR:', exc, file=sys.stderr)
        sys.exit(1)
