#!/usr/bin/env python3
"""NORDNET v0.7 persistence audit. STRICTLY READ-ONLY, no repair mode.

Place beside nordnet_local.py, nordnet_enterprise.py, nordnet_recover.py,
ios_console.py and inventory.yaml. Requires Python 3.12 for telnetlib.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from getpass import getpass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

import requests
import yaml
import nordnet_local as local
import nordnet_enterprise as enterprise
import nordnet_recover as recovery

BASE = Path(__file__).resolve().parent
IOS = ('PE1', 'PE2', 'P1', 'P2', 'CE-MUNI-HQ', 'CE-MUNI-BR',
       'CE-UNIV', 'CE-HEALTH', 'SW-MUNI-HQ', 'SW-MUNI-BR')
DHCP = {'PC-HQ-DHCP': ('10.10.10.0/24', '10.10.10.1'),
        'PC-BR-DHCP': ('10.11.10.0/24', '10.11.10.1')}


def v07_markers():
    m = recovery.expected_markers()
    extra = {
      'SW-MUNI-HQ': ['interface GigabitEthernet1/0', 'description LOCAL_SHARED_SERVICES_NO_NAT',
                     'interface GigabitEthernet1/1', 'description DHCP_TEST_HQ',
                     'logging host 10.10.30.250'],
      'SW-MUNI-BR': ['interface GigabitEthernet0/3', 'description DHCP_TEST_BR',
                     'logging host 10.10.30.250'],
      'CE-MUNI-HQ': ['ip dhcp excluded-address 10.10.30.250',
                     'ip dhcp pool NORDNET-HQ-STAFF', 'ip dhcp pool NORDNET-HQ-ADMIN',
                     'ip dhcp pool NORDNET-HQ-SERVICES', 'logging host 10.10.30.250'],
      'CE-MUNI-BR': ['ip dhcp pool NORDNET-BR-STAFF',
                     'ip dhcp pool NORDNET-BR-SERVICES', 'logging host 10.10.30.250'],
      'CE-UNIV': ['interface GigabitEthernet0/2',
                   'ip address 10.20.254.1 255.255.255.252',
                   'ip route 10.10.30.250 255.255.255.255 10.20.254.2',
                   'ip dhcp pool NORDNET-UNIV-RESEARCH', 'logging host 10.10.30.250'],
      'CE-HEALTH': ['interface GigabitEthernet0/2',
                     'ip address 10.30.254.1 255.255.255.252',
                     'ip route 10.10.30.250 255.255.255.255 10.30.254.2',
                     'ip dhcp pool NORDNET-HEALTH-LAB', 'logging host 10.10.30.250'],
      'P1': ['router ospf 100'],
      'P2': ['router ospf 100'],
    }
    for name in IOS:
        m.setdefault(name, []).insert(0, 'hostname '+name)
        m[name].extend(extra.get(name, []))
    return m


def configured_body(text):
    """Omit show-command header and timestamps, retain the actual IOS config."""
    lines = [x.strip() for x in text.replace('\r', '').splitlines()]
    start = next((i for i, x in enumerate(lines) if re.fullmatch(r'version\s+\S+', x)), None)
    if start is None:
        return None
    end = next((i for i in range(start, len(lines)) if lines[i] == 'end'), None)
    if end is None:
        return None
    return '\n'.join(x for x in lines[start:end+1]
                     if not re.match(r'^!\s*(?:Last configuration change|NVRAM config last updated)', x))


def check_ios(run, startup, marks):
    rm = recovery.missing_markers(run, marks)
    sm = recovery.missing_markers(startup, marks)
    rb, sb = configured_body(run), configured_body(startup)
    if rb is None or sb is None:
        equal = None
    else:
        equal = rb == sb
    status = ('FAIL' if rm or sm or equal is None else 'WARN' if not equal else 'PASS')
    return {'status': status, 'missing_running': rm, 'missing_startup': sm,
            'running_equals_startup_normalized': equal,
            'running_sha256': hashlib.sha256(rb.encode()).hexdigest() if rb is not None else None,
            'startup_sha256': hashlib.sha256(sb.encode()).hexdigest() if sb is not None else None}


def check_dhcp_vpcs(output, cidr, gateway):
    # Parse the address token without treating gateway/DNS address as the assigned IP.
    # VPCS 'show ip' commonly uses 'IP/MASK : 10.10.10.100/24'.
    match = re.search(r'(?im)^\s*(?:IP/MASK|IP ADDRESS|IP)\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?', output)
    if not match:
        return {'status': 'FAIL', 'reason': 'No VPCS IP address in show ip'}
    try:
        address = ipaddress.ip_address(match.group(1))
        subnet = ipaddress.ip_network(cidr)
    except ValueError:
        return {'status': 'FAIL', 'reason': 'Invalid VPCS address'}
    # Gateway must be present as the Gateway field, not merely a DHCP server or DNS entry.
    gw = re.search(r'(?im)^\s*(?:GATEWAY|GATEWAY IP)\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})', output)
    correct = address in subnet and address != subnet.network_address and address != subnet.broadcast_address and gw is not None and gw.group(1) == gateway
    return {'status': 'PASS' if correct else 'FAIL', 'ip': str(address),
            'gateway': gw.group(1) if gw else None, 'expected_subnet': cidr}


def topology_report(api, path, nodes, inv):
    base = set(local.ROUTERS) | set(local.SWITCHES) | {x['name'] for x in inv['endpoints']}
    required = base | set(enterprise.NODES)
    missing = sorted(required - nodes.keys())
    unexpected = sorted(nodes.keys() - required)
    links = api.call('GET', path+'/links')
    actual = {frozenset(local.epkey(e) for e in link['nodes']) for link in links}
    issues = []
    for link in local.desired_links(inv) + list(enterprise.LINKS):
        if link[0] not in nodes or link[2] not in nodes:
            continue
        try:
            a, ai, b, bi = link
            key = frozenset((local.epkey(enterprise.port(nodes[a], ai)),
                             local.epkey(enterprise.port(nodes[b], bi))))
            if key not in actual:
                issues.append('Missing link: '+a+' '+str(ai)+' -> '+b+' '+str(bi))
        except (KeyError, ValueError, RuntimeError) as exc:
            issues.append('Port resolution error: '+str(exc))
    service = nodes.get(enterprise.SERVICE)
    service_type = service.get('node_type') if service else None
    service_compute = service.get('compute_id') if service else None
    service_image = service.get('properties', {}).get('image') if service else None
    if service and (service_type != 'docker' or service_compute != 'vm' or service_image != enterprise.IMAGE):
        issues.append('Service node Docker type / image / compute changed')
    if missing:
        issues.append('Required nodes missing: '+', '.join(missing))
    return {'required_nodes': len(required), 'present_required_nodes': len(required)-len(missing),
            'unexpected_nodes': unexpected, 'links_checked': len(local.desired_links(inv))+len(enterprise.LINKS),
            'missing_or_invalid_links': issues,
            'service_node_api_status': service.get('status') if service else None,
            'status': 'PASS' if not issues else 'FAIL'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-id', required=True, help='Exact UUID from the OPEN main NORDNET project')
    parser.add_argument('--url', default='http://127.0.0.1:3080')
    parser.add_argument('--user', default='admin')
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError('Use py -3.12 (the existing IOS console helper requires Python 3.12)')
    inv = yaml.safe_load((BASE/'inventory.yaml').read_text(encoding='utf-8'))
    local.validate(inv)
    api = local.GNS(args.url, args.user, getpass('GNS3 API password: '))
    path, actual_id, vm = recovery.active_project(api, inv)
    if args.project_id.lower() != actual_id.lower():
        raise RuntimeError('Wrong GNS3 project UUID; no audit performed')
    print('OPEN GNS3 PROJECT UUID:', actual_id)
    nodes = local.get_nodes(api, path)
    topology = topology_report(api, path, nodes, inv)
    print('Topology:',topology['status'],'required nodes',topology['present_required_nodes'],'/',topology['required_nodes'],'links checked',topology['links_checked'])
    for issue in topology['missing_or_invalid_links']:
        print(' ',issue)
    if topology['status'] != 'PASS':
        raise RuntimeError('Required v0.7 topology is not complete; inspect without repair')
    markers = v07_markers()
    report = {'version':'0.7.4', 'read_only': True, 'project_id': actual_id,
              'created_utc': datetime.now(timezone.utc).isoformat(),
              'topology': topology, 'ios': {}, 'vpcs': {},
              'limitations': ['No nodes are rebooted; this is not a cold-start test.',
                              'VPCS show ip confirms current settings, not startup script persistence.',
                              'Docker service API state is not an application-level health check.',
                              'Config marker checks are not a complete security configuration audit.']}
    for name in IOS:
        if name not in nodes:
            continue
        print('Auditing IOS:',name,flush=True)
        run, start = recovery.snapshot_ios(nodes[name], vm['host'])
        result = check_ios(run, start, markers[name])
        report['ios'][name] = result
        print(' ',result['status'], 'missing running=',len(result['missing_running']),
              'startup=',len(result['missing_startup']),
              'normalized config match=',result['running_equals_startup_normalized'])
    for ep in inv['endpoints']:
        name=ep['name']
        print('Auditing VPCS:',name,flush=True)
        output = local.vpcs_commands(nodes[name],vm['host'],['show ip'])['show ip']
        result = {'status': 'PASS' if ep['ip'] in output and ep['gateway'] in output else 'FAIL',
                  'expected_ip': ep['ip'], 'expected_gateway': ep['gateway']}
        report['vpcs'][name] = result
        print(' ',result['status'])
    for name, (cidr, gateway) in DHCP.items():
        print('Auditing DHCP VPCS:',name,flush=True)
        output = local.vpcs_commands(nodes[name],vm['host'],['show ip'])['show ip']
        result = check_dhcp_vpcs(output, cidr, gateway)
        report['vpcs'][name] = result
        print(' ',result['status'],result.get('ip','(no IP)'))
    output_dir = BASE/'evidence'/'enterprise_audit'
    output_dir.mkdir(parents=True,exist_ok=True)
    filename = output_dir/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_audit.json')
    report['result'] = ('PASS' if topology['status'] == 'PASS'
                        and all(v['status']=='PASS' for v in report['ios'].values())
                        and all(v['status']=='PASS' for v in report['vpcs'].values())
                        else 'ATTENTION')
    filename.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('Evidence:',filename)
    print('AUDIT RESULT:',report['result'])
    print('No GNS3 configuration or state was changed.')
    if report['result'] != 'PASS':
        raise RuntimeError('Audit issues detected; do not run old v0.6.2 --repair')

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, requests.RequestException, TimeoutError, EOFError, KeyboardInterrupt) as exc:
        print('ERROR:',str(exc),file=sys.stderr)
        sys.exit(1)
