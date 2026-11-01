#!/usr/bin/env python3
"""NORDNET v0.7.3: read-only DHCP diagnostics or explicit VPCS-only renewal.

Run beside nordnet_local.py and nordnet_enterprise.py in the Phase 6.1 project.
Never modifies Cisco IOS, topology, provider routers, or Docker nodes.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from getpass import getpass
import json
from pathlib import Path
import re
import sys
import time

import nordnet_local as local
import nordnet_enterprise as enterprise

PROJECT_UUID = '381c9ab5-1701-4481-a808-6d13439ddeed'
CLIENTS = {
    'PC-HQ-DHCP': {'ce': 'CE-MUNI-HQ', 'switch': 'SW-MUNI-HQ',
                   'switchport': 'GigabitEthernet1/1', 'network': '10.10.10.',
                   'gateway': '10.10.10.1', 'pool': 'NORDNET-HQ-STAFF'},
    'PC-BR-DHCP': {'ce': 'CE-MUNI-BR', 'switch': 'SW-MUNI-BR',
                   'switchport': 'GigabitEthernet0/3', 'network': '10.11.10.',
                   'gateway': '10.11.10.1', 'pool': 'NORDNET-BR-STAFF'},
}
IOS_COMMANDS = [
    'show ip dhcp pool',
    'show ip dhcp binding',
    'show ip dhcp server statistics',
    'show ip dhcp conflict',
    'show ip interface brief',
    'show running-config | include ^no service dhcp',
]
SW_COMMANDS = ['show vlan brief', 'show interfaces trunk',
               'show interfaces status', 'show spanning-tree vlan 10']


def parse_vpcs_ip(text):
    """Return IP and GW from actual `show ip` output; ignore command echo."""
    address = re.search(r'(?im)^\s*IP/MASK\s*:\s*(\d+\.\d+\.\d+\.\d+)/(\d+)', text)
    gateway = re.search(r'(?im)^\s*GATEWAY\s*:\s*(\d+\.\d+\.\d+\.\d+)', text)
    return (address.group(1) if address else None,
            int(address.group(2)) if address else None,
            gateway.group(1) if gateway else None)


def valid_lease(text, settings):
    ip, prefix, gw = parse_vpcs_ip(text)
    has_dhcp = bool(re.search(r'(?im)^\s*DHCP SERVER\s*:\s*\d+\.\d+\.\d+\.\d+', text))
    return bool(ip and ip.startswith(settings['network']) and prefix == 24
                and gw == settings['gateway'] and has_dhcp
                and int(ip.rsplit('.',1)[1]) >= 100)


def switch_access_port(text):
    """Require actual access operation, VLAN10, not merely admin intent."""
    return bool(re.search(r'(?im)^Operational Mode:\s*static access\s*$', text)
                and re.search(r'(?im)^Access Mode VLAN:\s*10\b', text))


def safe_ios(node, host, cmd):
    try:
        return {'output': local.cli(node, host, [cmd])[cmd]}
    except Exception as exc:
        return {'error': str(exc)}


def safe_vpcs(node, host, cmd):
    try:
        return {'output': local.vpcs_commands(node, host, [cmd])[cmd]}
    except Exception as exc:
        return {'error': str(exc)}


def snapshot(nodes, host):
    result = {}
    for name, settings in CLIENTS.items():
        ce = settings['ce']; sw = settings['switch']
        print('Collecting DHCP server:', ce, flush=True)
        if ce not in result:
            result[ce] = {cmd: safe_ios(nodes[ce],host,cmd) for cmd in IOS_COMMANDS}
        print('Collecting switch state:', sw, settings['switchport'], flush=True)
        if sw not in result:
            cmds=SW_COMMANDS+[f'show interfaces {settings["switchport"]} switchport']
            result[sw] = {cmd: safe_ios(nodes[sw],host,cmd) for cmd in cmds}
        print('Collecting VPCS state:',name,flush=True)
        result[name] = {'show ip': safe_vpcs(nodes[name],host,'show ip'),
                        'show arp': safe_vpcs(nodes[name],host,'show arp')}
    return result


def summarize(data):
    summary = {}
    for name, settings in CLIENTS.items():
        ce = settings['ce']; sw = settings['switch']
        client = data[name]['show ip'].get('output','')
        sw_cmd=f'show interfaces {settings["switchport"]} switchport'
        port = data[sw][sw_cmd].get('output','')
        pools = data[ce]['show ip dhcp pool'].get('output','')
        stats = data[ce]['show ip dhcp server statistics'].get('output','')
        no_service=data[ce]['show running-config | include ^no service dhcp'].get('output','')
        summary[name] = {
            'dhcp_service_explicitly_disabled': bool(re.search(r'(?im)^no service dhcp\s*$',no_service)),
            'ip_and_gateway': parse_vpcs_ip(client),
            'lease_correct': valid_lease(client,settings),
            'access_vlan10_operational': switch_access_port(port),
            'expected_pool_present': settings['pool'] in pools,
            'server_stats_received': bool(stats.strip()),
        }
        print(f'{name}: {summary[name]}')
    return summary


def renew_client(node, host, settings, attempts=2):
    """VPCS-only changes. Preserve every raw DHCP exchange for diagnosis."""
    history=[]
    initial=local.vpcs_commands(node,host,['show ip'])['show ip']
    history.append({'command':'show ip (before)', 'output':initial})
    if valid_lease(initial, settings):
        print('  Valid lease already present; no DHCP request needed')
    else:
        for index in range(1,attempts+1):
            print(f'  DHCP attempt {index}/{attempts}',flush=True)
            output=local.vpcs_commands(node,host,['ip dhcp'])['ip dhcp']
            history.append({'command':f'ip dhcp #{index}', 'output':output})
            time.sleep(3)
            current=local.vpcs_commands(node,host,['show ip'])['show ip']
            history.append({'command':f'show ip after #{index}','output':current})
            if valid_lease(current, settings):
                break
    current=local.vpcs_commands(node,host,['show ip'])['show ip']
    if not valid_lease(current,settings):
        history.append({'result':'NO_VALID_LEASE; intentionally not saved'})
        return False,history
    probe=local.vpcs_commands(node,host,['ping '+settings['gateway']])['ping '+settings['gateway']]
    history.append({'command':'ping '+settings['gateway'],'output':probe})
    if not local.vpcs_received_reply(probe):
        history.append({'result':'GATEWAY_UNREACHABLE; intentionally not saved'})
        return False,history
    saved=local.vpcs_commands(node,host,['save'])['save']
    history.append({'command':'save after verified lease','output':saved})
    print('  PASS: valid /24 lease, correct gateway, gateway responds; VPCS saved')
    return True,history


def report(folder, mode, result):
    folder.mkdir(parents=True, exist_ok=True)
    timestamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    root=folder/f'{timestamp}_dhcp_{mode}'
    (root.with_suffix('.json')).write_text(json.dumps(result,indent=2,default=str)+'\n',encoding='utf-8')
    lines=[]
    def walk(obj, indent=0):
        if isinstance(obj,dict):
            for key,value in obj.items():
                lines.append(' '*indent+str(key)+':')
                walk(value,indent+2)
        elif isinstance(obj,list):
            for value in obj: walk(value,indent+2)
        else:
            lines.append(' '*indent+str(obj))
    walk(result)
    (root.with_suffix('.txt')).write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('Evidence:', root.with_suffix('.json'))
    print('Evidence:', root.with_suffix('.txt'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--diagnose',action='store_true',help='Read-only diagnostics')
    group.add_argument('--renew',action='store_true',help='Explicitly renew only the two new VPCS clients')
    parser.add_argument('--project-id',required=True,help='UUID shown by main-project recovery audit')
    parser.add_argument('--url',default='http://127.0.0.1:3080')
    parser.add_argument('--user',default='admin')
    args=parser.parse_args()
    if sys.version_info[:2]!=(3,12):
        parser.error('Python 3.12 required by existing console scripts')
    if args.project_id != PROJECT_UUID:
        parser.error('Project UUID does not match verified NORDNET main project')
    api=local.GNS(args.url,args.user,getpass('GNS3 API password: '))
    path,vm=enterprise.connect_gns(api)
    if path.rsplit('/',1)[-1]!=args.project_id:
        raise RuntimeError('OPEN PROJECT UUID MISMATCH. Refusing to continue: '+path)
    nodes=local.get_nodes(api,path)
    enterprise.check_topology(api,path,nodes,expect_built=True)
    for name in ('PC-HQ-DHCP','PC-BR-DHCP'):
        if name not in nodes or nodes[name]['status']!='started':
            raise RuntimeError(name+' must be running')
    base=Path(__file__).resolve().parent/'evidence'/'dhcp'
    output={'project_uuid':args.project_id,'mode':'renew' if args.renew else 'diagnose',
            'timestamp_utc':datetime.now(timezone.utc).isoformat()}
    try:
        output['before']=snapshot(nodes,vm['host'])
        output['summary_before']=summarize(output['before'])
        if args.renew:
            # Do not renew if switch ports or IOS pool presence are already incorrect.
            for client, state in output['summary_before'].items():
                if (not state['access_vlan10_operational'] or not state['expected_pool_present']
                        or state['dhcp_service_explicitly_disabled']):
                    raise RuntimeError(client+': switchport, DHCP service, or pool not confirmed; renew blocked')
            output['renewal']={}
            all_ok=True
            for name,settings in CLIENTS.items():
                print('Renewing VPCS:',name)
                success,log=renew_client(nodes[name],vm['host'],settings)
                output['renewal'][name]={'passed':success,'commands':log}
                all_ok=all_ok and success
            output['after']=snapshot(nodes,vm['host'])
            output['summary_after']=summarize(output['after'])
            output['passed']=all_ok
    except Exception as exc:
        output['error']=str(exc)
        raise
    finally:
        report(base,output['mode'],output)
    if args.renew:
        if output['passed']:
            print('PASS: Both VPCS DHCP clients addressed and saved. Now run enterprise --verify, then --commit.')
        else:
            raise RuntimeError('DHCP still failing; inspect evidence without changing router configurations')
    else:
        print('READ-ONLY DHCP diagnostics complete. No VPCS or Cisco configuration changes.')

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('ERROR:',exc,file=sys.stderr)
        sys.exit(1)
