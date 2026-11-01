#!/usr/bin/env python3
"""NORDNET Phase 6.2 recovery utility for an existing Phase 6.1 GNS3 lab.

Audit by default; apply only with explicit project UUID and maintenance consent.
Never starts nodes, creates links, or changes OSPF/MPLS/MP-BGP/VRFs.
Run with Python 3.12 alongside nordnet_local.py, ios_console.py and inventory.yaml.
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

import requests
import yaml
import nordnet_local as old
from ios_console import command, console_host, open_console

ROOT = Path(__file__).resolve().parent
IOS_DEVICES = ('SW-MUNI-HQ','SW-MUNI-BR','CE-MUNI-HQ','CE-MUNI-BR',
               'CE-UNIV','CE-HEALTH','PE1','PE2')
CORE = ('P1','P2')


def expected_markers():
    return {
      'SW-MUNI-HQ': ['vlan 10','vlan 20','vlan 30','vlan 99',
                     'switchport trunk encapsulation dot1q','switchport mode trunk',
                     'switchport trunk allowed vlan 10,20,30,99',
                     'switchport access vlan 10','switchport access vlan 20',
                     'switchport access vlan 30'],
      'SW-MUNI-BR': ['vlan 10','vlan 20','vlan 99',
                     'switchport trunk encapsulation dot1q','switchport mode trunk',
                     'switchport trunk allowed vlan 10,20,99',
                     'switchport access vlan 10','switchport access vlan 20'],
      'CE-MUNI-HQ': ['interface GigabitEthernet0/1.10','interface GigabitEthernet0/1.20',
                     'interface GigabitEthernet0/1.30','interface GigabitEthernet0/1.99',
                     'ip address 10.10.10.1 255.255.255.0','ip address 10.10.20.1 255.255.255.0',
                     'ip address 10.10.30.1 255.255.255.0',
                     'network 10.10.20.0 mask 255.255.255.0',
                     'network 10.10.30.0 mask 255.255.255.0',
                     'ip prefix-list PL-CE-HQ-OUT seq 15 permit 10.10.30.0/24'],
      'CE-MUNI-BR': ['interface GigabitEthernet0/1.10','interface GigabitEthernet0/1.20',
                    'interface GigabitEthernet0/1.99',
                    'ip address 10.11.10.1 255.255.255.0','ip address 10.11.20.1 255.255.255.0',
                    'network 10.11.20.0 mask 255.255.255.0',
                    'ip prefix-list PL-CE-BR-OUT seq 10 permit 10.11.20.0/24'],
      'CE-UNIV': ['interface GigabitEthernet0/1', 'ip address 10.20.10.1 255.255.255.0'],
      'CE-HEALTH': ['interface GigabitEthernet0/1','ip address 10.30.10.1 255.255.255.0'],
      'PE1': ['ip prefix-list PL-MUNI-HQ seq 10 permit 10.10.20.0/24',
              'ip prefix-list PL-MUNI-HQ seq 15 permit 10.10.30.0/24'],
      'PE2': ['ip prefix-list PL-MUNI-BR seq 10 permit 10.11.20.0/24'],
    }


def missing_markers(config: str, markers: list[str]):
    lines={line.strip() for line in config.replace('\r','').splitlines()}
    return [marker for marker in markers if marker not in lines]


def choose_action(running_missing, startup_missing):
    if running_missing: return 'REAPPLY_PHASE61'
    if startup_missing: return 'SAVE_ONLY'
    return 'OK'


def is_safe_generated(name, cfg):
    """Allowlisted Phase6.1 commands. Extra lines are a hard failure."""
    if name not in IOS_DEVICES: return False
    for raw in cfg.splitlines():
        line=raw.strip()
        if not line or line.startswith('!'): continue
        if name.startswith('PE'):
            if not (re.fullmatch(r'ip prefix-list PL-MUNI-(?:HQ|BR) seq \d+ permit 10\.(?:10|11)\.\d+\.0/24',line)
                    or line.startswith('service timestamps log ') or line.startswith('logging buffered ')):
                return False
        elif name.startswith('SW'):
            if not (re.fullmatch(r'(?:hostname|description|name) [A-Za-z0-9_-]+',line)
                    or re.fullmatch(r'vlan (?:10|20|30|99)',line)
                    or re.fullmatch(r'interface (?:GigabitEthernet0/[0-3]|Vlan99)',line)
                    or line in ('no ip domain-lookup','vtp mode transparent',
                                'switchport trunk encapsulation dot1q', 'switchport mode trunk',
                                'switchport mode access','spanning-tree portfast',
                                'no shutdown','exit')
                    or re.fullmatch(r'switchport trunk allowed vlan (?:10,20,30,99|10,20,99)',line)
                    or re.fullmatch(r'switchport access vlan (?:10|20|30)',line)
                    or re.fullmatch(r'ip address 10\.(?:10|11)\.99\.2 255\.255\.255\.0',line)
                    or re.fullmatch(r'ip default-gateway 10\.(?:10|11)\.99\.1',line)
                    or line.startswith('service timestamps log ') or line.startswith('logging buffered ')):
                return False
        elif name.startswith('CE'):
            allowed=(
               line=='no interface Loopback10' or
               line=='no ip address' or line=='no shutdown' or line=='exit' or
               line.startswith('service timestamps log ') or line.startswith('logging buffered ') or
               re.fullmatch(r'interface GigabitEthernet0/1(?:\.(?:10|20|30|99))?',line) or
               re.fullmatch(r'description [A-Za-z0-9_-]+',line) or
               re.fullmatch(r'encapsulation dot1Q (?:10|20|30|99)',line) or
               re.fullmatch(r'ip address 10\.(?:10|11|20|30)\.\d+\.1 255\.255\.255\.0',line) or
               line=='ip access-group NORD-HQ-STAFF-IN in' or
               line=='ip access-list extended NORD-HQ-STAFF-IN' or
               line=='deny ip 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 log' or
               line=='permit ip any any' or
               re.fullmatch(r'ip prefix-list PL-CE-(?:HQ|BR)-(?:OUT|IN) seq \d+ permit 10\.(?:10|11)\.\d+\.0/24',line) or
               re.fullmatch(r'router bgp 6511[01]',line) or
               re.fullmatch(r'network 10\.(?:10|11)\.\d+\.0 mask 255\.255\.255\.0',line))
            if not allowed: return False
    return True


def active_project(api, inv):
    projects=[p for p in api.call('GET','/v2/projects') if p['name']==inv['project']]
    if len(projects)!=1: raise RuntimeError('Expected one NORDNET-Core-POC project name; cannot safely choose')
    p=projects[0]
    if p.get('status')!='opened': raise RuntimeError('NORDNET-Core-POC is not OPEN in GNS3; open your main project first')
    path='/v2/projects/'+p['project_id']
    cs={c['compute_id']:c for c in api.call('GET','/v2/computes')}
    vm=cs.get('vm')
    if not vm or not vm.get('connected'): raise RuntimeError('GNS3 VM compute not connected')
    return path,p['project_id'],vm


def validate_topology(api,path,nodes,inv):
    expected=set(old.ROUTERS)|set(old.SWITCHES)|{e['name'] for e in inv['endpoints']}
    if set(nodes)!=expected:
        raise RuntimeError('Unknown/missing nodes: this recovery applies ONLY to the v0.6.1 topology')
    if any(nodes[n]['status']!='started' for n in expected):
        raise RuntimeError('Not all v0.6.1 nodes started; start via GNS3 and let them boot first')
    if any(nodes[n]['compute_id']!='vm' for n in expected):
        raise RuntimeError('Unexpected compute; refusing recovery')
    present={frozenset(old.epkey(e) for e in link['nodes'])
             for link in api.call('GET',path+'/links')}
    expected_links={old.linkkey(nodes,ln) for ln in old.desired_links(inv)}
    if present!=expected_links:
        raise RuntimeError('Project wiring differs from v0.6.1; refusing recovery')


def snapshot_ios(node,host):
    tn=open_console(console_host(node,host),node['console'])
    try:
        running=command(tn,'show running-config',timeout=110)
        try:
            startup=command(tn,'show startup-config',timeout=110)
        except RuntimeError as exc:
            startup='STARTUP-READ-FAILED: '+str(exc)
        return running,startup
    finally: tn.close()


def collect(api,path,vm,nodes,inv, folder):
    folder.mkdir(parents=True,exist_ok=True)
    markers=expected_markers()
    output={'ios':{},'vpcs':{},'project':'NORDNET-Core-POC','project_id':path.rsplit('/',1)[-1]}
    for name in IOS_DEVICES:
        print('Inspecting IOS:',name,flush=True)
        run,start=snapshot_ios(nodes[name],vm['host'])
        (folder/(name+'_running.txt')).write_text(run,encoding='utf-8')
        (folder/(name+'_startup.txt')).write_text(start,encoding='utf-8')
        if not re.search(rf'(?m)^hostname {re.escape(name)}\s*$',run):
            raise RuntimeError(f'{name} console running-config hostname does not match')
        rm=missing_markers(run,markers[name])
        sm=missing_markers(start,markers[name])
        action=choose_action(rm,sm)
        output['ios'][name]={'running_missing':rm,'startup_missing':sm,'action':action}
        print(f'  {action} | missing running={len(rm)} startup={len(sm)}')
    for ep in inv['endpoints']:
        name=ep['name']
        print('Inspecting VPCS:',name,flush=True)
        out=old.vpcs_commands(nodes[name],vm['host'],['show ip'])['show ip']
        (folder/(name+'_ip.txt')).write_text(out,encoding='utf-8')
        ip_ok=ep['ip'] in out and ep['gateway'] in out
        output['vpcs'][name]={'ip_expected':ep['ip'],'gateway_expected':ep['gateway'],
                              'matches_running':ip_ok,'action':'OK' if ip_ok else 'SET_IP_AND_SAVE'}
        print('  '+('OK' if ip_ok else 'SET_IP_AND_SAVE'))
    output['_snapshot_dir']=str(folder)
    (folder/'audit.json').write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    print('Snapshots and audit:',folder)
    return output


def config_commands(name, generated):
    text=generated[name]
    if not is_safe_generated(name,text):
        raise RuntimeError(f'Generated template for {name} contains a command outside the recovery allowlist')
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('!')]


def apply_ios(node,host,name,lines, configure):
    tn=open_console(console_host(node,host),node['console'])
    try:
        if configure:
            command(tn,'configure terminal')
            try:
                for line in lines: command(tn,line,timeout=55)
            finally:
                # End config mode even if a command fails; do not save on error.
                command(tn,'end')
        # Save only after all IOS configuration commands succeeded.
        result=command(tn,'write memory',timeout=120)
        if '[OK]' not in result and 'Building configuration' not in result:
            raise RuntimeError(f'{name}: write memory success not confirmed: {result[-350:]}')
    finally: tn.close()


def check_no_unexpected_customer_addresses(name, running):
    """Do not overwrite an unrelated customer interface, subinterface or loopback IP."""
    if name not in ('CE-MUNI-HQ','CE-MUNI-BR','CE-UNIV','CE-HEALTH'):
        return
    expected={
      'CE-MUNI-HQ': {'GigabitEthernet0/1':None,'GigabitEthernet0/1.10':'10.10.10.1',
                     'GigabitEthernet0/1.20':'10.10.20.1',
                     'GigabitEthernet0/1.30':'10.10.30.1',
                     'GigabitEthernet0/1.99':'10.10.99.1', 'Loopback10':'10.10.10.1'},
      'CE-MUNI-BR': {'GigabitEthernet0/1':None,'GigabitEthernet0/1.10':'10.11.10.1',
                     'GigabitEthernet0/1.20':'10.11.20.1',
                     'GigabitEthernet0/1.99':'10.11.99.1', 'Loopback10':'10.11.10.1'},
      'CE-UNIV': {'GigabitEthernet0/1':'10.20.10.1','Loopback10':'10.20.10.1'},
      'CE-HEALTH': {'GigabitEthernet0/1':'10.30.10.1','Loopback10':'10.30.10.1'},
    }[name]
    blocks=list(re.finditer(r'(?m)^interface ([A-Za-z][^\n]*)\s*$',running))
    for i,match in enumerate(blocks):
        iface=match.group(1).strip()
        if not (iface.startswith('GigabitEthernet0/1') or iface=='Loopback10'):
            continue
        body=running[match.end():blocks[i+1].start() if i+1<len(blocks) else len(running)]
        ips=re.findall(r'(?m)^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+',body)
        if iface not in expected:
            raise RuntimeError(f'{name}: unexpected {iface}; refusing to modify CE LAN')
        permitted=expected[iface]
        if any(ip!=permitted for ip in ips):
            raise RuntimeError(f'{name}: unexpected address on {iface}: {ips!r}; refusing repair')


def repair(nodes,vm,inv,audit,generated):
    for name in IOS_DEVICES:
        item=audit['ios'][name]
        action=item['action']
        if action=='OK': continue
        if name.startswith('CE'):
            running=(Path(audit['_snapshot_dir'])/(name+'_running.txt')).read_text(encoding='utf-8')
            check_no_unexpected_customer_addresses(name,running)
        print('Recovery:',name,action,flush=True)
        apply_ios(nodes[name],vm['host'],name,config_commands(name,generated),action=='REAPPLY_PHASE61')
    for ep in inv['endpoints']:
        name=ep['name']
        if audit['vpcs'][name]['matches_running']:
            cmds=['save']  # persist already-correct running state
        else:
            cmds=[f"ip {ep['ip']}/24 {ep['gateway']}",'save']
        print('Persist VPCS:',name,flush=True)
        outputs=old.vpcs_commands(nodes[name],vm['host'],cmds)
        if 'Saving' not in outputs['save'] and 'done' not in outputs['save'].lower():
            raise RuntimeError(name+' did not confirm VPCS save: '+outputs['save'][-400:])
    print('Recovery commands submitted. Validate v0.6.1 before enterprise preflight.')


def main():
    pa=argparse.ArgumentParser(description=__doc__)
    group=pa.add_mutually_exclusive_group(required=True)
    group.add_argument('--audit',action='store_true',help='READ ONLY: inspect saved and running state')
    group.add_argument('--repair',action='store_true',help='Reapply missing v0.6.1 config and persist VPCS')
    pa.add_argument('--project-id',help='Required for --repair: exact UUID printed by --audit')
    pa.add_argument('--approve-maintenance',action='store_true')
    pa.add_argument('--url',default='http://127.0.0.1:3080')
    pa.add_argument('--user',default='admin')
    args=pa.parse_args()
    if sys.version_info[:2]!=(3,12):raise RuntimeError('Use py -3.12 for IOSv and VPCS consoles')
    if args.repair and (not args.approve_maintenance or not args.project_id):
        raise RuntimeError('--repair needs --approve-maintenance and exact --project-id copied from --audit')
    inv=yaml.safe_load((ROOT/'inventory.yaml').read_text(encoding='utf-8'))
    old.validate(inv)
    generated=old.render(inv)  # Local file generation, never GNS3 commands.
    if any(not is_safe_generated(n,generated[n]) for n in IOS_DEVICES):
        raise RuntimeError('Unexpected generated config; run no recovery operations')
    api=old.GNS(args.url,args.user,getpass('GNS3 API password: '))
    path,prid,vm=active_project(api,inv)
    print('OPEN GNS3 PROJECT UUID:',prid,flush=True)
    if args.repair and args.project_id.lower()!=prid.lower():
        raise RuntimeError('Project UUID mismatch: refusing changes to the wrong project')
    nodes=old.get_nodes(api,path)
    validate_topology(api,path,nodes,inv)
    folder=ROOT/'evidence'/'recovery'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    audit=collect(api,path,vm,nodes,inv,folder)
    if args.audit:
        print('READ-ONLY audit complete; no device or topology configurations changed.')
        return
    print('Maintenance approved: only devices identified in the audit will be adjusted.')
    repair(nodes,vm,inv,audit,generated)
    print('Run: py -3.12 .\\nordnet_local.py --verify')

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,KeyError,requests.RequestException,EOFError,TimeoutError,KeyboardInterrupt) as exc:
        print('ERROR:',exc,file=sys.stderr)
        sys.exit(1)
