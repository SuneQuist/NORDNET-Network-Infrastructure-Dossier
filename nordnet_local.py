#!/usr/bin/env python3
"""NORDNET Local Bulk Release (offline/onsite LAN stage).

Extends the VERIFIED Phase 5 project; does not change PE/P core topology, MPLS,
VRFs, RDs/RTs, VPNv4, or CE-PE links. Build 2 IOSvL2 switches + 7 VPCS
endpoints; migrate simulated LAN loopbacks to customer ports, advertise new
municipal VLANs, verify reachability and isolation. No outside connectivity.

Use --plan first; --build only creates nodes/links; --apply requires an explicit
maintenance acknowledgement and is NOT atomic. See README for prerequisites.
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
import warnings

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from ios_console import command, console_host, open_console

BASE = Path(__file__).resolve().parent
ROUTERS = ('PE1','PE2','P1','P2','CE-MUNI-HQ','CE-MUNI-BR','CE-UNIV','CE-HEALTH')
SWITCHES = ('SW-MUNI-HQ','SW-MUNI-BR')
OLD_LINKS = [
 ('PE1','GigabitEthernet0/0','P1','GigabitEthernet0/0'),
 ('P1','GigabitEthernet0/1','PE2','GigabitEthernet0/0'),
 ('PE1','GigabitEthernet0/1','CE-MUNI-HQ','GigabitEthernet0/0'),
 ('PE2','GigabitEthernet0/1','CE-MUNI-BR','GigabitEthernet0/0'),
 ('PE1','GigabitEthernet0/2','P2','GigabitEthernet0/0'),
 ('P2','GigabitEthernet0/1','PE2','GigabitEthernet0/2'),
 ('PE1','GigabitEthernet0/3','CE-UNIV','GigabitEthernet0/0'),
 ('PE2','GigabitEthernet0/3','CE-HEALTH','GigabitEthernet0/0'),
]


def utc(): return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
def port_norm(s): return s.replace('GigabitEthernet','Gi')


def validate(inv):
    if inv.get('project') != os.environ.get('NORDNET_TARGET_PROJECT', 'NORDNET-Core-POC') or inv.get('compute') != 'vm':
        raise ValueError('Unexpected project or compute; refusing to continue')
    if set(inv['sites']) != {'HQ','BR'}: raise ValueError('Expected HQ and BR sites')
    expected_networks = {
      'HQ': {10:'10.10.10.0/24',20:'10.10.20.0/24',30:'10.10.30.0/24',99:'10.10.99.0/24'},
      'BR': {10:'10.11.10.0/24',20:'10.11.20.0/24',99:'10.11.99.0/24'},
    }
    for site, data in inv['sites'].items():
        if data['ce'] != ('CE-MUNI-HQ' if site=='HQ' else 'CE-MUNI-BR'):
            raise ValueError('Unexpected CE names')
        if data['switch'] != ('SW-MUNI-HQ' if site=='HQ' else 'SW-MUNI-BR'):
            raise ValueError('Unexpected switch names')
        nets = {v['vlan']:v['subnet'] for v in data['networks']}
        if nets != expected_networks[site]: raise ValueError(f'{site}: address plan changed')
        for v in data['networks']:
            if ipaddress.IPv4Address(v['gateway']) not in ipaddress.ip_network(v['subnet']):
                raise ValueError('Gateway outside subnet')
            if v['bgp'] != (v['vlan'] != 99):
                raise ValueError('Mgmt VLAN must not be advertised')
    endpoints = inv['endpoints']
    if len(endpoints) != 7 or len({e['name'] for e in endpoints}) != 7:
        raise ValueError('Expected seven uniquely named VPCS endpoints')
    expected_ips={'PC-HQ-STAFF':'10.10.10.10','PC-HQ-ADMIN':'10.10.20.10','PC-HQ-SVC':'10.10.30.10','PC-BR-STAFF':'10.11.10.10','PC-BR-SVC':'10.11.20.10','PC-UNIV':'10.20.10.10','PC-HEALTH':'10.30.10.10'}
    if {e['name']:e['ip'] for e in endpoints} != expected_ips:
        raise ValueError('Expected endpoint address plan not matched')
    parents=[(e['parent'], port_norm(e['port'])) for e in endpoints]
    if len(set(parents))!=len(parents): raise ValueError('Endpoint port collision')
    return True


def desired_links(inv):
    links = list(OLD_LINKS)
    for site in inv['sites'].values():
        links.append((site['ce'],site['trunk_interface'],site['switch'],site['switch_trunk']))
    for e in inv['endpoints']:
        links.append((e['parent'],e['port'],e['name'],'Ethernet0'))
    return links


def render(inv):
    env = Environment(loader=FileSystemLoader(BASE/'templates'), undefined=StrictUndefined,
                      trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    dest = BASE/'generated'; dest.mkdir(exist_ok=True)
    generated={}
    for site, v in inv['sites'].items():
        prefixes = [n['subnet'] for n in v['networks'] if n['bgp']]
        remote_site = inv['sites']['BR' if site=='HQ' else 'HQ']
        remote_prefixes=[n['subnet'] for n in remote_site['networks'] if n['bgp']]
        ce_config = env.get_template('municipal_ce.j2').render(
             site=site, ce=v['ce'], switch=v['switch'], trunk_interface=v['trunk_interface'],
             networks=v['networks'], remote_prefixes=remote_prefixes,
             asn=65110 if site=='HQ' else 65111)
        generated[v['ce']] = ce_config
        pe='PE1' if site=='HQ' else 'PE2'
        generated[pe] = env.get_template('pe_prefixes.j2').render(
             prefix_list='PL-MUNI-HQ' if site=='HQ' else 'PL-MUNI-BR', prefixes=prefixes)
        endpoints=[e for e in inv['endpoints'] if e['parent']==v['switch']]
        mgmt_ip='10.10.99.2' if site=='HQ' else '10.11.99.2'
        mgmt_gw='10.10.99.1' if site=='HQ' else '10.11.99.1'
        generated[v['switch']] = env.get_template('switch.j2').render(
            site=site, switch=v['switch'], ce=v['ce'],
            networks=v['networks'], endpoints=endpoints,
            trunk_interface=v['switch_trunk'], mgmt_ip=mgmt_ip, mgmt_gateway=mgmt_gw)
    generated['CE-UNIV'] = env.get_template('remote_ce.j2').render(site='UNIV',gateway='10.20.10.1')
    generated['CE-HEALTH'] = env.get_template('remote_ce.j2').render(site='HEALTH',gateway='10.30.10.1')
    for node, contents in generated.items():
        (dest/(node+'.cfg')).write_text(contents,encoding='utf-8')
        print('Rendered', 'generated/'+node+'.cfg')
    return generated


class GNS:
    def __init__(self, base,user,password):
        self.base=base.rstrip('/'); self.s=requests.Session(); self.s.auth=(user,password)
    def call(self,method,path,data=None):
        response=self.s.request(method,self.base+path,json=data,timeout=45)
        if not response.ok:
            raise RuntimeError(f'GNS3 {method} {path}: HTTP {response.status_code}: {response.text[:400]}')
        return response.json() if response.content else None


def connect(api,inv):
    proj=[p for p in api.call('GET','/v2/projects') if p['name']==inv['project']]
    if len(proj)!=1: raise RuntimeError(f"Expected exactly one existing project {inv['project']!r}")
    path='/v2/projects/'+proj[0]['project_id']
    if proj[0]['status']!='opened': api.call('POST',path+'/open',{})
    computes={c['compute_id']:c for c in api.call('GET','/v2/computes')}
    vm=computes.get('vm')
    if not vm or not vm.get('connected') or 'qemu' not in vm.get('capabilities',{}).get('node_types',[]):
        raise RuntimeError('GNS3 VM compute not connected or QEMU unavailable')
    return path,vm['host']


def get_nodes(api,path):
    items=api.call('GET',path+'/nodes')
    if len({n['name'] for n in items})!=len(items):
        raise RuntimeError('Duplicate GNS3 device names')
    return {n['name']:n for n in items}


def endpoint(node,iface):
    matches=[p for p in node.get('ports',[]) if port_norm(p['name'])==port_norm(iface)]
    if len(matches)!=1:
        raise RuntimeError(f"{node['name']}: missing expected port {iface}; ports={[p['name'] for p in node.get('ports',[])]}")
    p=matches[0]
    return {'node_id':node['node_id'], 'adapter_number':p['adapter_number'], 'port_number':p['port_number']}


def epkey(e): return (e['node_id'],e['adapter_number'],e['port_number'])
def linkkey(nodes,ln):
    a,ai,b,bi=ln
    return frozenset((epkey(endpoint(nodes[a],ai)),epkey(endpoint(nodes[b],bi))))

def build(api,path,inv,change_allowed=True):
    nodes=get_nodes(api,path)
    if not set(ROUTERS).issubset(nodes): raise RuntimeError('Existing Phase 5 routers missing')
    allowed=set(ROUTERS)|set(SWITCHES)|{e['name'] for e in inv['endpoints']}
    if set(nodes)-allowed: raise RuntimeError('Unrecognised existing devices in project; refusing changes')
    for name in ROUTERS:
        if nodes[name]['node_type']!='qemu' or nodes[name]['compute_id']!='vm':
            raise RuntimeError(f'{name} not on correct compute')
    # Existing topology must be intact. No new node created before this check.
    actual={frozenset(epkey(e) for e in l['nodes']) for l in api.call('GET',path+'/links')}
    if not {linkkey(nodes,ln) for ln in OLD_LINKS}.issubset(actual):
        raise RuntimeError('A pre-existing core/CE link is missing or changed')
    for name,site in inv['sites'].items():
        sw=site['switch']; endpoint(nodes[site['ce']],site['trunk_interface'])
        if sw not in nodes:
            if not change_allowed: raise RuntimeError(f'Missing {sw}; run --build first')
            templates=[t for t in api.call('GET','/v2/templates') if t['name']==inv['switch_template'] and t['template_type']=='qemu']
            if len(templates)!=1 or templates[0].get('compute_id') not in (None,'vm'):
                raise RuntimeError('IOSvL2 template not uniquely available on vm')
            x,y=inv['switch_positions'][sw]
            print('Creating switch:',sw)
            api.call('POST',path+'/templates/'+templates[0]['template_id'], {'name':sw,'compute_id':'vm','x':x,'y':y})
    nodes=get_nodes(api,path)
    for ep in inv['endpoints']:
        if ep['name'] not in nodes:
            if not change_allowed: raise RuntimeError(f'Missing {ep["name"]}; run --build first')
            script=f"ip {ep['ip']}/24 {ep['gateway']}\n"
            print('Creating VPCS:',ep['name'])
            api.call('POST',path+'/nodes', {'compute_id':'vm','name':ep['name'],'node_type':'vpcs',
                    'x':ep['x'],'y':ep['y'], 'properties':{'startup_script':script}})
    nodes=get_nodes(api,path)
    if set(nodes)!=allowed: raise RuntimeError('Unexpected device set after build')
    for name in SWITCHES:
        if nodes[name]['node_type']!='qemu' or nodes[name]['compute_id']!='vm': raise RuntimeError('Switch appliance wrong type/compute')
    for e in inv['endpoints']:
        if nodes[e['name']]['node_type']!='vpcs' or nodes[e['name']]['compute_id']!='vm':
            raise RuntimeError('VPCS node wrong type/compute')
    current={frozenset(epkey(e) for e in l['nodes']) for l in api.call('GET',path+'/links')}
    expected={linkkey(nodes,ln) for ln in desired_links(inv)}
    if current-expected: raise RuntimeError('Unexpected links, refusing wiring modifications')
    used=set().union(*current) if current else set()
    for ln in desired_links(inv)[len(OLD_LINKS):]:
        key=linkkey(nodes,ln)
        if key in current: continue
        if not change_allowed: raise RuntimeError('Missing link; run --build before --verify')
        a,ai,b,bi=ln
        ep1,ep2=endpoint(nodes[a],ai),endpoint(nodes[b],bi)
        if epkey(ep1) in used or epkey(ep2) in used:
            raise RuntimeError('Interface already occupied: '+str(ln))
        api.call('POST',path+'/links',{'nodes':[ep1,ep2]})
        used.update((epkey(ep1),epkey(ep2)))
        print('Connected',a,ai,'<->',b,bi)
    return get_nodes(api,path)


def evidence(label,data):
    folder=BASE/'evidence';folder.mkdir(exist_ok=True)
    f=folder/(utc()+'_'+label+'.json'); f.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
    print('Evidence:',f)


def cli(node,host,commands):
    tn=open_console(console_host(node,host),node['console'])
    try: return {c:command(tn,c,timeout=75) for c in commands}
    finally:tn.close()


def check_base(nodes,host):
    for ce,command_text in [('CE-MUNI-HQ','ping 10.11.10.1 source 10.10.10.1'),
                            ('CE-MUNI-BR','ping 10.10.10.1 source 10.11.10.1')]:
        response=cli(nodes[ce],host,[command_text])[command_text]
        if 'Success rate is 100 percent (5/5)' not in response:
            raise RuntimeError(f'{ce}: previous municipality VPN already degraded. Restore before applying.')
    print('Original municipality VPN baseline verified')


def preflight_ios(name,running):
    # Do not silently replace loopbacks/subinterface addresses in an unfamiliar configuration.
    match=re.search(r'(?ms)^interface Loopback10\s*\n(.*?)(?=^!|^interface |\Z)',running)
    loop=match.group(1) if match else ''
    if name in ('CE-MUNI-HQ','CE-MUNI-BR','CE-UNIV','CE-HEALTH') and loop:
        expected={'CE-MUNI-HQ':'10.10.10.1','CE-MUNI-BR':'10.11.10.1',
                  'CE-UNIV':'10.20.10.1','CE-HEALTH':'10.30.10.1'}[name]
        if f'ip address {expected} 255.255.255.0' not in loop:
            raise RuntimeError(f'{name} Loopback10 does not match Phase 5; refusing migration')
    # Check no wrong IP already on relevant CE LAN interfaces.
    if name in ('CE-UNIV','CE-HEALTH'):
        ifaces=['GigabitEthernet0/1']
    elif name in ('CE-MUNI-HQ','CE-MUNI-BR'):
        ifaces=['GigabitEthernet0/1']
    else: ifaces=[]
    for iface in ifaces:
        m=re.search(rf'(?ms)^interface {re.escape(iface)}\s*\n(.*?)(?=^!|^interface |\Z)',running)
        if m and re.search(r'(?m)^ ip address ',m.group(1)):
            raise RuntimeError(f'{name}: physical {iface} already has IP, cannot convert to customer LAN')


def push(node,host,name):
    tn=open_console(console_host(node,host),node['console'])
    try:
        running=command(tn,'show running-config',timeout=110)
        preflight_ios(name,running)
        backups=BASE/'evidence'/'prechange';backups.mkdir(parents=True,exist_ok=True)
        (backups/f'{utc()}_{name}.txt').write_text(running,encoding='utf-8')
        text=(BASE/'generated'/(name+'.cfg')).read_text(encoding='utf-8')
        commands=[line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('!')]
        print(f'Applying {name}: {len(commands)} IOS commands')
        command(tn,'configure terminal')
        for line in commands: command(tn,line,timeout=55)
        command(tn,'end')
        command(tn,'write memory',timeout=100)
    finally:tn.close()


def vpcs_commands(node,host,commands):
    if sys.version_info[:2]!=(3,12): raise RuntimeError('VPCS console transport requires Python 3.12')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',DeprecationWarning)
        import telnetlib
    address=console_host(node,host)
    tn=telnetlib.Telnet(address,int(node['console']),timeout=10)
    try:
        results={}
        tn.write(b'\r\n')
        initial=tn.read_until(b'>',timeout=25)
        if not initial.endswith(b'>'):
            raise RuntimeError(f'VPCS {node["name"]} prompt not ready')
        for cmd in commands:
            tn.write(cmd.encode('ascii')+b'\r\n')
            data=tn.read_until(b'>',timeout=25).decode('utf-8',errors='replace')
            if not data.rstrip().endswith('>'):
                raise RuntimeError(f'VPCS {node["name"]} timed out running {cmd!r}: {data[-160:]}')
            results[cmd]=data
        return results
    finally:tn.close()


def check_vpcs(nodes,host,inv):
    for ep in inv['endpoints']:
        n=nodes[ep['name']]
        out=vpcs_commands(n,host,[f"ip {ep['ip']}/24 {ep['gateway']}", 'save'])
        if any('Invalid' in value or 'Unknown command' in value for value in out.values()):
            raise RuntimeError(f"{ep['name']}: VPCS rejected IP setup")
        print('VPCS addressed:',ep['name'])


def ios_ping_count(output):
    """Return (received, sent) from Cisco IOS extended ping output, or None."""
    match = re.search(r"Success rate is\s+\d+\s+percent\s*\((\d+)\s*/\s*(\d+)\)", output, re.I)
    return (int(match.group(1)), int(match.group(2))) if match else None


def ping_reachable(output, min_replies=4):
    """Accept one first-packet ARP loss in a five-echo IOS test."""
    value = ios_ping_count(output)
    return value is not None and value[1] == 5 and value[0] >= min_replies


def ping_blocked(output):
    """An isolation test passes only if all five echoes were unanswered."""
    return ios_ping_count(output) == (0, 5)


def vpcs_received_reply(text):
    # VPCS normally emits '84 bytes from <ip> ... ttl=...'.
    # Match the entire reply line, not a summary or a command prompt.
    return bool(re.search(r"(?im)^\s*\d+\s+bytes from\s+\d+\.\d+\.\d+\.\d+\b", text))


def trunk_state(output, interface, required_vlans):
    """Verify actual trunk status and active VLANs; don't confuse admin and operational mode.

    IOSvL2 can report STP forwarding VLANs as 'none' during convergence.
    Actual reachability is separately checked by ICMP rather than inferred
    solely from this diagnostic text.
    """
    iface = port_norm(interface)
    rows = output.splitlines()
    operational = any(re.match(
        rf"^\s*{re.escape(iface)}\s+\S+\s+\S+\s+trunking\s+\d+\s*$", row, re.I
    ) for row in rows)
    if not operational:
        return False, f'{iface} is not operationally trunking (802.1Q)'
    try:
        marker = next(i for i, row in enumerate(rows)
                      if 'Vlans allowed and active in management domain' in row)
    except StopIteration:
        return False, f'{iface}: missing active-VLAN section in show interfaces trunk'
    active = set()
    for row in rows[marker+1:]:
        if row.strip().lower().startswith('port'):
            break
        columns = row.strip().split()
        if len(columns) >= 2 and columns[0].lower() == iface.lower():
            for item in ','.join(columns[1:]).split(','):
                if item.isdecimal():
                    active.add(int(item))
                elif '-' in item:
                    left, sep, right = item.partition('-')
                    if left.isdecimal() and right.isdecimal():
                        active.update(range(int(left), int(right)+1))
            break
    missing = set(required_vlans) - active
    if missing:
        return False, f'{iface}: missing active VLANs {sorted(missing)} (active: {sorted(active)})'
    return True, f'{iface} operational trunk, VLANs {sorted(active)} active'


def verify(nodes,host,inv):
    out={}
    for name in ('PE1','PE2','CE-MUNI-HQ','CE-MUNI-BR','CE-UNIV','CE-HEALTH','SW-MUNI-HQ','SW-MUNI-BR'):
        cmds={'PE1':['show ip route vrf MUNI','show ip ospf neighbor'],
              'PE2':['show ip route vrf MUNI','show ip ospf neighbor'],
              'CE-MUNI-HQ':['ping 10.11.10.10 source 10.10.10.1','ping 10.10.20.10 source 10.10.20.1'],
              'CE-MUNI-BR':['ping 10.10.10.10 source 10.11.10.1'],
              'CE-UNIV':['ping 10.20.10.10 source 10.20.10.1','ping 10.10.10.10 source 10.20.10.1'],
              'CE-HEALTH':['ping 10.30.10.10 source 10.30.10.1','ping 10.10.10.10 source 10.30.10.1'],
              'SW-MUNI-HQ':['show vlan brief','show interfaces trunk'],
              'SW-MUNI-BR':['show vlan brief','show interfaces trunk']}[name]
        print('Collecting',name)
        out[name]=cli(nodes[name],host,cmds)
    failures=[]
    for sw, vlans in [('SW-MUNI-HQ', (10,20,30,99)), ('SW-MUNI-BR', (10,20,99))]:
        ok, detail = trunk_state(out[sw]['show interfaces trunk'],'GigabitEthernet0/0',vlans)
        if not ok: failures.append(f'{sw}: {detail}')
        else: print('PASS:', sw, detail)
    for ce in ('CE-MUNI-HQ','CE-MUNI-BR'):
        for cmd,txt in out[ce].items():
            if not ping_reachable(txt): failures.append(f'{ce} ping failed: {cmd} (IOS {ios_ping_count(txt)})')
    for ce in ('CE-UNIV','CE-HEALTH'):
        cmds=list(out[ce].items())
        if not ping_reachable(cmds[0][1]): failures.append(f'{ce}: local endpoint not reachable (IOS {ios_ping_count(cmds[0][1])})')
        if not ping_blocked(cmds[1][1]): failures.append(f'{ce}: unexpected or inconclusive inter-organisation test (IOS {ios_ping_count(cmds[1][1])})')
    for pe in ('PE1','PE2'):
        txt=out[pe]['show ip route vrf MUNI']
        expected=('10.10.10.0','10.10.20.0','10.10.30.0','10.11.10.0','10.11.20.0')
        if not all(e in txt for e in expected): failures.append(f'{pe}: municipal route set incomplete')
        if len(re.findall(r'(?m)^172\.20\.255\.[34]\s+\d+\s+FULL',out[pe]['show ip ospf neighbor']))!=2:
            failures.append(f'{pe}: provider OSPF regressed')
    try:
        endpoint_results = {
          'HQ_to_branch': vpcs_commands(nodes['PC-HQ-STAFF'],host,['ping 10.11.10.10']),
          'HQ_staff_to_admin_denied': vpcs_commands(nodes['PC-HQ-STAFF'],host,['ping 10.10.20.10']),
          'branch_to_HQ_services': vpcs_commands(nodes['PC-BR-STAFF'],host,['ping 10.10.30.10']),
        }
        out['VPCS_TESTS'] = endpoint_results
        if not vpcs_received_reply(endpoint_results['HQ_to_branch']['ping 10.11.10.10']):
            failures.append('HQ staff VPCS cannot reach branch staff VPCS')
        if vpcs_received_reply(endpoint_results['HQ_staff_to_admin_denied']['ping 10.10.20.10']):
            failures.append('HQ staff VPCS can reach administration despite ACL')
        if not vpcs_received_reply(endpoint_results['branch_to_HQ_services']['ping 10.10.30.10']):
            failures.append('Branch staff cannot reach municipal HQ services endpoint')
    except (OSError, EOFError, TimeoutError, RuntimeError) as exc:
        failures.append('VPCS endpoint tests inconclusive: '+str(exc))
    # Separate gateway probes reveal local VLAN or CE-link failures before
    # assuming an MPLS/VRF fault. These commands do not modify configurations.
    for ep in inv['endpoints']:
        try:
            test = f"ping {ep['gateway']}"
            sample = vpcs_commands(nodes[ep['name']], host, [test])[test]
            out.setdefault('VPCS_GATEWAYS', {})[ep['name']] = sample
            if not vpcs_received_reply(sample):
                failures.append(f"{ep['name']}: gateway {ep['gateway']} did not answer")
        except (OSError, EOFError, TimeoutError, RuntimeError) as exc:
            failures.append(f"{ep['name']}: gateway probe inconclusive: {exc}")
    evidence('local_bulk_verify',{'phase':'local_bulk','passed':not failures,'failures':failures,'outputs':out})
    if failures:
        for x in failures: print('FAIL:',x)
        raise RuntimeError('Local enterprise verification failed')
    print('PASS: VLANs and CE LANs, 5 municipal prefixes, HQ/BR traffic, local UNIV/HEALTH endpoints, customer isolation, OSPF')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    modes=p.add_mutually_exclusive_group()
    modes.add_argument('--plan',action='store_true')
    modes.add_argument('--build',action='store_true')
    modes.add_argument('--apply',action='store_true')
    modes.add_argument('--verify',action='store_true')
    p.add_argument('--approve-maintenance',action='store_true',help='Required for --apply: CE Loopback10 migration temporarily disrupts service')
    p.add_argument('--resume',action='store_true',help='For interrupted --apply only: bypass healthy-baseline check')
    p.add_argument('--url',default='http://127.0.0.1:3080')
    p.add_argument('--user',default='admin')
    args=p.parse_args()
    if sys.version_info[:2] != (3,12) and (args.apply or args.verify):
        raise RuntimeError('Use Python 3.12 for IOSv/VPCS Telnet consoles')
    inv=yaml.safe_load((BASE/'inventory.yaml').read_text(encoding='utf-8'))
    inv['project']=os.environ.get('NORDNET_TARGET_PROJECT', 'NORDNET-Core-POC')
    validate(inv); render(inv)
    if args.plan or not any((args.build,args.apply,args.verify)):
        print('PLAN ONLY. Existing Phase 5 core untouched; 2 switches, 7 VPCS, LAN migration on four CEs.')
        print('Warning: shared-services VRF, external SOC, true provider OOB management NOT part of this bundle.')
        return
    if args.apply and not args.approve_maintenance:
        raise RuntimeError('Use --apply --approve-maintenance only after backing up the verified Phase 5 project')
    api=GNS(args.url,args.user,getpass('GNS3 API password: '))
    print('Controller:', api.call('GET','/v2/version'))
    path,host=connect(api,inv)
    nodes=build(api,path,inv,change_allowed=not args.verify)
    if args.build:
        print('Built local LAN topology (no configuration changes).')
        return
    if args.apply:
        old=get_nodes(api,path)
        for name in ROUTERS:
            if old[name]['status']!='started':
                raise RuntimeError('Existing Phase 5 router is not started: '+name)
        if not args.resume: check_base(old,host)
        else: print('WARNING: --resume skips healthy-baseline validation; reviewing interface preflight per device')
        for name in SWITCHES + tuple(e['name'] for e in inv['endpoints']):
            if nodes[name]['status']!='started':
                api.call('POST',path+'/nodes/'+nodes[name]['node_id']+'/start',{})
                print('Starting',name)
        nodes=get_nodes(api,path)
        for name in ('SW-MUNI-HQ','SW-MUNI-BR','PE1','PE2',
                     'CE-MUNI-HQ','CE-MUNI-BR','CE-UNIV','CE-HEALTH'):
            push(nodes[name],host,name)
        check_vpcs(nodes,host,inv)
        print('Local LAN deployment applied; run --verify after convergence.')
    if args.verify:
        for name in SWITCHES + tuple(e['name'] for e in inv['endpoints']):
            if nodes[name]['status']!='started': raise RuntimeError('Local node is not started: '+name)
        verify(nodes,host,inv)

if __name__=='__main__':
    try: main()
    except (RuntimeError,ValueError,KeyError,requests.RequestException,KeyboardInterrupt) as exc:
        print('ERROR:',exc,file=sys.stderr);sys.exit(1)
