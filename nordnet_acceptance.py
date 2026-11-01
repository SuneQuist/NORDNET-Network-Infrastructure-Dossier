#!/usr/bin/env python3
"""NORDNET v0.8.6 local-acceptance suite (GNS3 2.2.61 / Python 3.12).

--plan: offline change plan
--prepare: additive GNS3 Docker probe nodes/links only (changes topology)
--dhcp-startup: safely replace recognized VPCS save-format leases with DHCP startup files (backups first)
--dhcp-inspect: display both existing DHCP startup scripts without modifying anything
--verify: read-only device/config inspection + active DNS/HTTP/syslog network probes
--cold-start-guide: describes a manually controlled persistence check, never reboots nodes
--hardening-audit: read-only unsafe management configuration review

This package does not configure Cisco interfaces, core routers or routing policy.
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
import time
import warnings

import requests
import yaml
import nordnet_local as local
import nordnet_enterprise as enterprise
from ios_console import console_host

BASE = Path(__file__).resolve().parent
PROJECT_ID_DEFAULT = '381c9ab5-1701-4481-a808-6d13439ddeed'
NODE_PLAN = {
    'PROBE-MUNI': {'parent':'SW-MUNI-HQ', 'iface':'GigabitEthernet1/2', 'ip':'10.10.30.251', 'gateway':'10.10.30.1','x':-630,'y':-550},
    'PROBE-UNIV': {'parent':'LAN-UNIV-SW', 'iface':'Ethernet2', 'ip':'10.20.10.20', 'gateway':'10.20.10.1','x':-650,'y':-650},
    'PROBE-HEALTH': {'parent':'LAN-HEALTH-SW', 'iface':'Ethernet2', 'ip':'10.30.10.20', 'gateway':'10.30.10.1','x':780,'y':-630},
}
DHCP = {
    'PC-HQ-DHCP': ('10.10.10.0/24','10.10.10.1'),
    'PC-BR-DHCP': ('10.11.10.0/24','10.11.10.1'),
}
VPCS_SCRIPT='ip dhcp\n'
SPLITS={
    'LAN-UNIV-SW': {'ce':'CE-UNIV','pc':'PC-UNIV','ce_port':'GigabitEthernet0/1',
                    'x':-870,'y':-490,'probe':'PROBE-UNIV'},
    'LAN-HEALTH-SW': {'ce':'CE-HEALTH','pc':'PC-HEALTH','ce_port':'GigabitEthernet0/1',
                      'x':850,'y':-490,'probe':'PROBE-HEALTH'},
}

MARKER='NORDNET_E2E_V1 '
IOS = enterprise.ROUTERS + enterprise.SWs


def stamp(): return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')

def save_report(kind, data):
    folder=BASE/'evidence'/'local_acceptance';folder.mkdir(parents=True,exist_ok=True)
    path=folder/(stamp()+'_'+kind+'.json')
    path.write_text(json.dumps(data, indent=2, default=str)+'\n',encoding='utf-8')
    print('Evidence:',path)
    return path


def resolve(api, project_id):
    matches=[p for p in api.call('GET','/v2/projects') if p['name']==enterprise.PROJECT]
    if len(matches)!=1 or matches[0].get('project_id','').lower()!=project_id.lower():
        raise RuntimeError('Wrong project name/UUID; stop, do not change the backup project')
    if matches[0].get('status')!='opened':
        raise RuntimeError('Open the main NORDNET project before continuing')
    computes={c['compute_id']:c for c in api.call('GET','/v2/computes')}
    vm=computes.get('vm')
    if not vm or not vm.get('connected'):
        raise RuntimeError('GNS3 VM compute is disconnected')
    path='/v2/projects/'+project_id
    return path,vm,local.get_nodes(api,path)


def edge(a,b):
    return frozenset((local.epkey(a), local.epkey(b)))


def original_edges(nodes, inv):
    result={}
    for a,ai,b,bi in list(local.desired_links(inv))+list(enterprise.LINKS):
        if a not in nodes or b not in nodes: raise RuntimeError('Missing v0.7 node '+a+' or '+b)
        result[edge(enterprise.port(nodes[a],ai),enterprise.port(nodes[b],bi))]=(a,ai,b,bi)
    return result


def split_edges(nodes):
    """All intended fixture links, if the needed nodes are present."""
    result={}
    for name,info in SPLITS.items():
        if name not in nodes:continue
        ce=nodes[info['ce']];pc=nodes[info['pc']];sw=nodes[name]
        for a,b in ((enterprise.port(ce,info['ce_port']),enterprise.port(sw,'Ethernet0')),
                    (enterprise.port(pc,'Ethernet0'),enterprise.port(sw,'Ethernet1'))):
            result[edge(a,b)]=(a,b)
    for name,info in NODE_PLAN.items():
        if name in nodes and info['parent'] in nodes:
            a=enterprise.port(nodes[info['parent']],info['iface'])
            b=enterprise.port(nodes[name],0)
            result[edge(a,b)]=(a,b)
    return result


def check_topology(api,path,nodes,inv,require_probes=False):
    baseline=set(enterprise.ROUTERS)|set(enterprise.SWs)|{x['name'] for x in inv['endpoints']}|set(enterprise.NODES)
    extras=set(NODE_PLAN)|set(SPLITS)
    missing=baseline-set(nodes);unknown=set(nodes)-baseline-extras
    if missing or unknown:
        raise RuntimeError(f'v0.7 topology changed; missing={sorted(missing)}, unexpected={sorted(unknown)}')
    for name in NODE_PLAN:
        if name in nodes:
            n=nodes[name]
            if (n.get('node_type'),n.get('compute_id'),n.get('properties',{}).get('image'),n.get('properties',{}).get('adapters'))!=('docker','vm',enterprise.IMAGE,1):
                raise RuntimeError(name+' unexpected type, compute, image or adapter count')
            cmd=n.get('properties',{}).get('start_command')
            if cmd and cmd!=make_boot_command(name):
                raise RuntimeError(name+' previously created with different start command')
        elif require_probes:raise RuntimeError(name+' missing; run --prepare')
    for name in SPLITS:
        if name in nodes:
            n=nodes[name]
            if n.get('node_type')!='ethernet_switch' or n.get('compute_id') not in ('vm','local'):
                raise RuntimeError(name+' is not the expected built-in Ethernet switch')
            for ix in range(3):enterprise.port(n,'Ethernet'+str(ix))
        elif require_probes:raise RuntimeError(name+' missing; run --prepare')
    old=original_edges(nodes,inv)
    new=split_edges(nodes)
    links=api.call('GET',path+'/links')
    actual={frozenset(local.epkey(x) for x in ln['nodes']):ln for ln in links}
    existing=set(actual)
    # All previously existing links other than the two explicitly approved
    # CE<->PC links must remain intact through preparation.
    replaced={}
    for name,info in SPLITS.items():
        k=edge(enterprise.port(nodes[info['ce']],info['ce_port']),enterprise.port(nodes[info['pc']],'Ethernet0'))
        replaced[name]=k
    must_exist=set(old)-set(replaced.values())
    if not must_exist.issubset(existing):raise RuntimeError('Unrelated original v0.7 links are missing')
    if existing-set(old)-set(new):raise RuntimeError('Unexpected links in project; refusing changes')
    # One GNS3 port cannot be connected to more than one link.
    occupied={}
    for key in existing:
        for ep in key:
            if ep in occupied:raise RuntimeError('One GNS3 port appears in multiple links')
            occupied[ep]=key
    for name,info in SPLITS.items():
        k=replaced[name]
        sw_present=name in nodes
        if k not in existing and not sw_present:
            raise RuntimeError('CE-PC direct link missing but inline switch absent: '+name)
        if k in existing and sw_present:
            candidate=split_edges(nodes)
            if any(x in existing and (local.epkey(enterprise.port(nodes[info['ce']],info['ce_port'])) in x or
                                            local.epkey(enterprise.port(nodes[info['pc']],'Ethernet0')) in x)
                   for x in candidate):
                raise RuntimeError('Direct and inline LAN links overlap: '+name)
    # The planned new switch/probe source ports must not be occupied by another link.
    for key,(a,b) in new.items():
        if key in existing:continue
        for ep in (local.epkey(a),local.epkey(b)):
            if ep in occupied and occupied[ep] not in replaced.values():
                raise RuntimeError('Fixture port already occupied by unrelated link')
    if require_probes and not set(new).issubset(existing):
        raise RuntimeError('Incomplete test fixture; run --prepare to finish')
    return {'baseline_links':len(old),'expected_fixture_links':len(new),
            'existing_links':len(existing),'probes_present':sorted(set(nodes)&set(NODE_PLAN)),
            'inline_switches_present':sorted(set(nodes)&set(SPLITS)),
            'direct_links_remaining':[k for k in SPLITS if replaced[k] in existing]}


def image_guard(api):
    images=enterprise.images_available(api)
    if enterprise.IMAGE not in str(images):
        raise RuntimeError('Image '+enterprise.IMAGE+' missing on the GNS3 VM')


def make_boot_command(name):
    if name not in NODE_PLAN: raise ValueError(name)
    source=(BASE/'probes'/'nordnet_probe.py').read_text(encoding='utf-8')
    source=source.replace("name = os.environ.get('NORDNET_PROBE_NAME', '')", "name = "+repr(name))
    return enterprise.boot_cmd(source)


def switch_compute(api):
    computes={x['compute_id']:x for x in api.call('GET','/v2/computes')}
    for candidate in ('vm','local'):
        node_types=computes.get(candidate,{}).get('capabilities',{}).get('node_types',[])
        if 'ethernet_switch' in node_types and (candidate=='local' or computes[candidate].get('connected')):
            return candidate
    raise RuntimeError('No GNS3 compute advertises built-in Ethernet switch capability')


def prepare(api,path,vm,nodes,inv):
    check_topology(api,path,nodes,inv)
    image_guard(api)
    is_fresh=not any(n in nodes for n in set(NODE_PLAN)|set(SPLITS))
    if is_fresh:
        enterprise.phase6_baseline(nodes,vm)
    compute=switch_compute(api)
    print('The university/healthcare CE-to-PC links will be moved through two built-in switches.')
    print('There will be a brief UNIV/HEALTH LAN interruption. NO Cisco router configuration changes.')
    print('Read the project backup requirement in README before running this maintenance action.')
    mapping=[{'name':'Ethernet'+str(i),'port_number':i,'type':'access','vlan':1} for i in range(8)]
    for name,info in SPLITS.items():
        if name not in nodes:
            print('Creating inline L2 switch:',name,'compute',compute)
            api.call('POST',path+'/nodes',{'compute_id':compute,'node_type':'ethernet_switch','name':name,
                     'x':info['x'],'y':info['y'],'properties':{'ports_mapping':mapping}})
    for name,info in NODE_PLAN.items():
        if name not in nodes:
            print('Creating Docker application probe:',name)
            api.call('POST',path+'/nodes',{'compute_id':'vm','node_type':'docker','name':name,
                     'x':info['x'],'y':info['y'],'properties':{'image':enterprise.IMAGE,
                     'adapters':1,'console_type':'telnet','start_command':make_boot_command(name)}})
    nodes=local.get_nodes(api,path)
    check_topology(api,path,nodes,inv)
    # Reconnect each tested customer LAN through the built-in switch.
    # All link removals are LIMITED to the two exact, pre-known original pairs.
    for sw,info in SPLITS.items():
        node_ce=nodes[info['ce']];node_pc=nodes[info['pc']];node_sw=nodes[sw]
        before=api.call('GET',path+'/links')
        current={frozenset(local.epkey(e) for e in l['nodes']):l for l in before}
        direct=edge(enterprise.port(node_ce,info['ce_port']),enterprise.port(node_pc,'Ethernet0'))
        fixture=[(enterprise.port(node_ce,info['ce_port']),enterprise.port(node_sw,'Ethernet0')),
                 (enterprise.port(node_pc,'Ethernet0'),enterprise.port(node_sw,'Ethernet1')),
                 (enterprise.port(nodes[info['probe']],0),enterprise.port(node_sw,'Ethernet2'))]
        if direct in current:
            original=current[direct]
            if not original.get('link_id'):
                raise RuntimeError('Original link has no link_id, cannot safely replace '+sw)
            print('Rewiring CE-to-PC LAN through:',sw)
            save_report('link_backup_'+sw,{'project_id':path.split('/')[-1],
                         'original_link_id':original['link_id'],'original_endpoints':original['nodes']})
            api.call('DELETE',path+'/links/'+original['link_id'])
        now={frozenset(local.epkey(e) for e in l['nodes']) for l in api.call('GET',path+'/links')}
        for a,b in fixture:
            key=edge(a,b)
            if key not in now:
                api.call('POST',path+'/links',{'nodes':[a,b]})
                now.add(key)
    # Municipal probe uses an already-available access port on SW-MUNI-HQ.
    info=NODE_PLAN['PROBE-MUNI']
    a=enterprise.port(nodes[info['parent']],info['iface'])
    b=enterprise.port(nodes['PROBE-MUNI'],0)
    actual={frozenset(local.epkey(e) for e in l['nodes']) for l in api.call('GET',path+'/links')}
    if edge(a,b) not in actual:
        api.call('POST',path+'/links',{'nodes':[a,b]})
    nodes=local.get_nodes(api,path)
    check_topology(api,path,nodes,inv,True)
    for name in NODE_PLAN:
        if nodes[name].get('status')!='started':
            print('Starting:',name)
            api.call('POST',path+'/nodes/'+nodes[name]['node_id']+'/start',{})
    print('PASS: Inline LAN switches and three test probes wired; original Cisco configs untouched.')
    print('NOTE: Existing nordnet_enterprise.py topology guard expects direct CE-PC links.')
    print('      Use THIS script --verify while test fixtures are installed,')
    print('      then use --restore to return to the fully supported original topology.')


def restore(api,path,vm,nodes,inv):
    """Recreate only the two exact direct LAN links and remove ONLY our five test nodes."""
    check_topology(api,path,nodes,inv)
    for sw,info in SPLITS.items():
        ce=nodes[info['ce']];pc=nodes[info['pc']]
        originals=edge(enterprise.port(ce,info['ce_port']),enterprise.port(pc,'Ethernet0'))
        existing={frozenset(local.epkey(x) for x in link['nodes']):link for link in api.call('GET',path+'/links')}
        # Remove our three switch edges before recreating the direct link.
        if sw in nodes:
            switch_id=nodes[sw]['node_id']
            for link in list(existing.values()):
                if any(p['node_id']==switch_id for p in link['nodes']):
                    print('Removing test-fixture link:',link['link_id'])
                    api.call('DELETE',path+'/links/'+link['link_id'])
        remaining={frozenset(local.epkey(x) for x in link['nodes']) for link in api.call('GET',path+'/links')}
        if originals not in remaining:
            print('Restoring original LAN link:',info['ce'],'<->',info['pc'])
            api.call('POST',path+'/links',{'nodes':[
                enterprise.port(ce,info['ce_port']),enterprise.port(pc,'Ethernet0')]})
    # Explicitly delete municipal test link. It is the only remaining probe link.
    links=api.call('GET',path+'/links')
    probe_ids={nodes[name]['node_id'] for name in NODE_PLAN if name in nodes}
    for link in links:
        if any(x['node_id'] in probe_ids for x in link['nodes']):
            print('Removing application-probe link:',link['link_id'])
            api.call('DELETE',path+'/links/'+link['link_id'])
    for name in NODE_PLAN:
        if name in nodes and nodes[name].get('status')=='started':
            print('Stopping ONLY Docker probe:',name)
            api.call('POST',path+'/nodes/'+nodes[name]['node_id']+'/stop',{})
    for name in list(NODE_PLAN)+list(SPLITS):
        if name in nodes:
            print('Deleting ONLY test-fixture node:',name)
            api.call('DELETE',path+'/nodes/'+nodes[name]['node_id'])
    nodes=local.get_nodes(api,path)
    # Confirm the exact original 20-node/22-link inventory is restored.
    if len(nodes)!=20 or any(x in nodes for x in list(NODE_PLAN)+list(SPLITS)):
        raise RuntimeError('Fixture cleanup incomplete; inspect GNS3 project')
    actual={frozenset(local.epkey(x) for x in link['nodes']) for link in api.call('GET',path+'/links')}
    if actual!=set(original_edges(nodes,inv)):
        raise RuntimeError('Restored links do not match the original 22-link topology')
    print('PASS: Original v0.7 20-node/22-link topology restored.')
    print(r'Now run: py -3.12 .\nordnet_enterprise.py --verify')


def vpcs_file_url(path, node_id):
    """Exact GNS3 node-file API endpoint; never a generic project-file path."""
    if not re.fullmatch(r'[a-f0-9-]{36}', node_id, flags=re.I):
        raise RuntimeError('Invalid VPCS node UUID')
    return path+'/nodes/'+node_id+'/files/startup.vpc'


def node_file_get(api, path, node_id):
    """Read startup.vpc; None means no saved startup file exists."""
    url=vpcs_file_url(path,node_id)
    response=api.s.get(api.base+url,timeout=45)
    if response.status_code==404:
        return None
    if response.status_code!=200:
        raise RuntimeError('GNS3 GET '+url+' HTTP '+str(response.status_code)+': '+response.text[:250])
    return response.content


def node_file_post(api, path, node_id, data):
    """Write raw startup.vpc contents; never use PUT node properties (VPCS API 400)."""
    url=vpcs_file_url(path,node_id)
    response=api.s.post(api.base+url, data=data,
                        headers={'Content-Type':'application/octet-stream'},timeout=45)
    if response.status_code not in (200,201,204):
        raise RuntimeError('GNS3 POST '+url+' HTTP '+str(response.status_code)+': '+response.text[:250])


def parse_previous_vpcs_script(content, network, gateway):
    """Strictly recognize simple saved VPCS lease/startup scripts.

    The native VPCS `save` format can include the `1` PC selector and
    `ip ADDRESS GATEWAY 24`, which v0.8.1 incorrectly rejected.
    Return a stable plan with an optional preserved hostname, or raise ValueError.
    Never interpret arbitrary script commands as safe.
    """
    if content is None or not content.strip():
        return {'kind':'absent_or_blank','pcname':None,'dhcp':False,'ip':None}
    if len(content)>8192 or b'\x00' in content:
        raise ValueError('startup.vpc is too large or contains NUL bytes')
    try:
        body=content.decode('utf-8-sig',errors='strict').replace('\r\n','\n').replace('\r','\n')
    except UnicodeDecodeError as exc:
        raise ValueError('startup.vpc is not UTF-8') from exc
    net=ipaddress.ip_network(network,strict=True)
    expected_gateway=ipaddress.IPv4Address(gateway)
    hostname=None
    dhcp_count=0
    saved_ip=None
    for raw in body.splitlines():
        line=raw.strip()
        if not line or line.startswith(('#','!')):
            continue
        if len(line)>256:
            raise ValueError('overlong startup.vpc command')
        # VPCS save may include a `1` host selector before/after its commands.
        if line=='1':
            continue
        m=re.fullmatch(r'set\s+pcname\s+([A-Za-z0-9_.-]{1,64})',line,flags=re.I)
        if m:
            if hostname is not None and hostname!=m.group(1):
                raise ValueError('multiple conflicting PC names')
            hostname=m.group(1)
            continue
        if re.fullmatch(r'(?:ip\s+)?dhcp',line,flags=re.I):
            dhcp_count+=1
            if dhcp_count>1:
                raise ValueError('multiple DHCP commands')
            continue
        m=re.fullmatch(r'dns\s+(\d{1,3}(?:\.\d{1,3}){3})',line,flags=re.I)
        if m:
            if str(ipaddress.IPv4Address(m.group(1)))!='10.10.30.250':
                raise ValueError('unexpected saved DNS address')
            continue
        m=re.fullmatch(r'domain\s+([A-Za-z0-9.-]+)',line,flags=re.I)
        if m:
            if m.group(1).lower()!='nordnet.test':
                raise ValueError('unexpected saved search domain')
            continue
        parts=line.split()
        if len(parts)>=2 and parts[0].lower()=='ip':
            if saved_ip is not None:
                raise ValueError('multiple saved IPv4 commands')
            args=parts[1:]
            if len(args) not in (2,3):
                raise ValueError('unrecognised saved IP syntax')
            try:
                iface=ipaddress.IPv4Interface(args[0] if '/' in args[0] else args[0]+'/24')
                if iface.network!=net or int(iface.ip.packed[-1])<100 or int(iface.ip.packed[-1])>254:
                    raise ValueError('saved IP is outside expected DHCP allocation range')
                if len(args)==2:
                    if '/' not in args[0] or ipaddress.IPv4Address(args[1])!=expected_gateway:
                        raise ValueError('saved IP/gateway incompatible with expected DHCP client')
                else:
                    a1,a2=args[1:]
                    # VPCS save: ip ADDRESS GATEWAY 24
                    # Other supported forms: ip ADDRESS 24 GATEWAY,
                    # ip ADDRESS NETMASK GATEWAY and ip ADDRESS GATEWAY NETMASK.
                    if a1==gateway:
                        mask=a2
                    elif a2==gateway:
                        mask=a1
                    else:
                        raise ValueError('unexpected gateway in saved IP command')
                    if mask not in ('24','/24','255.255.255.0'):
                        raise ValueError('unexpected saved netmask')
                    if '/' in args[0]:
                        raise ValueError('duplicate mask in saved IP command')
                saved_ip=str(iface.ip)
            except (ipaddress.AddressValueError,ipaddress.NetmaskValueError) as exc:
                raise ValueError('invalid saved IPv4 address') from exc
            continue
        raise ValueError('unrecognised VPCS startup command: '+repr(line[:110]))
    if dhcp_count and saved_ip:
        raise ValueError('ambiguous startup: DHCP and fixed address both present')
    return {'kind':'dhcp' if dhcp_count else 'saved_lease' if saved_ip else 'metadata_only',
            'pcname':hostname,'dhcp':bool(dhcp_count),'ip':saved_ip}


def approved_previous_vpcs_script(content, network):
    """Compatibility with older offline tests; returns no permission to overwrite custom scripts."""
    try:
        gateway=DHCP_GW_BY_NET[str(ipaddress.ip_network(network))]
        parse_previous_vpcs_script(content,network,gateway)
        return True
    except (ValueError,KeyError):
        return False


DHCP_GW_BY_NET={network:gateway for network,gateway in DHCP.values()}


def make_dhcp_startup(plan):
    """Keep the saved VPCS hostname, if any; replace only the lease behavior."""
    return (('set pcname '+plan['pcname']+'\n') if plan['pcname'] else '')+'ip dhcp\n'


def dhcp_startup_inspect(api,path,nodes):
    """Read-only troubleshooting output; no files are written, even locally."""
    print('READ-ONLY DHCP startup inspection; no GNS3 changes')
    for name,(network,gateway) in DHCP.items():
        node=nodes[name]
        if node.get('node_type')!='vpcs' or node.get('compute_id')!='vm':
            raise RuntimeError(name+' is not the expected VPCS on vm')
        previous=node_file_get(api,path,node['node_id'])
        print(name, 'file:', 'ABSENT' if previous is None else str(len(previous))+' bytes')
        if previous is None:
            continue
        print('  sha256:',hashlib.sha256(previous).hexdigest())
        try:
            plan=parse_previous_vpcs_script(previous,network,gateway)
            print('  recognized:',plan)
        except ValueError as exc:
            print('  UNRECOGNIZED:',exc)
        for idx,line in enumerate(previous.decode('utf-8',errors='replace').splitlines(),1):
            print(f'  line {idx}: {line[:160]}')


def set_dhcp_startup(api,path,nodes):
    """Preflight both nodes; back up both before writing either. No Cisco changes."""
    pending=[]
    for name,(cidr,gw) in DHCP.items():
        node=nodes[name]
        if node.get('node_type')!='vpcs' or node.get('compute_id')!='vm':
            raise RuntimeError(name+' is not the expected VPCS on vm')
        previous=node_file_get(api,path,node['node_id'])
        try:
            plan=parse_previous_vpcs_script(previous,cidr,gw)
        except ValueError as exc:
            raise RuntimeError(name+' has an unexpected startup.vpc ('+str(exc)+
                '); refusing overwrite; run --dhcp-inspect') from exc
        desired=make_dhcp_startup(plan).encode('utf-8')
        pending.append((name,node,previous,desired,plan['kind']=='dhcp' and previous is not None))
    # All originals are backed up before any update is sent to GNS3.
    needs_update=[(n,node,previous,desired) for n,node,previous,desired,already_dhcp in pending if not already_dhcp and previous != desired]
    if needs_update:
        folder=BASE/'evidence'/'local_acceptance'/'vpcs_startup_backups'
        folder.mkdir(parents=True,exist_ok=True)
        unique=stamp()
        for name,node,previous,desired in needs_update:
            fn=unique+'_'+name+'_'+node['node_id']+'.startup.vpc'
            backup=folder/fn
            if backup.exists():
                raise RuntimeError('Backup file exists; no VPCS writes: '+str(backup))
            backup.write_bytes(previous if previous is not None else b'')
            if backup.read_bytes() != (previous if previous is not None else b''):
                raise RuntimeError('Backup verification failed; no VPCS writes')
            print('Backed up existing VPCS file:',backup,
                  '(absent)' if previous is None else '('+str(len(previous))+' bytes)')
    for name,node,previous,desired,already_dhcp in pending:
        if already_dhcp or previous==desired:
            print('Already configured:',name)
            continue
        print('Writing DHCP startup.vpc for:',name)
        node_file_post(api,path,node['node_id'],desired)
        after=node_file_get(api,path,node['node_id'])
        if after!=desired:
            raise RuntimeError(name+' startup.vpc readback mismatch; stop and inspect backups')
        print('PASS: verified startup.vpc:',name)
    print('PASS: Both DHCP startup files verified; effective on NEXT VPCS start only.')


def dhcp_startup_audit(api, path, nodes):
    """Check startup file contains only a safe DHCP startup command and optional hostname."""
    result={}
    for name,(cidr,gw) in DHCP.items():
        node=nodes[name]
        data=node_file_get(api,path,node['node_id'])
        try:
            plan=parse_previous_vpcs_script(data,cidr,gw)
            ok=plan['kind']=='dhcp' and data is not None
        except ValueError:
            ok=False
        result[name]={'ok':ok,'present':data is not None,
                      'sha256':hashlib.sha256(data).hexdigest() if data is not None else None}
    return result


def strip_ansi(blob):
    return re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', blob).replace('\r','')


def parse_vpcs_ip(text):
    """Extract only address/gateway fields; reject blanks and stale prompt-only reads."""
    text=strip_ansi(text)
    ip=re.search(r'(?im)^\s*IP/MASK\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\s*$',text)
    gw=re.search(r'(?im)^\s*GATEWAY\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$',text)
    if ip is None or gw is None:
        raise ValueError('VPCS show ip did not contain complete IP/MASK and GATEWAY fields')
    return {'ip':str(ipaddress.ip_address(ip.group(1))), 'prefix':int(ip.group(2)),
            'gateway':str(ipaddress.ip_address(gw.group(1)))}


def vpcs_show(node,host):
    if sys.version_info[:2]!=(3,12):
        raise RuntimeError('Use Python 3.12 for VPCS Telnet console')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',DeprecationWarning)
        import telnetlib
    tn=telnetlib.Telnet(console_host(node,host), int(node['console']), timeout=7)
    try:
        tn.write(b'\r\n')
        # Discard the greeting and stale prompt before sending a fresh command.
        deadline=time.monotonic()+8; raw=''
        while time.monotonic()<deadline:
            raw+=tn.read_very_eager().decode('utf-8',errors='replace')
            if re.search(r'(?m)^\s*VPCS>\s*$',strip_ansi(raw)):
                break
            time.sleep(.1)
        if not re.search(r'(?m)^\s*VPCS>\s*$',strip_ansi(raw)):
            raise RuntimeError('VPCS prompt unavailable')
        # Drain any buffered bytes before the command (not a topology change).
        tn.read_very_eager()
        tn.write(b'show ip\r\n')
        raw=''; lastdata=time.monotonic(); deadline=time.monotonic()+14
        while time.monotonic()<deadline:
            b=tn.read_very_eager()
            if b:
                raw+=b.decode('utf-8',errors='replace');lastdata=time.monotonic()
            clean=strip_ansi(raw)
            if ('IP/MASK' in clean and 'GATEWAY' in clean and
                re.search(r'(?m)^\s*VPCS>\s*$',clean) and time.monotonic()-lastdata>.20):
                return parse_vpcs_ip(clean)
            time.sleep(.06)
        raise RuntimeError('Incomplete VPCS show ip console output; captured='+repr(strip_ansi(raw)[-200:]))
    finally: tn.close()


def vpcs_audit(nodes,vm,inv,startup_audit):
    report={};issues=[]
    for ep in inv['endpoints']:
        name=ep['name']
        try:
            found=vpcs_show(nodes[name],vm['host'])
            ok=found == {'ip':ep['ip'],'prefix':24,'gateway':ep['gateway']}
            report[name]={'status':'PASS' if ok else 'FAIL','address':found}
            if not ok: issues.append(name+' static IP mismatch')
        except Exception as ex:
            report[name]={'status':'FAIL','error':str(ex)[:220]}
            issues.append(name+' console read failed')
    for name,(cidr,gw) in DHCP.items():
        try:
            found=vpcs_show(nodes[name],vm['host'])
            addr=ipaddress.ip_address(found['ip']); net=ipaddress.ip_network(cidr)
            ok=(found['prefix']==24 and addr in net and addr not in (net.network_address,net.broadcast_address)
                and found['gateway']==gw and addr.packed[-1]>=100)
            report[name]={'status':'PASS' if ok else 'FAIL','address':found,
                          'startup_script_ok':startup_audit[name]['ok']}
            if not ok: issues.append(name+' DHCP lease missing/wrong')
        except Exception as ex:
            report[name]={'status':'FAIL','error':str(ex)[:220]}
            issues.append(name+' console read failed')
    return report,issues


def probe_report(line):
    try:
        obj=json.loads(line)
        if not isinstance(obj,dict):raise ValueError('not a dictionary')
        if obj.get('node') not in NODE_PLAN: raise ValueError('wrong probe identity')
        return obj
    except (json.JSONDecodeError, ValueError) as ex: raise ValueError('Invalid probe JSON: '+str(ex)) from ex


def newest_probe_heartbeat(raw, expected_node):
    """Choose latest complete record; GNS3 telnet consoles replay old output."""
    newest = None
    newest_timestamp = None
    for match in re.finditer(r'(?m)^'+re.escape(MARKER)+r'([^\n]+)$', raw):
        try:
            obj = probe_report(match.group(1))
            if obj.get('node') != expected_node:
                continue
            timestamp = datetime.fromisoformat(obj['created_utc'].replace('Z', '+00:00'))
            if timestamp.tzinfo is None:
                continue
            if newest_timestamp is None or timestamp > newest_timestamp:
                newest, newest_timestamp = obj, timestamp
        except (ValueError, KeyError, AttributeError, TypeError):
            continue
    return newest


def probe_console(node,host,timeout=47):
    if sys.version_info[:2]!=(3,12): raise RuntimeError('Use Python 3.12')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',DeprecationWarning)
        import telnetlib
    tn=telnetlib.Telnet(console_host(node,host),int(node['console']),timeout=6)
    raw=''; deadline=time.monotonic()+timeout
    last_age=None
    try:
        while time.monotonic()<deadline:
            chunk=tn.read_very_eager().decode('utf-8',errors='replace')
            if chunk: raw+=chunk
            # Do not return the first valid line: it may be a cached GNS3
            # console heartbeat from minutes ago. Always pick the newest.
            candidate=newest_probe_heartbeat(raw,node['name'])
            if candidate:
                if fresh(candidate.get('created_utc'),seconds=90):
                    return candidate
                try:
                    dt=datetime.fromisoformat(candidate['created_utc'].replace('Z','+00:00'))
                    last_age=round((datetime.now(timezone.utc)-dt).total_seconds())
                except (ValueError,KeyError,AttributeError,TypeError):
                    last_age=None
            raw=raw[-55000:]
            time.sleep(.2)
    finally: tn.close()
    raise RuntimeError(node['name']+' has no FRESH E2E JSON heartbeat'
                       +' (newest age seconds='+str(last_age)+')'
                       +'; output='+repr(raw[-400:]))


def fresh(iso,seconds=300):
    try:
        date=datetime.fromisoformat(iso.replace('Z','+00:00'))
        if date.tzinfo is None:return False
        return abs((datetime.now(timezone.utc)-date).total_seconds()) <= seconds
    except (ValueError,TypeError,AttributeError):return False


def assess(probes):
    issues=[]
    for name,info in NODE_PLAN.items():
        obj=probes.get(name,{})
        if obj.get('node')!=name or obj.get('source_ip')!=info['ip'] or not fresh(obj.get('created_utc')):
            issues.append(name+' identity/IP/timestamp incorrect or stale')
        for field in ('dns_ok','http_ok','events_policy_ok','syslog_sent'):
            if obj.get(field) is not True: issues.append(name+' '+field+' failed')
    # Municipal /events endpoint is intentionally accessible from the
    # municipal service LAN only. Confirm it contains fresh receive records,
    # not merely UDP sends from probes.
    stored=probes.get('PROBE-MUNI',{}).get('events',[])
    for name,info in NODE_PLAN.items():
        if not any(e.get('source')==info['ip'] and ('NORDNET_ACCEPTANCE:'+name) in str(e.get('message',''))
                   and fresh(e.get('received_utc')) for e in stored):
            issues.append(name+' recent syslog reception not proven by /events')
    return issues


def ios_persistence(nodes,vm):
    # Reuse v0.7.4 configuration parser and audited marker set, without using
    # its VPCS console implementation that produced false failures.
    import nordnet_enterprise_audit as audit
    import nordnet_recover as recovery
    markers=audit.v07_markers()
    reports={};issues=[]
    for name in IOS:
        print('Config persistence:',name,flush=True)
        run,boot=recovery.snapshot_ios(nodes[name],vm['host'])
        report=audit.check_ios(run,boot,markers[name])
        reports[name]={'status':report['status'],
                       'running_equals_startup_normalized':report['running_equals_startup_normalized'],
                       'missing_running':report['missing_running'],
                       'missing_startup':report['missing_startup'],
                       'running_sha256':report['running_sha256'],
                       'startup_sha256':report['startup_sha256']}
        if report['status']!='PASS':issues.append(name+' running/startup mismatch or marker absent')
    return reports,issues


def verify(api,path,vm,nodes,inv,project_id):
    topology=check_topology(api,path,nodes,inv,True)
    print('Verifying municipal HQ/branch, university/health endpoints and ACLs (Phase 6.1 tests)...')
    local.verify(nodes,vm['host'],inv)
    report={'version':'0.8.6','project_id':project_id,'created_utc':datetime.now(timezone.utc).isoformat(),
            'limitations':['Active application checks require Docker probes started and connected',
                           'No router/device is restarted by this command',
                           'Management hardening and public exposure are NOT certified',
                           'Customer isolation is checked separately by Phase 6.1/enterprise verifier'],
            'topology':topology,'ios':{},'vpcs':{},'probes':{},'dhcp_startup':dhcp_startup_audit(api,path,nodes),'issues':[]}
    for name in NODE_PLAN:
        print('E2E application probe:',name,flush=True)
        try: report['probes'][name]=probe_console(nodes[name],vm['host'])
        except Exception as exc:
            report['probes'][name]={'error':str(exc)[:400]}
            report['issues'].append(name+' probe console/error')
    # The municipal probe may have sampled /events before university/healthcare
    # emitted their first marker. Re-sample it after the other two probes run.
    for attempt in range(4):
        missing_logs=[x for x in assess(report['probes']) if 'recent syslog reception' in x]
        if not missing_logs: break
        print('Waiting for fresh syslog markers at municipal collector... attempt',attempt+1,flush=True)
        time.sleep(13)
        try: report['probes']['PROBE-MUNI']=probe_console(nodes['PROBE-MUNI'],vm['host'],timeout=25)
        except Exception as exc:
            report['issues'].append('PROBE-MUNI syslog confirmation: '+str(exc)[:200])
    report['issues']+=assess(report['probes'])
    print('Reading nine VPCS interfaces (new synchronized console parser)...',flush=True)
    report['vpcs'],issues=vpcs_audit(nodes,vm,inv,report['dhcp_startup'])
    report['issues']+=issues
    for name,check in report['dhcp_startup'].items():
        if not check['ok']:report['issues'].append(name+' DHCP auto-start script not configured')
    report['ios'],issues=ios_persistence(nodes,vm)
    report['issues']+=issues
    report['passed']=not report['issues']
    save_report('verification',report)
    if report['issues']:
        for issue in report['issues']:print('FAIL:',issue)
        raise RuntimeError(f'Acceptance incomplete: {len(report["issues"])} issue(s); no changes made')
    print('PASS: end-to-end DNS/HTTP (MUNI, UNIV, HEALTH), access to /events policy,')
    print('      received syslog from all three probe IPs, nine VPCS addresses,')
    print('      DHCP startup scripts, and 10 IOS running/startup matches')


def hardening(api,path,vm,nodes,project_id):
    # Non-mutating configuration-risk inventory, not a compliance certificate.
    problems=[]; detail={}
    for name in IOS:
        text=local.cli(nodes[name],vm['host'],['show running-config'])['show running-config']
        risk=[]
        if re.search(r'(?m)^ip http server\s*$',text):risk.append('HTTP management enabled (plaintext)')
        if not re.search(r'(?m)^aaa new-model\s*$',text):risk.append('AAA not enabled (review authentication design)')
        if re.search(r'(?m)^line vty \d+(?: \d+)?\s*\n\s*login\s*$',text):risk.append('VTY login lacks explicit supported authentication method')
        if re.search(r'(?m)^transport input none\s*$',text):risk.append('Remote VTY management disabled (not hardened SSH management)')
        detail[name]=risk
        problems.extend(name+': '+s for s in risk)
    report={'project_id':project_id,'status':'REVIEW_REQUIRED' if problems else 'NO_SIMPLE_FLAGS',
            'per_device_findings':detail,
            'other_gaps':['Check GNS3 VM/controller password and firewall; do not expose port 3080/VM console ports',
                          'Design dedicated management path before enabling router SSH',
                          'Review service firewall and central logging retention before offsite connectivity'],
            'changed_devices':False}
    save_report('hardening',report)
    print('Hardening review findings:',len(problems))
    for p in problems:print('REVIEW:',p)
    print('No management commands were applied.')


def plan():
    print('NORDNET v0.8 local acceptance; existing Phase 6.1/v0.7 must be healthy.')
    for name,info in NODE_PLAN.items():
        print(f'{name}: {info["parent"]} {info["iface"]} -> Docker eth0 {info["ip"]}/24 gw {info["gateway"]}')
    print('Active tests: UDP DNS, TCP HTTP /health and /events access control, UDP syslog ingestion.')
    print('DHCP startup change: only PC-HQ-DHCP and PC-BR-DHCP -> ip dhcp (separate explicit action).')
    print('Verify: VPCS read-only show ip; Cisco running/startup read-only snapshots; evidence JSON.')
    print('After testing: --restore --approve-maintenance removes the five temporary fixture nodes')
    print('and restores the two original direct LAN links (no Cisco config changes).')
    print('Not included: actual router management hardening, reboot automation, external VPN or SOC.')


def cold_start_guide():
    print('COLD-START PERSISTENCE CHECK — manual and controlled; no device restarted by this tool:')
    print('1. Export the working GNS3 main project. Run --verify and keep evidence.')
    print('2. In GNS3, stop/start ONLY PC-HQ-DHCP and PC-BR-DHCP. Their startup scripts should request DHCP.')
    print('3. Stop/start ONLY the three PROBE-* Docker clients. Do NOT interrupt SVC-NORDNET-LOCAL foreground console.')
    print('4. Wait for clients to boot. Rerun --verify. Successful DHCP + probe tests prove those starts.')
    print('5. For FULL router/switch cold-start test, do separate scheduled maintenance after another export;')
    print('   restart one device at a time and rerun --verify and nordnet_enterprise.py --verify.')
    print('   Existing read-only running/startup matches are not themselves proof of post-reboot operation.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    modes=p.add_mutually_exclusive_group(required=True)
    for a in ('plan','prepare','restore','dhcp-startup','dhcp-inspect','verify','cold-start-guide','hardening-audit'):
        modes.add_argument('--'+a,action='store_true')
    p.add_argument('--project-id',default=PROJECT_ID_DEFAULT)
    p.add_argument('--url',default='http://127.0.0.1:3080')
    p.add_argument('--user',default='admin')
    p.add_argument('--approve-maintenance',action='store_true')
    args=p.parse_args()
    if args.plan:return plan()
    if args.cold_start_guide:return cold_start_guide()
    if sys.version_info[:2]!=(3,12):raise RuntimeError('Use py -3.12')
    if (args.prepare or args.restore or args.dhcp_startup) and not args.approve_maintenance:
        raise RuntimeError('This action changes GNS3 nodes; pass --approve-maintenance after backing up the project')
    inv=yaml.safe_load((BASE/'inventory.yaml').read_text(encoding='utf-8'))
    local.validate(inv)
    api=local.GNS(args.url,args.user,getpass('GNS3 API password: '))
    path,vm,nodes=resolve(api,args.project_id)
    check_topology(api,path,nodes,inv)
    if args.prepare: return prepare(api,path,vm,nodes,inv)
    if args.restore: return restore(api,path,vm,nodes,inv)
    if args.dhcp_inspect:return dhcp_startup_inspect(api,path,nodes)
    if args.dhcp_startup:return set_dhcp_startup(api,path,nodes)
    if args.verify:return verify(api,path,vm,nodes,inv,args.project_id)
    if args.hardening_audit:return hardening(api,path,vm,nodes,args.project_id)

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,KeyError,requests.RequestException,OSError,TimeoutError,EOFError) as exc:
        print('ERROR:',str(exc),file=sys.stderr)
        sys.exit(1)
