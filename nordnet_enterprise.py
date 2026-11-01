#!/usr/bin/env python3
"""NORDNET local-enterprise integration: local Docker DNS/HTTP/syslog,
CE DHCP, isolated shared-service attachments, and operational evidence.

Requires the already deployed Phase 6.1 bundle in the same folder.
See README. This has OFFLINE tests only until run on the user's GNS3 VM.
"""
from __future__ import annotations
import argparse
import os
import base64
from datetime import datetime, timezone
from getpass import getpass
import ipaddress
import json
from pathlib import Path
import re
import sys
import time
import warnings
import zlib

import yaml
import requests
import nordnet_local as old
from ios_console import command, console_host, open_console

BASE=Path(__file__).resolve().parent
SERVICE_FILE=BASE/'services'/'nordnet_services.py'
SERVICE='SVC-NORDNET-LOCAL'
IMAGE='python:3.12-alpine'
PROJECT=os.environ.get('NORDNET_TARGET_PROJECT', 'NORDNET-Core-POC')
CEs=('CE-MUNI-HQ','CE-MUNI-BR','CE-UNIV','CE-HEALTH')
SWs=('SW-MUNI-HQ','SW-MUNI-BR')
ROUTERS=('PE1','PE2','P1','P2')+CEs
NODES=(SERVICE,'PC-HQ-DHCP','PC-BR-DHCP')
# IOSvL2 modules expose Gi0/0..Gi0/3, Gi1/0..Gi1/3, etc.
# HQ Gi0/0..Gi0/3 are ALREADY OCCUPIED by the Phase 6.1 trunk and clients.
HQ_SERVICE_IFACE='GigabitEthernet1/0'
HQ_DHCP_IFACE='GigabitEthernet1/1'
BR_DHCP_IFACE='GigabitEthernet0/3'
# These are the only intended new topology links. Reuse the same constants
# in IOS switch configuration to prevent wiring/configuration mismatches.
LINKS=(
 ('SW-MUNI-HQ',HQ_SERVICE_IFACE,SERVICE,0),
 ('CE-UNIV','GigabitEthernet0/2',SERVICE,1),
 ('CE-HEALTH','GigabitEthernet0/2',SERVICE,2),
 ('SW-MUNI-HQ',HQ_DHCP_IFACE,'PC-HQ-DHCP','Ethernet0'),
 ('SW-MUNI-BR',BR_DHCP_IFACE,'PC-BR-DHCP','Ethernet0'),
)
DNS='10.10.30.250'
DHCP={
 'CE-MUNI-HQ':(('HQ-STAFF','10.10.10.0','10.10.10.1'),('HQ-ADMIN','10.10.20.0','10.10.20.1'),('HQ-SERVICES','10.10.30.0','10.10.30.1')),
 'CE-MUNI-BR':(('BR-STAFF','10.11.10.0','10.11.10.1'),('BR-SERVICES','10.11.20.0','10.11.20.1')),
 'CE-UNIV':(('UNIV-RESEARCH','10.20.10.0','10.20.10.1'),),
 'CE-HEALTH':(('HEALTH-LAB','10.30.10.0','10.30.10.1'),),
}


def stamp(): return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def evidence(tag,value):
    folder=BASE/'evidence';folder.mkdir(parents=True,exist_ok=True)
    filename=folder/f'{stamp()}_enterprise_{tag}.json'
    filename.write_text(json.dumps(value,indent=2,default=str)+'\n',encoding='utf-8')
    print('Evidence:',filename)
    return filename


def boot_cmd(source):
    encoded=base64.b64encode(zlib.compress(source.encode('utf-8'),9)).decode('ascii')
    script="import base64,zlib;exec(zlib.decompress(base64.b64decode('"+encoded+"')))"
    return 'python -u -c "'+script+'"'


def check_invariants(inv):
    if inv.get('project')!=PROJECT or inv.get('docker_image')!=IMAGE:
        raise RuntimeError('Project or Docker image differs from the approved inventory')
    if inv.get('service_ip')!=DNS:
        raise RuntimeError('Unapproved service address')
    if len({(x[0],str(x[1])) for x in LINKS})!=len(LINKS):
        raise RuntimeError('Duplicate port assignments')
    for name,entries in DHCP.items():
        for label,prefix,gateway in entries:
            if ipaddress.ip_address(gateway) not in ipaddress.ip_network(prefix+'/24'):
                raise RuntimeError(name+' unexpected DHCP address plan')
    return True


def config(name):
    lines=[]
    if name=='SW-MUNI-HQ':
        lines+=['interface '+HQ_SERVICE_IFACE,
                ' description LOCAL_SHARED_SERVICES_NO_NAT',
                ' switchport mode access',' switchport access vlan 30',
                ' spanning-tree portfast',' no shutdown',' exit',
                'interface '+HQ_DHCP_IFACE,
                ' description DHCP_TEST_HQ',' switchport mode access',
                ' switchport access vlan 10',' spanning-tree portfast',' no shutdown',' exit',
                'logging trap informational','logging '+DNS,'logging source-interface Vlan99']
    elif name=='SW-MUNI-BR':
        lines+=['interface '+BR_DHCP_IFACE,' description DHCP_TEST_BR',
                ' switchport mode access',' switchport access vlan 10',
                ' spanning-tree portfast',' no shutdown',' exit',
                'logging trap informational','logging '+DNS,'logging source-interface Vlan99']
    elif name in CEs:
        if name=='CE-UNIV':
            lines+=['interface GigabitEthernet0/2',' description LOCAL_SERVICE_ONLY_NOT_CUSTOMER_TRANSIT',
                    ' ip address 10.20.254.1 255.255.255.252',' no shutdown',' exit',
                    'ip route 10.10.30.250 255.255.255.255 10.20.254.2']
        elif name=='CE-HEALTH':
            lines+=['interface GigabitEthernet0/2',' description LOCAL_SERVICE_ONLY_NOT_CUSTOMER_TRANSIT',
                    ' ip address 10.30.254.1 255.255.255.252',' no shutdown',' exit',
                    'ip route 10.10.30.250 255.255.255.255 10.30.254.2']
        if name=='CE-MUNI-HQ':
            # The shared service lives in VLAN 30; never offer its fixed address.
            lines.append('ip dhcp excluded-address 10.10.30.250')
        for label,prefix,gateway in DHCP[name]:
            net=ipaddress.ip_network(prefix+'/24')
            a=str(net.network_address+1); b=str(net.network_address+99)
            lines+=['ip dhcp excluded-address '+a+' '+b,
                    'ip dhcp pool NORDNET-'+label,
                    ' network '+prefix+' 255.255.255.0',
                    ' default-router '+gateway,
                    ' dns-server '+DNS,
                    ' domain-name nordnet.test',
                    ' lease 0 12',
                    ' exit']
        # The PE/P devices cannot reach this address in their global table.
        # Only customer CEs ship syslog here; provider telemetry uses --monitor.
        lines+=['service timestamps log datetime msec','logging buffered 32768 informational',
                'logging trap informational','logging '+DNS]
        src={'CE-MUNI-HQ':'GigabitEthernet0/1.30',
             'CE-MUNI-BR':'GigabitEthernet0/1.10',
             'CE-UNIV':'GigabitEthernet0/2','CE-HEALTH':'GigabitEthernet0/2'}[name]
        lines+=['logging source-interface '+src]
    else: raise ValueError('Not an allowed target: '+name)
    return '\n'.join(lines)+'\n'


def render():
    dest=BASE/'generated'/'enterprise';dest.mkdir(parents=True,exist_ok=True)
    for name in CEs+SWs:
        content=config(name)
        (dest/(name+'.cfg')).write_text(content,encoding='utf-8')
    return dest


def connect_gns(api):
    projects=[p for p in api.call('GET','/v2/projects') if p['name']==PROJECT]
    if len(projects)!=1: raise RuntimeError(f'Required project {PROJECT!r} not unique')
    pr=projects[0]
    if pr['status']!='opened':
        raise RuntimeError(f'Open project {PROJECT!r} in GNS3 before running this package')
    comps={c['compute_id']:c for c in api.call('GET','/v2/computes')}
    vm=comps.get('vm')
    if not vm or not vm.get('connected'):
        raise RuntimeError('Connected GNS3 VM compute "vm" missing')
    return '/v2/projects/'+pr['project_id'],vm


def port(node,iface):
    ports=node.get('ports',[])
    if isinstance(iface,int):
        matches=[x for x in ports if x.get('adapter_number')==iface and x.get('port_number')==0]
    else:
        matches=[x for x in ports if old.port_norm(x['name']).lower()==old.port_norm(iface).lower()]
    if len(matches)!=1:
        raise RuntimeError(f'{node["name"]}: cannot find interface {iface!r}, ports={[x["name"] for x in ports]}')
    p=matches[0]
    return {'node_id':node['node_id'],'adapter_number':p['adapter_number'],'port_number':p['port_number']}


def eid(p): return (p['node_id'],p['adapter_number'],p['port_number'])


def check_topology(api,path,nodes,expect_built=False):
    original=set(old.ROUTERS+old.SWITCHES+tuple(e['name'] for e in yaml.safe_load((BASE/'inventory.yaml').read_text())['endpoints']))
    allowed=original|set(NODES)
    if not original.issubset(nodes) or set(nodes)-allowed:
        raise RuntimeError('NORDNET nodes missing or unexpected devices present; refusing changes')
    if SERVICE in nodes:
        svc=nodes[SERVICE]
        if svc['node_type']!='docker' or svc['compute_id']!='vm' or svc['properties'].get('image')!=IMAGE:
            raise RuntimeError('Service node type, compute or image unexpectedly changed')
        if svc['properties'].get('adapters')!=3:
            raise RuntimeError('Service node adapter count unexpectedly changed')
    for n in ('PC-HQ-DHCP','PC-BR-DHCP'):
        if n in nodes and (nodes[n]['node_type']!='vpcs' or nodes[n]['compute_id']!='vm'):
            raise RuntimeError(n+' is not a VM-compute VPCS device')
    links=api.call('GET',path+'/links')
    all_existing={frozenset(eid(x) for x in link['nodes']) for link in links}
    # Compare all 6.1 links, not just the original provider backbone.
    old_inv=yaml.safe_load((BASE/'inventory.yaml').read_text())
    if not {old.linkkey(nodes,l) for l in old.desired_links(old_inv)}.issubset(all_existing):
        raise RuntimeError('Previously validated Phase 6.1 links changed')
    # Validate every source interface BEFORE creating any enterprise nodes.
    # Previously we skipped checking Gi0/4 until the Docker and VPCS nodes
    # had already been created, leaving a partial deployment behind.
    reserved=[]
    for a,ai,b,bi in LINKS:
        if a not in nodes:
            raise RuntimeError('Missing existing enterprise link parent: '+a)
        reserved.append(eid(port(nodes[a],ai)))
    if len(reserved)!=len(set(reserved)):
        raise RuntimeError('Duplicate enterprise source-port reservation')
    target={}
    for a,ai,b,bi in LINKS:
        if a in nodes and b in nodes:
            pa,pb=port(nodes[a],ai),port(nodes[b],bi)
            target[frozenset((eid(pa),eid(pb)))]=(pa,pb)
        elif expect_built: raise RuntimeError('Required enterprise node missing')
    for ln in links:
        for endpoint in ln['nodes']:
            if endpoint['node_id'] not in {n['node_id'] for n in nodes.values()}:
                raise RuntimeError('Unknown link endpoint')
    allowed_links={old.linkkey(nodes,l) for l in old.desired_links(old_inv)}|set(target)
    if all_existing-allowed_links:
        raise RuntimeError('Unexpected links in project. Review before using additive enterprise builder.')
    used={x for lk in all_existing for x in lk}
    for key,(pa,pb) in target.items():
        if key not in all_existing and (eid(pa) in used or eid(pb) in used):
            raise RuntimeError('Already occupied interface: '+repr((pa,pb)))
    return target, all_existing


def images_available(api):
    # Controller forwards to the compute; do not auto-pull from Internet.
    try: return api.call('GET','/v2/computes/vm/docker/images')
    except RuntimeError as exc:
        raise RuntimeError('Cannot query Docker images on VM; enable Docker support in GNS3 VM') from exc


def check_image(api,vm):
    caps=vm.get('capabilities',{}).get('node_types',[])
    if 'docker' not in caps: raise RuntimeError('Docker compute capability unavailable on GNS3 VM')
    images=images_available(api)
    if IMAGE not in str(images):
        raise RuntimeError(f'Docker image {IMAGE} missing on the GNS3 VM; run "docker pull {IMAGE}" in the GNS3 VM shell, then retry')


def phase6_baseline(nodes,vm):
    inv=yaml.safe_load((BASE/'inventory.yaml').read_text())
    inv['project']=PROJECT
    old.validate(inv)
    print('Checking validated Phase 6.1 running baseline (read-only)...')
    old.verify(nodes,vm['host'],inv)


def probe_ios_console(node, vm, timeout=12):
    """Read-only short probe. Never starts, stops or configures a node.

    Verifies that the responding console hostname equals the expected GNS3
    node name; an open TCP socket alone is not proof of a running IOS router.
    """
    from ios_console import recv_prompt, last_line
    import telnetlib
    host=console_host(node,vm['host'])
    port=node.get('console')
    if port is None:
        return False, 'No Telnet console assigned'
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            tn=telnetlib.Telnet(host,int(port),timeout=3)
        try:
            tn.write(b'\r\n')
            prompt=last_line(recv_prompt(tn,timeout=timeout,first_boot=False))
            if prompt not in (node['name']+'#',node['name']+'>'):
                return False, f'Unexpected IOS prompt {prompt!r}'
            output=command(tn,'show clock',timeout=timeout)
            ending=last_line(output)
            if ending not in (node['name']+'#',node['name']+'>'):
                return False, f'show clock did not return expected prompt: {ending!r}'
            return True, 'show clock returned expected '+ending+' prompt'
        finally:
            tn.close()
    except (OSError, EOFError, TimeoutError, RuntimeError, ValueError) as exc:
        return False, str(exc)


def verified_ios_state(api,path,node,vm):
    """Guard against stale bulk API status without masking a real outage."""
    name=node['name']
    reported=node.get('status','missing')
    if reported=='started':
        return {'name':name,'bulk_status':reported,'detail_status':reported,'proof':'bulk-api'}
    print(f'NOTICE: {name} bulk API status={reported!r}; checking individual node status...',flush=True)
    detail=api.call('GET',path+'/nodes/'+node['node_id'])
    if detail.get('node_id')!=node['node_id'] or detail.get('name')!=name:
        raise RuntimeError(name+' individual API response does not match expected node identity')
    current=detail.get('status','missing')
    if current=='started':
        print(f'PASS: {name} individual API reports started (bulk listing was {reported!r})')
        return {'name':name,'bulk_status':reported,'detail_status':current,'proof':'individual-api'}
    ok,why=probe_ios_console(detail,vm)
    if ok:
        print(f'WARNING: {name} API reports {current!r}, but live IOS console responds: {why}')
        print('         Check GNS3 controller/GUI state synchronization before future maintenance.')
        return {'name':name,'bulk_status':reported,'detail_status':current,'proof':'read-only-ios-console'}
    raise RuntimeError(f'{name} could not be verified running: bulk API={reported!r}, '
                       f'individual API={current!r}; console check failed: {why}. '
                       'Do not restart the provider core automatically; inspect node state in GNS3.')


def status_report(api,path,vm,nodes):
    """No topology changes, starts, stops, commits, or config changes."""
    report={'type':'enterprise_node_status_diagnostics','nodes':{},'project':PROJECT}
    for name in ROUTERS+SWs:
        node=nodes[name]
        bulk=node.get('status','missing')
        print(f'{name:12} bulk API={bulk!r} compute={node.get("compute_id")!r}')
        detail=api.call('GET',path+'/nodes/'+node['node_id'])
        current=detail.get('status','missing')
        print(f'             individual API={current!r}')
        entry={'bulk_status':bulk,'detail_status':current,'compute_id':node.get('compute_id')}
        if name=='PE1' or current!='started' or bulk!='started':
            ok,why=probe_ios_console(detail,vm)
            entry['console_ok']=ok
            entry['console_result']=why
            print(f'             live console={"PASS" if ok else "FAIL"}: {why}')
        report['nodes'][name]=entry
    evidence('status',report)
    print('Status diagnostics did not change GNS3 or IOS configurations.')
    return report


def preflight(api,path,vm,full=True):
    nodes=old.get_nodes(api,path)
    check_topology(api,path,nodes)
    check_image(api,vm)
    for name in ROUTERS+SWs:
        verified_ios_state(api,path,nodes[name],vm)
    # Before linking Gi0/2, ensure the interface is not already an unrelated service.
    for name in ('CE-UNIV','CE-HEALTH'):
        cfg=old.cli(nodes[name],vm['host'],['show running-config interface GigabitEthernet0/2'])
        text=cfg['show running-config interface GigabitEthernet0/2']
        if '10.20.254.1' in text and name=='CE-UNIV': continue
        if '10.30.254.1' in text and name=='CE-HEALTH': continue
        if re.search(r'(?m)^\s+ip address\s+\d',text):
            raise RuntimeError(name+' Gi0/2 already has an unexpected address')
    if full: phase6_baseline(nodes,vm)
    print('PASS: API, project, previous links, Docker image, free CE service interfaces')
    return nodes


def build(api,path,vm):
    nodes=old.get_nodes(api,path)
    check_topology(api,path,nodes)
    check_image(api,vm)
    if SERVICE not in nodes:
        source=SERVICE_FILE.read_text(encoding='utf-8')
        props={'image':IMAGE,'adapters':3,'start_command':boot_cmd(source),
               'console_type':'telnet','extra_volumes':['/data']}
        print('Creating:',SERVICE)
        api.call('POST',path+'/nodes',{'compute_id':'vm','name':SERVICE,'node_type':'docker',
                    'x':-430,'y':-600,'properties':props})
    for name,x,y in [('PC-HQ-DHCP',-1100,-390),('PC-BR-DHCP',690,480)]:
        if name not in nodes:
            print('Creating:',name)
            api.call('POST',path+'/nodes',{'compute_id':'vm','name':name,'node_type':'vpcs',
                                          'x':x,'y':y})
    nodes=old.get_nodes(api,path)
    target,exists=check_topology(api,path,nodes,expect_built=True)
    for key,(p1,p2) in target.items():
        if key not in exists:
            print('Creating enterprise link:',p1['node_id'],'<->',p2['node_id'])
            api.call('POST',path+'/links',{'nodes':[p1,p2]})
    nodes=old.get_nodes(api,path)
    check_topology(api,path,nodes,expect_built=True)
    print('PASS: enterprise nodes and five links in place (idempotent)')
    return nodes


def start(api,path,nodes):
    for name in NODES:
        node=nodes[name]
        if node['status']!='started':
            print('Starting',name)
            api.call('POST',path+'/nodes/'+node['node_id']+'/start',{})
    return old.get_nodes(api,path)


def docker_health(node,vm,seconds=22):
    if sys.version_info[:2]!=(3,12):
        raise RuntimeError('Use Python 3.12 for GNS3 Telnet consoles')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',DeprecationWarning)
        import telnetlib
    if node.get('console') is None: raise RuntimeError('Docker node has no Telnet console')
    addr=console_host(node,vm['host'])
    deadline=time.monotonic()+seconds
    result=''
    try:
        tn=telnetlib.Telnet(addr,int(node['console']),timeout=8)
        try:
            while time.monotonic()<deadline:
                chunk=tn.read_very_eager().decode('utf-8',errors='replace')
                result+=chunk
                if 'NORDNET_SERVICES_HEALTH ready=1 forwarding=0 dns=ok http=ok syslog=ok' in result:
                    return True,result[-2000:]
                time.sleep(0.4)
        finally: tn.close()
    except (OSError,EOFError,TimeoutError) as exc:
        return False,str(exc)
    return False,result[-2000:] or 'No service heartbeat received'


def cfg_snapshot(nodes,vm,names,tag):
    backup={}
    for name in names:
        print('Reading running configuration:',name)
        backup[name]=old.cli(nodes[name],vm['host'],['show running-config'])['show running-config']
    evidence(tag,backup)
    return backup


def safe_config(name,running):
    if name in ('CE-UNIV','CE-HEALTH'):
        # These interfaces should not already host an unrelated network.
        if not re.search(r'(?m)^interface GigabitEthernet0/2\s*$',running):
            return
        block=re.search(r'(?ms)^interface GigabitEthernet0/2\s*\n(.*?)(?=^!|^interface |\Z)',running)
        body=block.group(1) if block else ''
        expected='10.20.254.1' if name=='CE-UNIV' else '10.30.254.1'
        for ip in re.findall(r'(?m)^ ip address\s+(\d+\.\d+\.\d+\.\d+)',body):
            if ip!=expected: raise RuntimeError(name+' Gi0/2 unexpectedly configured for another network')


def configure_device(node,vm,name):
    tn=open_console(console_host(node,vm['host']),node['console'])
    try:
        running=command(tn,'show running-config',timeout=100)
        safe_config(name,running)
        print('Applying',name,'enterprise additive configuration')
        command(tn,'configure terminal')
        for line in config(name).splitlines():
            if line.strip(): command(tn,line,timeout=45)
        command(tn,'end')
        # Do not save to NVRAM until verification passes.
    finally: tn.close()


def apply(api,path,vm,nodes):
    check_topology(api,path,nodes,expect_built=True)
    cfg_snapshot(nodes,vm,CEs+SWs,'prechange')
    nodes=start(api,path,nodes)
    good,details=docker_health(nodes[SERVICE],vm)
    if not good:
        raise RuntimeError('Local Docker services did not report READY/forwarding OFF. '+details)
    print('PASS: Local DNS/HTTP/syslog process started with forwarding disabled')
    for name in SWs+CEs:
        configure_device(nodes[name],vm,name)
    # DHCP clients, no changes to the original seven VPCS nodes.
    for name in ('PC-HQ-DHCP','PC-BR-DHCP'):
        print('Requesting DHCP lease:',name)
        response=old.vpcs_commands(nodes[name],vm['host'],['ip dhcp','save'])
        if re.search(r'(?i)(unable to|no dhcp|dhcp.*failed|invalid|unknown command)',str(response)):
            raise RuntimeError(name+' failed DHCP request: '+str(response)[-500:])
    print('Enterprise changes applied to running configs only; run --verify, then --commit')


def verify(api,path,vm,nodes):
    results={};failures=[]
    check_topology(api,path,nodes,expect_built=True)
    for name in NODES:
        status=nodes[name].get('status','missing')
        if status!='started':
            detail=api.call('GET',path+'/nodes/'+nodes[name]['node_id'])
            if detail.get('status')!='started':
                print(f'NOTICE: {name} API status={status!r}/{detail.get("status")!r}; using service/VPCS protocol tests below to confirm reachability')
    try:
        phase6_baseline(nodes,vm)
        results['phase6_baseline']='pass'
    except Exception as exc:
        failures.append('Phase 6.1 baseline changed: '+str(exc))
    health,details=docker_health(nodes[SERVICE],vm)
    results['services_console']=details
    if not health: failures.append('Docker service heartbeat not verified')
    for name in CEs:
        cmds=['show ip dhcp pool','show running-config | include logging','show ip route '+DNS]
        if name=='CE-UNIV': cmds+=['ping '+DNS+' source 10.20.254.1']
        if name=='CE-HEALTH': cmds+=['ping '+DNS+' source 10.30.254.1']
        try:
            data=old.cli(nodes[name],vm['host'],cmds)
            results[name]=data
            if 'NORDNET-' not in data['show ip dhcp pool']:
                failures.append(name+' has no NORDNET DHCP pool')
            if name in ('CE-UNIV','CE-HEALTH'):
                count=old.ios_ping_count(data[cmds[-1]])
                if not count or count[1]!=5 or count[0]<4:
                    failures.append(name+' cannot reach local services through private /30 attachment')
        except Exception as exc:
            failures.append(name+' verification error: '+str(exc))
    for name in ('PC-HQ-STAFF','PC-BR-STAFF','PC-UNIV','PC-HEALTH'):
        try:
            sample=old.vpcs_commands(nodes[name],vm['host'],['ping '+DNS])['ping '+DNS]
            results[name]=sample
            if not old.vpcs_received_reply(sample):
                failures.append(name+' cannot reach shared service IP')
        except Exception as exc:
            failures.append(name+' ping error: '+str(exc))
    for name,net in (('PC-HQ-DHCP','10.10.10.'),('PC-BR-DHCP','10.11.10.')):
        try:
            data=old.vpcs_commands(nodes[name],vm['host'],['show ip','ping '+('10.10.10.1' if name=='PC-HQ-DHCP' else '10.11.10.1')])
            results[name]=data
            if net not in data['show ip']:
                failures.append(name+' no expected DHCP lease address')
            if not old.vpcs_received_reply(data[next(k for k in data if k.startswith('ping'))]):
                failures.append(name+' DHCP client gateway unreachable')
        except Exception as exc:
            failures.append(name+' DHCP check error: '+str(exc))
    results['passed']=not failures;results['failures']=failures
    evidence('verification',results)
    if failures:
        for issue in failures: print('FAIL:',issue)
        raise RuntimeError('Enterprise integration verification FAILED; configurations not saved to startup-config')
    print('PASS: Phase 6.1 baseline, live shared-service IP, DHCP, Docker health, customer isolation and service attachments')
    print('NOTE: DNS/HTTP protocol behavior and syslog reception require separate end-to-end probes; see README')
    return results


def commit(nodes,vm):
    # Caller must have run verify successfully in the same process.
    for name in SWs+CEs:
        print('Saving to startup-config:',name)
        old.cli(nodes[name],vm['host'],['write memory'])
    cfg_snapshot(nodes,vm,SWs+CEs,'postcommit')
    print('PASS: six modified IOS devices saved')


def monitor(api,path,vm,nodes):
    report={'controller_version':api.call('GET','/v2/version'),
            'nodes':{k:{'status':v['status'],'node_type':v['node_type']} for k,v in nodes.items()},
            'outputs':{}}
    checks={
        'PE1':['show ip ospf neighbor','show mpls ldp neighbor','show ip bgp vpnv4 all summary','show ip route vrf MUNI'],
        'PE2':['show ip ospf neighbor','show mpls ldp neighbor','show ip bgp vpnv4 all summary','show ip route vrf MUNI'],
        'P1':['show ip ospf neighbor','show mpls ldp neighbor'],
        'P2':['show ip ospf neighbor','show mpls ldp neighbor'],
        'CE-MUNI-HQ':['show ip bgp summary','show logging | include SYS'],
        'CE-MUNI-BR':['show ip bgp summary','show logging | include SYS'],
        'CE-UNIV':['show ip bgp summary'],
        'CE-HEALTH':['show ip bgp summary'],
        'SW-MUNI-HQ':['show interfaces trunk','show vlan brief'],
        'SW-MUNI-BR':['show interfaces trunk','show vlan brief'],
    }
    for name,cmds in checks.items():
        print('Monitoring',name)
        try: report['outputs'][name]=old.cli(nodes[name],vm['host'],cmds)
        except Exception as exc: report['outputs'][name]={'error':str(exc)}
    evidence('monitor',report)
    print('Snapshot saved; this is a one-time monitoring collection, not a continuous SIEM')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    m=p.add_mutually_exclusive_group(required=True)
    for mode in ('plan','preflight','build','apply','verify','commit','deploy','monitor','status'):
        m.add_argument('--'+mode,action='store_true')
    p.add_argument('--approve-maintenance',action='store_true')
    p.add_argument('--url',default='http://127.0.0.1:3080')
    p.add_argument('--user',default='admin')
    args=p.parse_args()
    inv=yaml.safe_load((BASE/'enterprise_inventory.yaml').read_text(encoding='utf-8'))
    inv['project']=PROJECT
    check_invariants(inv)
    path_cfg=render()
    if args.plan:
        print('NORDNET local enterprise plan: ONE Docker shared-services node; two DHCP test VPCS; five links;')
        print('6 additive IOS configuration updates on CEs/switches; no P/PE or VRF/RT/BGP changes.')
        print('Image:',IMAGE,'Service:',DNS,'TCP 53/8080, UDP 53/514')
        for cfg in sorted(path_cfg.glob('*.cfg')): print('Review:',cfg)
        print('Prerequisite: Docker image already present on GNS3 VM; no automatic Docker Hub pull.')
        print('Shared service is multi-homed, NOT a new SHARED VRF or a firewall appliance.')
        return
    if sys.version_info[:2]!=(3,12): raise RuntimeError('Use Python 3.12')
    if (args.apply or args.commit or args.deploy) and not args.approve_maintenance:
        raise RuntimeError('Use --approve-maintenance after exporting the known-good Phase 6.1 GNS3 project')
    api=old.GNS(args.url,args.user,getpass('GNS3 API password: '))
    path,vm=connect_gns(api)
    nodes=old.get_nodes(api,path)
    if args.status:
        status_report(api,path,vm,nodes);return
    if args.preflight:
        preflight(api,path,vm);return
    if args.monitor:
        monitor(api,path,vm,nodes);return
    if args.verify:
        verify(api,path,vm,nodes);return
    if args.commit:
        verify(api,path,vm,nodes)
        commit(nodes,vm);return
    if args.build:
        preflight(api,path,vm)
        build(api,path,vm);return
    if args.apply:
        check_topology(api,path,nodes,expect_built=True)
        phase6_baseline(nodes,vm)
        apply(api,path,vm,nodes);return
    if args.deploy:
        preflight(api,path,vm)
        nodes=build(api,path,vm)
        apply(api,path,vm,nodes)
        nodes=old.get_nodes(api,path)
        verify(api,path,vm,nodes)
        commit(nodes,vm)
        return

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,KeyError,requests.RequestException,KeyboardInterrupt) as exc:
        print('ERROR:',exc,file=sys.stderr)
        sys.exit(1)
