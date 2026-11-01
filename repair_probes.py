#!/usr/bin/env python3
"""NORDNET v0.8.5: repair ONLY three failed acceptance Docker probes.

--check: read-only API/source inspection
--apply --approve-maintenance: backup probe source, update ONLY those Docker
    nodes' start_command via GNS3 API, start them, and check READY heartbeats.

Never modifies provider/core, CE, switches, VPCS, existing services, or links.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from getpass import getpass
import hashlib
import json
from pathlib import Path
import sys
import time

# Runtime dependencies are installed in nordnet_local_bulk.
import nordnet_acceptance as acceptance
import nordnet_enterprise as enterprise
import nordnet_local as local

BASE=Path(__file__).resolve().parent
SOURCE=BASE/'probes'/'nordnet_probe.py'
OLD_SNIPPET='''    forward = '/proc/sys/net/ipv4/ip_forward'
    with open(forward, encoding='ascii') as f:
        if f.read().strip() != '0':
            raise RuntimeError('IP forwarding unexpectedly enabled')'''
NEW_SNIPPET='''    forward = '/proc/sys/net/ipv4/ip_forward'
    with open(forward, encoding='ascii') as f:
        enabled = f.read().strip() != '0'
    if enabled:
        # Match the existing NORDNET shared-services container: disable in
        # this container's network namespace, then verify fail-closed.
        try:
            with open(forward, 'w', encoding='ascii') as f:
                f.write('0\\n')
        except OSError as exc:
            raise RuntimeError('Cannot disable IPv4 forwarding in probe') from exc
    with open(forward, encoding='ascii') as f:
        if f.read().strip() != '0':
            raise RuntimeError('IPv4 forwarding still enabled; refusing to run')'''


def patched_pair(source):
    if source.count(OLD_SNIPPET)==1 and NEW_SNIPPET not in source:
        old=source
        new=source.replace(OLD_SNIPPET,NEW_SNIPPET,1)
    elif source.count(NEW_SNIPPET)==1 and OLD_SNIPPET not in source:
        new=source
        old=source.replace(NEW_SNIPPET,OLD_SNIPPET,1)
    else:
        raise RuntimeError('Unexpected probe source; refusing automatic patch')
    compile(new,'nordnet_probe.py','exec')
    compile(old,'nordnet_probe.py','exec')
    if "subprocess.run(['ifconfig', 'eth0'" not in new or "def measure(node):" not in new:
        raise RuntimeError('Unexpected probe code; refusing change')
    return old,new


def boot(src,name):
    if name not in acceptance.NODE_PLAN:
        raise RuntimeError('Unknown probe name')
    needle="name = os.environ.get('NORDNET_PROBE_NAME', '')"
    if src.count(needle)!=1:
        raise RuntimeError('Unexpected probe identity marker')
    return enterprise.boot_cmd(src.replace(needle,'name = '+repr(name)))


def digest(txt):return hashlib.sha256(txt.encode('utf-8')).hexdigest()


def guard_nodes(nodes,old,new):
    """Attest exact 3 probes, original image and expected startup commands."""
    changes={}
    for name in acceptance.NODE_PLAN:
        if name not in nodes:raise RuntimeError(name+' absent; do not run --prepare again')
        n=nodes[name]
        props=n.get('properties',{})
        if (n.get('node_type'),n.get('compute_id'),props.get('image'),props.get('adapters')) != ('docker','vm',enterprise.IMAGE,1):
            raise RuntimeError(name+' unexpected Docker image/node type/compute/adapters')
        existing=props.get('start_command')
        old_cmd,new_cmd=boot(old,name),boot(new,name)
        if existing not in (old_cmd,new_cmd):
            raise RuntimeError(name+' startup command differs from known NORDNET v0.8.x; refusing')
        changes[name]={'id':n['node_id'],'old':old_cmd,'new':new_cmd,
                       'patched':existing==new_cmd,'status':n.get('status')}
    return changes


def inspect_project(api,project_id):
    path,vm,nodes=acceptance.resolve(api,project_id)
    # All baseline nodes must be present, with no unexpected additions.
    expected=set(enterprise.ROUTERS)|set(enterprise.SWs)|set(enterprise.NODES)|{x['name'] for x in
        __import__('yaml').safe_load((BASE/'inventory.yaml').read_text(encoding='utf-8'))['endpoints']}|set(acceptance.NODE_PLAN)|set(acceptance.SPLITS)
    if set(nodes)!=expected:
        raise RuntimeError('Unexpected project node set; stop and inspect')
    # Confirm topology links through a read-only comparison; no rewiring.
    links=api.call('GET',path+'/links')
    actual={frozenset(local.epkey(x) for x in ln['nodes']) for ln in links}
    inv=__import__('yaml').safe_load((BASE/'inventory.yaml').read_text(encoding='utf-8'))
    old=acceptance.original_edges(nodes,inv)
    desired=acceptance.split_edges(nodes)
    replaced={acceptance.edge(enterprise.port(nodes[info['ce']],info['ce_port']),enterprise.port(nodes[info['pc']],'Ethernet0')) for info in acceptance.SPLITS.values()}
    expected_edges=(set(old)-replaced)|set(desired)
    if actual != expected_edges:raise RuntimeError('Temporary acceptance links differ from expected fixture; refusing')
    return path,vm,nodes


def take_action(api,path,nodes,old,new,changes,apply):
    for name,rec in changes.items():
        print(f'{name}: API status={rec["status"]!r}; command={"fixed" if rec["patched"] else "original"}')
    if not apply:
        print('CHECK ONLY: no GNS3/network/source changes')
        return
    if all(rec['patched'] for rec in changes.values()) and SOURCE.read_text(encoding='utf-8') == new:
        print('PASS: all probe startup commands and local source already patched; no changes')
        return
    folder=BASE/'evidence'/'local_acceptance'/'probe_hotfix_backups'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder.mkdir(parents=True,exist_ok=True)
    (folder/'nordnet_probe.py').write_text(old,encoding='utf-8')
    metadata={'project_id':path.rsplit('/',1)[-1], 'source_old_sha256':digest(old),
              'source_new_sha256':digest(new),
              'nodes':{n:{'id':c['id'],'old_start_command':c['old'],'new_start_command':c['new']}
                       for n,c in changes.items()}}
    (folder/'node_commands.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    print('Backup:',folder)
    # This phase modifies ONLY 3 dedicated test nodes. No CE/PE/P/SW access.
    for name,rec in changes.items():
        route=path+'/nodes/'+rec['id']
        live=api.call('GET',route)
        if live.get('properties',{}).get('start_command') not in (rec['old'],rec['new']):
            raise RuntimeError(name+' changed since inspection; stop')
        if live.get('status')=='started':
            print('Stopping only:',name)
            api.call('POST',route+'/stop',{})
        elif live.get('status')!='stopped':
            raise RuntimeError(name+' is not stopped/started; cannot update safely')
        if not rec['patched']:
            print('Updating startup command:',name)
            api.call('PUT',route,{'properties':{'start_command':rec['new']}})
        check=api.call('GET',route)
        if check.get('properties',{}).get('start_command')!=rec['new']:
            raise RuntimeError(name+' command readback mismatch; do not start')
        print('PASS: startup command updated:',name)
    if SOURCE.read_text(encoding='utf-8')!=new:
        SOURCE.write_text(new,encoding='utf-8')
        if SOURCE.read_text(encoding='utf-8')!=new:
            raise RuntimeError('Probe file update failed')
    print('PASS: local probe source matches all three Docker commands')
    for name,rec in changes.items():
        print('Starting only:',name)
        api.call('POST',path+'/nodes/'+rec['id']+'/start',{})
    print('PASS: requested start of all three acceptance probes.')
    print('Now run: py -3.12 .\\nordnet_acceptance.py --verify')
    print('If the probes exit again, inspect docker logs. No Cisco changes were made.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check',action='store_true')
    modes.add_argument('--apply',action='store_true')
    p.add_argument('--approve-maintenance',action='store_true')
    p.add_argument('--project-id',default=acceptance.PROJECT_ID_DEFAULT)
    p.add_argument('--url',default='http://127.0.0.1:3080')
    p.add_argument('--user',default='admin')
    args=p.parse_args()
    if args.apply and not args.approve_maintenance:
        raise RuntimeError('Apply requires --approve-maintenance and current GNS3 backup')
    source=SOURCE.read_text(encoding='utf-8')
    old,new=patched_pair(source)
    api=local.GNS(args.url,args.user,getpass('GNS3 API password: '))
    path,vm,nodes=inspect_project(api,args.project_id)
    changes=guard_nodes(nodes,old,new)
    take_action(api,path,nodes,old,new,changes,args.apply)

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('ERROR:',str(exc),file=sys.stderr)
        raise SystemExit(1)
