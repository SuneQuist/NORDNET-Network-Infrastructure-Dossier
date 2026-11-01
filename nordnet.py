#!/usr/bin/env python3
"""NORDNET consolidated local deployment/controller (Python 3.12).

Modes:
  plan       Offline review: exact phase sequence; no API calls.
  preflight  Read-only GNS3 project, template and compute inspection.
  deploy     Fresh project build, or guarded enterprise add-on on an existing Phase 6.1 lab.
  validate   Read-only Phase 6.1 + enterprise service verification on a 20-node lab.
  recover-dhcp  Request/verify DHCP leases on two VPCS only (explicit maintenance flag).
  prefix     Delegate to offline CIDR/prefix helper.

No automatic project deletion, router erase, VPN exposure, or Docker image pull.
The historical phases support a scoped target project name, without changing the address plan.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from getpass import getpass
import importlib.util
import json
import os
from pathlib import Path
import sys
import re
import time
from contextlib import contextmanager
import requests
from requests.auth import HTTPBasicAuth

ROOT=Path(__file__).resolve().parent
PROJECT='NORDNET-Core-POC'
ENV_PROJECT="NORDNET_TARGET_PROJECT"
TEMPLATES=('Cisco IOSv 15.9(3)M8','Cisco IOSvL2 15.2.1')
ROUTERS={'PE1','P1','PE2','P2','CE-MUNI-HQ','CE-MUNI-BR','CE-UNIV','CE-HEALTH'}
NAMES_17=ROUTERS|{'SW-MUNI-HQ','SW-MUNI-BR','PC-HQ-STAFF','PC-HQ-ADMIN','PC-HQ-SVC','PC-BR-STAFF','PC-BR-SVC','PC-UNIV','PC-HEALTH'}
NAMES_20=NAMES_17|{'SVC-NORDNET-LOCAL','PC-HQ-DHCP','PC-BR-DHCP'}
FIXTURE={'PROBE-MUNI','PROBE-UNIV','PROBE-HEALTH','LAN-UNIV-SW','LAN-HEALTH-SW'}
PHASES=[
 ('01 Create core topology','phases/phase1/nordnet_gns3_phase1.py',['--start']),
 ('02 Configure OSPF/LDP underlay','phases/phase2/nordnet_phase2.py',['--apply']),
 ('03 Configure municipal MPLS L3VPN','phases/phase3/nordnet_phase3.py',['--apply']),
 ('03 Verify municipal VPN','phases/phase3/nordnet_phase3.py',['--verify']),
 ('04 Deploy redundant transit P2','phases/phase4/nordnet_phase4.py',['--apply']),
 ('04 Verify redundant provider routing','phases/phase4/nordnet_phase4.py',['--verify']),
 ('05 Deploy UNIV and HEALTH VRFs','phases/phase5/nordnet_phase5.py',['--apply']),
 ('05 Verify organisations / customer isolation','phases/phase5/nordnet_phase5.py',['--verify']),
 ('06 Deploy local switches, VLANs and VPCS','nordnet_local.py',['--apply','--approve-maintenance']),
 ('06 Verify LAN and isolation','nordnet_local.py',['--verify']),
 ('07 Preflight Docker and enterprise connections','nordnet_enterprise.py',['--preflight']),
 ('07 Build service and DHCP nodes','nordnet_enterprise.py',['--build']),
 ('07 Apply local DNS/HTTP/syslog and DHCP','nordnet_enterprise.py',['--apply','--approve-maintenance']),
]

class Controller:
 def __init__(self,url,user,password):
  self.url=url.rstrip('/');self.session=requests.Session()
  self.session.auth=HTTPBasicAuth(user,password)
 def get(self,path):
  r=self.session.get(self.url+path,timeout=25)
  if not r.ok:raise RuntimeError(f'GNS3 GET {path} HTTP {r.status_code}: {r.text[:250]}')
  return r.json()


def valid_name(name):
 """GNS3 project names are free text, but never accept ambiguous/unsafe names."""
 if not isinstance(name,str) or name.strip()!=name or not name or len(name)>100:
  raise RuntimeError('Project --name must be 1-100 characters with no surrounding whitespace')
 if any(ord(c)<32 or ord(c)==127 for c in name) or any(c in name for c in ('/', '\\')):
  raise RuntimeError('Project --name contains invalid control or path characters')
 return name

@contextmanager
def project_context(name):
 """Give every historical stage exactly one target name; restore caller environment."""
 name=valid_name(name)
 previous=os.environ.get(ENV_PROJECT)
 os.environ[ENV_PROJECT]=name
 try:yield
 finally:
  if previous is None:os.environ.pop(ENV_PROJECT,None)
  else:os.environ[ENV_PROJECT]=previous


def project_status(api,name=PROJECT):
 name=valid_name(name)
 matches=[p for p in api.get('/v2/projects') if p.get('name')==name]
 if len(matches)>1:raise RuntimeError('Duplicate project names; refusing to select one')
 if not matches:return None,set(),None
 p=matches[0]
 if p.get('status')!='opened':raise RuntimeError(f'Open project {name!r} in GNS3 before use')
 path=f"/v2/projects/{p['project_id']}"
 nodes=api.get(path+'/nodes')
 names=[n['name'] for n in nodes]
 if len(names)!=len(set(names)):raise RuntimeError('Duplicate node names in project')
 return p,set(names),{n['name']:n for n in nodes}


def require_state(api, mode, purpose, name=PROJECT):
 p,names,nodes=project_status(api,name)
 if mode=='fresh':
  if p is not None:
   raise RuntimeError(f'Fresh mode REFUSES existing project {name!r}; choose a different --name. Never overwrites projects.')
 else:
  if p is None:raise RuntimeError(f'Existing mode requires an open project named {name!r}')
  if names==NAMES_20:return p,names,nodes
  if names==NAMES_17 and purpose=='deploy':return p,names,nodes
  if names==NAMES_20|FIXTURE:
   raise RuntimeError('25-node temporary acceptance fixture detected. Run the validated acceptance --restore procedure first; do not redeploy.')
  raise RuntimeError(f'Unsupported existing project layout ({len(names)} nodes). No automatic replay over partial or unknown projects. Nodes: {sorted(names)}')
 return p,names,nodes


def preflight(api,mode,purpose,name=PROJECT):
 version=api.get('/v2/version')
 compute=next((x for x in api.get('/v2/computes') if x.get('compute_id')=='vm'),None)
 if not compute or not compute.get('connected'):
  raise RuntimeError('GNS3 VM compute id vm not connected')
 caps=compute.get('capabilities',{}).get('node_types',[])
 if not {'qemu','docker'}.issubset(caps):
  raise RuntimeError('GNS3 VM must advertise QEMU and Docker; got '+str(caps))
 p,names,nodes=require_state(api,mode,purpose,name)
 templates=api.get('/v2/templates')
 required=TEMPLATES if mode=='fresh' else ()
 for name in required:
  matches=[t for t in templates if t.get('name')==name and t.get('template_type')=='qemu']
  if len(matches)!=1 or matches[0].get('compute_id') not in (None,'vm'):
   raise RuntimeError('Missing/ambiguous QEMU template: '+name)
 if (mode=='fresh' or purpose=='deploy'):
  # Check before touching a single IOS node. Do not pull an image automatically.
  images=api.get('/v2/computes/vm/docker/images')
  if 'python:3.12-alpine' not in str(images):
   raise RuntimeError('Docker image python:3.12-alpine not on VM. Run docker pull python:3.12-alpine in GNS3 VM, then retry.')
 if p:
  print('Project:',p['name'],'UUID:',p['project_id'],'nodes:',len(names))
 print('GNS3:',version.get('version'),'compute vm:',compute.get('host','?'))
 print('PASS: read-only safety preflight; no changes')
 return p,names,nodes


@contextmanager
def load_stage(filename,stage):
 path=(ROOT/filename).resolve()
 if not path.is_file():raise RuntimeError('Missing bundled stage '+str(path))
 old_argv=sys.argv[:];old_path=sys.path[:]
 # Different historical phases bundle different ios_console adapters.
 # Never accidentally import a previous phase's adapter by module cache.
 previous_ios=sys.modules.pop('ios_console',None)
 sys.path.insert(0,str(path.parent));sys.argv=[str(path)]+list(stage)
 try:
  module_name='nordnet_bundle_'+path.stem
  spec=importlib.util.spec_from_file_location(module_name,path)
  module=importlib.util.module_from_spec(spec)
  sys.modules[module_name]=module
  assert spec.loader
  spec.loader.exec_module(module)
  yield module
 finally:
  sys.modules.pop('nordnet_bundle_'+path.stem,None)
  sys.modules.pop('ios_console',None)
  if previous_ios is not None:sys.modules['ios_console']=previous_ios
  sys.argv=old_argv;sys.path[:]=old_path


def run_stage(label,source,params,password,url,user,log):
 print('\n'+'='*68+'\n'+label+'\n'+'='*68,flush=True)
 log.append({'stage':label,'started_utc':datetime.now(timezone.utc).isoformat(),'state':'RUNNING'})
 try:
  with load_stage(source,params+['--url',url,'--user',user]) as module:
   if hasattr(module,'getpass'):
    module.getpass=lambda _prompt:password
   try:module.main()
   except SystemExit as exc:raise RuntimeError(f'{label}: program exited: {exc}') from exc
 except Exception as exc:
  log[-1]['state']='FAILED'
  log[-1]['error']=str(exc)[:1200]
  log[-1]['finished_utc']=datetime.now(timezone.utc).isoformat()
  raise
 log[-1]['state']='SUCCESS'
 log[-1]['finished_utc']=datetime.now(timezone.utc).isoformat()


def run_with_convergence(label,source,params,password,url,user,log,attempts=5,delay=25):
 """Only retries read-only verification. Never blindly repeats apply."""
 for attempt in range(1,attempts+1):
  try:return run_stage(f'{label} (attempt {attempt}/{attempts})',source,params,password,url,user,log)
  except (RuntimeError,ValueError,TimeoutError) as exc:
   if attempt==attempts:raise
   print(f'Verification not ready: {exc}\nRetrying after {delay}s (NO config replay)...',flush=True)
   time.sleep(delay)


def load_root(filename):
 with load_stage(filename,[]) as m:
  return m


def renew_dhcp(api,password,url,user,write_startup=True,name=PROJECT):
 """Request DHCP from VPCS only, after Cisco routing is ready; do NOT save lease."""
 import nordnet_local as local
 import nordnet_acceptance as acceptance
 import nordnet_enterprise as enterprise
 p,names,nodes=project_status(api,name)
 if names!=NAMES_20:raise RuntimeError('DHCP recovery allowed on normal 20-node topology only')
 path=f"/v2/projects/{p['project_id']}"
 if write_startup:
  print('Ensuring future VPCS startup.vpc uses DHCP (with backups)...')
  acceptance.set_dhcp_startup(local.GNS(url,user,password),path,nodes)
 vm=next(c for c in api.get('/v2/computes') if c['compute_id']=='vm')
 host=vm['host']
 for name,cidr in (('PC-HQ-DHCP','10.10.10.0/24'),('PC-BR-DHCP','10.11.10.0/24')):
  import ipaddress
  target=ipaddress.ip_network(cidr)
  gateway=str(list(target.hosts())[0])
  def show():
   out=local.vpcs_commands(nodes[name],host,['show ip'])['show ip']
   return acceptance.parse_vpcs_ip(out)
  good=False
  for attempt in range(3):
   try:
    actual=show()
    good=(ipaddress.ip_address(actual['ip']) in target and actual['ip'].endswith('.100')
          and actual['gateway']==gateway and actual['prefix']==24)
    if good:break
   except (RuntimeError,KeyError,ValueError) as exc:print(name,'console retry:',exc)
   print(name,'renewing DHCP; attempt',attempt+1)
   local.vpcs_commands(nodes[name],host,['ip dhcp'])
   time.sleep(3)
  if not good:
   actual=show()
   if actual['ip']!=('10.10.10.100' if name=='PC-HQ-DHCP' else '10.11.10.100'):
    raise RuntimeError(name+' did not recover expected DHCP lease: '+str(actual))
  print('PASS:',name,'DHCP lease:',show())


def write_run_log(records,status):
 evidence=ROOT/'evidence'/'orchestrator';evidence.mkdir(parents=True,exist_ok=True)
 destination=evidence/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_bundle_run.json')
 destination.write_text(json.dumps({'result':status,'stages':records},indent=2)+'\n',encoding='utf-8')
 print('Orchestrator evidence:',destination)


def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 sub=parser.add_subparsers(dest='command',required=True)
 for action in ('plan','preflight','deploy','validate','recover-dhcp'):
  cmd=sub.add_parser(action)
  cmd.add_argument('--mode',choices=('fresh','existing'),default='existing')
  cmd.add_argument('--name', default=PROJECT, help='Exact GNS3 project name to create/use (unique on this controller)')
  cmd.add_argument('--url',default='http://127.0.0.1:3080')
  cmd.add_argument('--user',default='admin')
  if action in ('deploy','recover-dhcp'):
   cmd.add_argument('--approve-maintenance',action='store_true')
   cmd.add_argument('--backup-confirmed',action='store_true',help='Assert project export or backup has been preserved')
 pref=sub.add_parser('prefix');pref.add_argument('prefix_args',nargs=argparse.REMAINDER)
 args=parser.parse_args(argv)
 if args.command=='prefix':
  import prefix_helper
  return prefix_helper.main(args.prefix_args)
 name=valid_name(args.name)
 with project_context(name):
  return execute(args,name)

def execute(args,name):
 if args.command=='plan':
  print('NORDNET local bundle v0.9.1; mode:',args.mode, 'project:',name)
  print('Target: MPLS, 3 customer VRFs, 2 switches, 9 VPCS, DNS/HTTP/syslog Docker service.')
  print('NOT included: external IPsec VPN/SOC, dedicated OOB, management hardening.')
  if args.mode=='fresh':
   for i,(label,_,_) in enumerate(PHASES,1):print(f'{i:02d} {label}')
   print('After stages: write DHCP startup scripts and renew leases; read-only enterprise validation.')
  else:
   print('Existing 17-node Phase 6.1: deploy enterprise v0.7; 20-node: validate only; 25-node fixture: refuse.')
  print('No GNS3 API call or configuration changes performed.')
  return
 if args.command in ('deploy','recover-dhcp') and not (args.approve_maintenance and args.backup_confirmed):
  raise RuntimeError('Explicit --approve-maintenance and --backup-confirmed required for modifications')
 if sys.version_info[:2]!=(3,12):raise RuntimeError('Use py -3.12 (telnetlib requirement)')
 pwd=getpass('GNS3 API password (not saved): ')
 api=Controller(args.url,args.user,pwd)
 if args.command=='recover-dhcp':
  preflight(api,'existing','validate',name)
  return renew_dhcp(api,pwd,args.url,args.user,name=name)
 mode=args.mode
 purpose='deploy' if args.command=='deploy' else 'validate'
 p,names,nodes=preflight(api,mode,purpose,name)
 if args.command=='preflight':return
 if args.command=='validate' and mode=='fresh':raise RuntimeError('Cannot validate a project that does not yet exist')
 if args.command=='validate':
  log=[]
  try:
   run_with_convergence('Read-only existing baseline', 'nordnet_enterprise.py',['--verify'],pwd,args.url,args.user,log,3,15)
  finally:write_run_log(log,'VALIDATE')
  print('PASS: normal NORDNET enterprise baseline. Note: 3-probe active acceptance is separate.')
  return
 log=[];status='FAILED'
 try:
  if mode=='existing':
   if names==NAMES_20:
    print('Existing normal 20-node system detected; deployment SKIPPED to prevent reconfiguration.')
   else:
    run_stage('07 Enterprise preflight','nordnet_enterprise.py',['--preflight'],pwd,args.url,args.user,log)
    run_stage('07 Enterprise build','nordnet_enterprise.py',['--build'],pwd,args.url,args.user,log)
    run_stage('07 Enterprise apply','nordnet_enterprise.py',['--apply','--approve-maintenance'],pwd,args.url,args.user,log)
  else:
   for label,filename,flags in PHASES:
    if label=='01 Create core topology':
     flags=flags+['--project',name]
    if '--verify' in flags:
     run_with_convergence(label,filename,flags,pwd,args.url,args.user,log)
    else:
     run_stage(label,filename,flags,pwd,args.url,args.user,log)
    if label=='01 Create core topology':time.sleep(4)
    if label=='02 Configure OSPF/LDP underlay':time.sleep(30)
    if label=='03 Configure municipal MPLS L3VPN':time.sleep(25)
  # Confirm normal topology before any further writes.
  current,nm,_=project_status(api,name)
  if nm!=NAMES_20:raise RuntimeError('20-node enterprise topology not obtained; stop')
  renew_dhcp(api,pwd,args.url,args.user,name=name)
  run_with_convergence('Final local enterprise verification','nordnet_enterprise.py',['--verify'],pwd,args.url,args.user,log)
  # Save enterprise modifications only after verification, if existing 17-node mode.
  if mode=='fresh' or (mode=='existing' and names==NAMES_17):
   run_stage('Commit enterprise config after final verification','nordnet_enterprise.py',['--commit','--approve-maintenance'],pwd,args.url,args.user,log)
  status='PASS'
 finally:write_run_log(log,status)
 print('PASS: NORDNET local deployment complete. External SOC/VPN and security hardening remain separate work.')

if __name__=='__main__':
 try:main()
 except (RuntimeError,ValueError,KeyError,requests.RequestException,KeyboardInterrupt) as exc:
  print('ERROR:',exc,file=sys.stderr)
  raise SystemExit(1)
