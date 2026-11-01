#!/usr/bin/env python3
"""Offline IP/CIDR helper for NORDNET. No GNS3 access or config writes.

Commands:
  inventory                        print all lab customer LANs, /30 attachments and loopbacks
  explain 10.10.30.0/24            subnet mask, usable hosts, wildcards
  contains 10.10.30.0/24 10.10.30.250
  summarize 10.10.10.0/24 10.10.11.0/24
  prefix-list MUNI 10.10.10.0/24 10.11.10.0/24
  check                            detect unintended overlaps in fixed lab plan
"""
from __future__ import annotations
import argparse
import ipaddress as ip
from pathlib import Path
import sys
import yaml
ROOT=Path(__file__).resolve().parent

def rows():
 inv=yaml.safe_load((ROOT/'inventory.yaml').read_text(encoding='utf8'))
 result=[]
 for site,info in inv['sites'].items():
  for net in info['networks']:
   result.append({'name':f'{site}-VLAN{net["vlan"]}-{net["name"]}',
                  'network':ip.ip_network(net['subnet'],strict=True),'vrf':'MUNI'})
 for name,network,vrf in (
  ('UNIV-LAN','10.20.10.0/24','UNIV'),('HEALTH-LAN','10.30.10.0/24','HEALTH'),
  ('PE1-P1','172.20.0.0/30','UNDERLAY'),('P1-PE2','172.20.0.4/30','UNDERLAY'),
  ('PE1-P2','172.20.0.8/30','UNDERLAY'),('P2-PE2','172.20.0.12/30','UNDERLAY'),
  ('PE1-MUNI','172.21.0.0/30','MUNI'),('PE2-MUNI','172.21.0.4/30','MUNI'),
  ('PE1-UNIV','172.21.0.8/30','UNIV'),('PE2-HEALTH','172.21.0.12/30','HEALTH'),
  ('UNIV-SVC','10.20.254.0/30','SERVICE'),('HEALTH-SVC','10.30.254.0/30','SERVICE'),
  ('PE1-LO','172.20.255.1/32','UNDERLAY'),('PE2-LO','172.20.255.2/32','UNDERLAY'),
  ('P1-LO','172.20.255.3/32','UNDERLAY'),('P2-LO','172.20.255.4/32','UNDERLAY')):
  result.append({'name':name,'network':ip.ip_network(network),'vrf':vrf})
 return result

def network(value):
 try:net=ip.ip_network(value,strict=True)
 except ValueError as exc:raise ValueError(f'Invalid canonical network prefix {value!r}: {exc}') from exc
 if net.version != 4:raise ValueError('NORDNET CLI examples require IPv4 CIDR')
 return net

def explain(value):
 n=network(value)
 if n.version!=4:raise ValueError('NORDNET helper currently generates IPv4 IOS examples only')
 usable=n.num_addresses if n.prefixlen>=31 else n.num_addresses-2
 first=n.network_address if n.prefixlen>=31 else n.network_address+1
 last=n.broadcast_address if n.prefixlen>=31 else n.broadcast_address-1
 wildcard=ip.IPv4Address(int(n.hostmask))
 return {'cidr':str(n),'network':str(n.network_address),'prefix_length':n.prefixlen,
         'mask':str(n.netmask),'wildcard':str(wildcard),
         'broadcast':str(n.broadcast_address),'usable_hosts':usable,
         'first_usable':str(first),'last_usable':str(last)}

def check_overlaps(items):
 collisions=[]
 for i,a in enumerate(items):
  for b in items[i+1:]:
   if a['network'].overlaps(b['network']):
    collisions.append(f'{a["name"]} ({a["network"]}) overlaps {b["name"]} ({b["network"]})')
 return collisions

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__)
 s=p.add_subparsers(dest='action',required=True)
 s.add_parser('inventory');s.add_parser('check')
 x=s.add_parser('explain');x.add_argument('cidr')
 x=s.add_parser('contains');x.add_argument('cidr');x.add_argument('ip')
 x=s.add_parser('summarize');x.add_argument('cidrs',nargs='+')
 x=s.add_parser('prefix-list');x.add_argument('name');x.add_argument('cidrs',nargs='+')
 a=p.parse_args(argv)
 if a.action=='inventory':
  print(f'{"NAME":<29} {"PREFIX":<19} {"VRF/ROLE":<10} MASK')
  for r in rows():
   n=r['network'];print(f'{r["name"]:<29} {str(n):<19} {r["vrf"]:<10} {n.netmask}')
 elif a.action=='check':
  clashes=check_overlaps(rows())
  if clashes:
   for c in clashes:print('FAIL:',c)
   raise RuntimeError('Prefix overlap detected; this check does not detect routed policy conflicts')
  print('PASS: no overlapping subnets in the documented local address plan')
 elif a.action=='explain':
  for k,v in explain(a.cidr).items():print(f'{k:>16}: {v}')
 elif a.action=='contains':
  n=network(a.cidr);address=ip.ip_address(a.ip)
  print(f'{address} {"IS" if address in n else "IS NOT"} in {n}')
  if address not in n:raise SystemExit(2)
 elif a.action=='summarize':
  for n in ip.collapse_addresses([network(c) for c in a.cidrs]):print(n)
 elif a.action=='prefix-list':
  if not a.name.replace('-','').replace('_','').isalnum():raise ValueError('Invalid IOS prefix-list name')
  for idx,n in enumerate(dict.fromkeys(str(network(x)) for x in a.cidrs)):
   print(f'ip prefix-list {a.name} seq {(idx+1)*10} permit {n}')
 print('READ-ONLY: no network configuration changed')

if __name__=='__main__':
 try:main()
 except (ValueError,RuntimeError) as exc:
  print('ERROR:',exc,file=sys.stderr);raise SystemExit(1)
