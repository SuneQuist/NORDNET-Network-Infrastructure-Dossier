"""Offline safety and helper tests; no real GNS3 calls."""
import io
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import Mock
import nordnet
import prefix_helper

class SimulatedAPI:
 def __init__(self,names,project=True):self.names=names;self.project=project
 def get(self,path):
  if path=='/v2/projects':return [{'name':nordnet.PROJECT,'project_id':'fake-id','status':'opened'}] if self.project else []
  if path=='/v2/projects/fake-id/nodes':return [{'name':x,'node_id':x} for x in self.names]
  raise AssertionError('Unexpected path: '+path)

class BundleSafety(unittest.TestCase):
 def test_fresh_refuses_existing(self):
  for names in (set(),nordnet.NAMES_17,nordnet.NAMES_20,nordnet.NAMES_20|nordnet.FIXTURE):
   with self.subTest(n=len(names)),self.assertRaisesRegex(RuntimeError,'REFUSES existing'):
    nordnet.require_state(SimulatedAPI(names),'fresh','deploy')
 def test_fresh_missing_project_is_allowed(self):
  p,names,nodes=nordnet.require_state(SimulatedAPI([],False),'fresh','deploy')
  self.assertIsNone(p);self.assertEqual(names,set())
 def test_existing_17_can_deploy(self):
  p,names,_=nordnet.require_state(SimulatedAPI(nordnet.NAMES_17),'existing','deploy')
  self.assertEqual(len(names),17)
 def test_existing_20_can_deploy_or_validate(self):
  for purpose in ('deploy','validate'):
   self.assertEqual(len(nordnet.require_state(SimulatedAPI(nordnet.NAMES_20),'existing',purpose)[1]),20)
 def test_existing_17_cannot_validate(self):
  with self.assertRaisesRegex(RuntimeError,'Unsupported existing'):
   nordnet.require_state(SimulatedAPI(nordnet.NAMES_17),'existing','validate')
 def test_fixture_refused(self):
  with self.assertRaisesRegex(RuntimeError,'temporary acceptance fixture'):
   nordnet.require_state(SimulatedAPI(nordnet.NAMES_20|nordnet.FIXTURE),'existing','deploy')
 def test_unexpected_node_refused(self):
  with self.assertRaisesRegex(RuntimeError,'Unsupported existing'):
   nordnet.require_state(SimulatedAPI(nordnet.NAMES_20|{'UNKNOWN'}),'existing','deploy')
 def test_duplicate_nodes_refused(self):
  class DuplicateAPI(SimulatedAPI):
   def get(self,path):
    if path.endswith('/nodes'):return [{'name':'PE1','node_id':'a'},{'name':'PE1','node_id':'b'}]
    return super().get(path)
  with self.assertRaisesRegex(RuntimeError,'Duplicate node names'):
   nordnet.project_status(DuplicateAPI(set()))
 def test_plan_is_offline(self):
  f=io.StringIO()
  with redirect_stdout(f):nordnet.main(['plan','--mode','fresh'])
  self.assertIn('No GNS3 API call',f.getvalue())
 def test_no_apply_without_approval_or_backup(self):
  for flags in ([],['--approve-maintenance'],['--backup-confirmed']):
   with self.subTest(flags=flags),self.assertRaisesRegex(RuntimeError,'required'):
    nordnet.main(['deploy','--mode','fresh']+flags)

class PrefixHelper(unittest.TestCase):
 def test_no_overlap(self):self.assertEqual(prefix_helper.check_overlaps(prefix_helper.rows()),[])
 def test_wildcard(self):
  item=prefix_helper.explain('10.10.30.0/24')
  self.assertEqual((item['wildcard'],item['usable_hosts']),('0.0.0.255',254))
 def test_strict_canonical_subnet(self):
  with self.assertRaises(ValueError):prefix_helper.network('10.10.10.5/24')
 def test_ios_prefix_list(self):
  f=io.StringIO()
  with redirect_stdout(f):prefix_helper.main(['prefix-list','NORDNET','10.11.10.0/24'])
  self.assertIn('ip prefix-list NORDNET seq 10 permit 10.11.10.0/24',f.getvalue())
 def test_isolation_negative_contains(self):
  with self.assertRaises(SystemExit) as ctx:
   with redirect_stdout(io.StringIO()):prefix_helper.main(['contains','10.10.10.0/24','10.11.10.10'])
  self.assertEqual(ctx.exception.code,2)

if __name__=='__main__':unittest.main()

# /31 point-to-point and /32 host routes have distinct usable-address semantics.
class PrefixEdgeCases(unittest.TestCase):
 def test_point_to_point(self):self.assertEqual(prefix_helper.explain('172.20.0.0/31')['usable_hosts'],2)
 def test_host_route(self):self.assertEqual(prefix_helper.explain('172.20.255.1/32')['usable_hosts'],1)
 def test_ipv6_rejected_for_ios(self):
  with self.assertRaisesRegex(ValueError,'IPv4'):prefix_helper.network('2001:db8::/32')
