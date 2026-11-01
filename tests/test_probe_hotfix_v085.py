import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import repair_probes as h

class FakeApi:
    def __init__(self,changes):
        self.nodes={n:{'properties':{'start_command':v['old']},'status':'stopped'} for n,v in changes.items()}
        self.id_to_name={v['id']:n for n,v in changes.items()}
        self.actions=[]
    def call(self,verb,route,data=None):
        name=next((n for uid,n in self.id_to_name.items() if uid in route),None)
        self.actions.append((verb,route,data))
        if name is None:raise AssertionError('Unexpected non-probe API call: '+route)
        node=self.nodes[name]
        if verb=='GET':return {'properties':dict(node['properties']),'status':node['status']}
        if verb=='PUT':
            assert list(data)==['properties'] and list(data['properties'])==['start_command']
            node['properties']['start_command']=data['properties']['start_command']
            return {}
        if verb=='POST' and route.endswith('/start'):
            node['status']='started';return {}
        if verb=='POST' and route.endswith('/stop'):
            node['status']='stopped';return {}
        raise AssertionError('Unexpected call')

class ProbeHotfixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src=(ROOT/'probes'/'nordnet_probe.py').read_text(encoding='utf-8')
        cls.old,cls.new=h.patched_pair(src)
    def nodes(self,source=None):
        src=source or self.old
        return {name:{'node_type':'docker','compute_id':'vm','name':name,
                      'node_id':('00000000-0000-0000-0000-%012d'%i),
                      'status':'stopped',
                      'properties':{'image':h.enterprise.IMAGE,'adapters':1,
                          'start_command':h.boot(src,name)}}
                for i,name in enumerate(h.acceptance.NODE_PLAN,1)}
    def test_forwarding_startup_fix_is_fail_closed(self):
        self.assertIn("f.write('0\\n')", self.new)
        self.assertIn('IPv4 forwarding still enabled',self.new)
        self.assertIn('Cannot disable IPv4 forwarding',self.new)
        self.assertNotIn('IP forwarding unexpectedly enabled',self.new)
    def test_source_old_new_idempotence(self):
        self.assertEqual(h.patched_pair(self.new),(self.old,self.new))
        self.assertEqual(h.patched_pair(self.old),(self.old,self.new))
    def test_invalid_source_rejected(self):
        with self.assertRaises(RuntimeError):h.patched_pair('unexpected source')
    def test_boot_command_matches_original(self):
        for name in h.acceptance.NODE_PLAN:
            self.assertEqual(h.boot(self.new,name),h.acceptance.make_boot_command(name))
            self.assertNotEqual(h.boot(self.old,name),h.boot(self.new,name))
    def test_guard_node_recognizes_expected_old(self):
        r=h.guard_nodes(self.nodes(),self.old,self.new)
        self.assertEqual(len(r),3)
        self.assertTrue(all(not v['patched'] for v in r.values()))
    def test_guard_accepts_mixed_retry(self):
        n=self.nodes()
        n['PROBE-MUNI']['properties']['start_command']=h.boot(self.new,'PROBE-MUNI')
        r=h.guard_nodes(n,self.old,self.new)
        self.assertTrue(r['PROBE-MUNI']['patched'])
    def test_guard_rejects_unknown_command(self):
        n=self.nodes();n['PROBE-MUNI']['properties']['start_command']='sh'
        with self.assertRaisesRegex(RuntimeError,'differs'):h.guard_nodes(n,self.old,self.new)
    def test_guard_rejects_wrong_image(self):
        n=self.nodes();n['PROBE-UNIV']['properties']['image']='another-image'
        with self.assertRaisesRegex(RuntimeError,'unexpected Docker'):h.guard_nodes(n,self.old,self.new)
    def test_check_does_not_touch_anything(self):
        changes=h.guard_nodes(self.nodes(),self.old,self.new)
        api=FakeApi(changes)
        with patch('builtins.print'),patch.object(h,'SOURCE',ROOT/'probes'/'nordnet_probe.py'):
            h.take_action(api,'/v2/projects/demo',{},self.old,self.new,changes,False)
        self.assertEqual(api.actions,[])
    def test_apply_only_three_test_nodes_and_source(self):
        changes=h.guard_nodes(self.nodes(),self.old,self.new)
        api=FakeApi(changes)
        with tempfile.TemporaryDirectory() as tmp:
            loc=Path(tmp); f=loc/'probes'/'nordnet_probe.py';f.parent.mkdir()
            f.write_text(self.old,encoding='utf-8')
            with patch.object(h,'BASE',loc),patch.object(h,'SOURCE',f),patch('builtins.print'):
                h.take_action(api,'/v2/projects/demo',{},self.old,self.new,changes,True)
            self.assertEqual(f.read_text(),self.new)
            self.assertEqual(len([x for x in api.actions if x[0]=='PUT']),3)
            self.assertEqual(len([x for x in api.actions if x[0]=='POST' and x[1].endswith('/start')]),3)
            self.assertFalse([x for x in api.actions if x[0] not in ('GET','PUT','POST')])
            for name in h.acceptance.NODE_PLAN:
                self.assertEqual(api.nodes[name]['properties']['start_command'],h.boot(self.new,name))
            self.assertTrue((next((loc/'evidence'/'local_acceptance'/'probe_hotfix_backups').iterdir())/'node_commands.json').exists())
    def test_idempotent_does_not_restart_probes(self):
        changes=h.guard_nodes(self.nodes(self.new),self.old,self.new)
        api=FakeApi(changes)
        for name in changes:api.nodes[name]['properties']['start_command']=changes[name]['new']
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'nordnet_probe.py';path.write_text(self.new)
            with patch.object(h,'SOURCE',path),patch('builtins.print'):
                h.take_action(api,'/v2/projects/demo',{},self.old,self.new,changes,True)
        self.assertEqual(api.actions,[])

if __name__=='__main__':unittest.main()
