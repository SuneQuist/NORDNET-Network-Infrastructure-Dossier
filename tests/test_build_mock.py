"""In-memory controller regression tests. No real API or Cisco devices involved."""
from pathlib import Path
import sys
import unittest
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nordnet_local as n

class FakeGNS:
    def __init__(self):
        self.counter=0
        self.nodes={}
        self.links=[]
        for name in n.ROUTERS:
            self.add(name,'qemu')
        for link in n.OLD_LINKS:
            self.links.append({'nodes':[n.endpoint(self.nodes[link[0]],link[1]), n.endpoint(self.nodes[link[2]],link[3])]})
    def add(self,name,typ):
        self.counter += 1
        ports=[{'name':f'GigabitEthernet0/{i}','adapter_number':i,'port_number':0} for i in range(16 if name in n.SWITCHES else 4)] if typ=='qemu' else [{'name':'Ethernet0','adapter_number':0,'port_number':0}]
        node={'name':name,'node_type':typ,'compute_id':'vm','ports':ports,'node_id':str(self.counter),'status':'stopped','console':5000+self.counter}
        self.nodes[name]=node
        return node
    def call(self,method,path,data=None):
        if method=='GET' and path.endswith('/nodes'): return list(self.nodes.values())
        if method=='GET' and path.endswith('/links'): return self.links
        if method=='GET' and path=='/v2/templates': return [{'name':'Cisco IOSvL2 15.2.1','template_id':'sw','template_type':'qemu','compute_id':'vm'}]
        if method=='POST' and '/templates/sw' in path: return self.add(data['name'],'qemu')
        if method=='POST' and path.endswith('/nodes'): return self.add(data['name'],'vpcs')
        if method=='POST' and path.endswith('/links'):
            self.links.append(data);return data
        raise AssertionError((method,path,data))

class BuildMockTests(unittest.TestCase):
    def setUp(self):
        self.inv=yaml.safe_load((n.BASE/'inventory.yaml').read_text())
        self.api=FakeGNS()
    def test_build_twice_is_idempotent(self):
        nodes=n.build(self.api,'/v2/projects/test',self.inv)
        self.assertEqual(len(nodes),17)
        self.assertEqual(len(self.api.links),17)
        again=n.build(self.api,'/v2/projects/test',self.inv)
        self.assertEqual(len(again),17)
        self.assertEqual(len(self.api.links),17)
    def test_verify_cannot_create_nodes(self):
        with self.assertRaises(RuntimeError):
            n.build(self.api,'/v2/projects/test',self.inv,change_allowed=False)
        self.assertEqual(len(self.api.nodes),8)
    def test_refuse_existing_port_collision(self):
        # A new, unknown link on HQ customer LAN port must block deployment.
        self.api.links.append({'nodes':[n.endpoint(self.api.nodes['CE-MUNI-HQ'],'Gi0/1'),n.endpoint(self.api.nodes['PE1'],'Gi0/2')]})
        with self.assertRaises(RuntimeError): n.build(self.api,'/v2/projects/test',self.inv)

if __name__=='__main__': unittest.main()
