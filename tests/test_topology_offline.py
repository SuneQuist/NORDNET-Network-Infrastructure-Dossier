"""Exercise the complete temporary link split / idempotent retry / restoration offline."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import yaml

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
if os.environ.get('NORDNET_TEST_DEPS'):
    sys.path.insert(0,os.environ['NORDNET_TEST_DEPS'])
import nordnet_acceptance as a
import nordnet_local as local
import nordnet_enterprise as ent

class FakeAPI:
    def __init__(self):
        self.nodes={};self.links=[];self.serial=0;self.counter=0
        self.inv=yaml.safe_load((local.BASE/'inventory.yaml').read_text())
        for name in local.ROUTERS+local.SWITCHES:
            self.add(name,'qemu','vm')
        for ep in self.inv['endpoints']:
            self.add(ep['name'],'vpcs','vm')
        self.add(ent.SERVICE,'docker','vm',{'image':ent.IMAGE,'adapters':3})
        for name in ('PC-HQ-DHCP','PC-BR-DHCP'):
            self.add(name,'vpcs','vm')
        for src,si,dest,di in local.desired_links(self.inv)+list(ent.LINKS):
            self.link(ent.port(self.nodes[src],si),ent.port(self.nodes[dest],di))
    def add(self,name,typ,compute,props=None):
        self.serial+=1
        if typ=='qemu':
            count=16 if name in local.SWITCHES else 4
            ports=[{'name':f'GigabitEthernet{i//4}/{i%4}' if name in local.SWITCHES else f'GigabitEthernet0/{i}',
                    'adapter_number':i,'port_number':0} for i in range(count)]
        elif typ=='ethernet_switch':
            ports=[{'name':'Ethernet'+str(i),'adapter_number':0,'port_number':i} for i in range(8)]
        else:
            count=props.get('adapters',1) if typ=='docker' else 1
            ports=[{'name':'eth'+str(i) if typ=='docker' else 'Ethernet0','adapter_number':i,'port_number':0} for i in range(count)]
        obj={'name':name,'node_id':str(self.serial),'node_type':typ,'compute_id':compute,
             'ports':ports,'properties':props or {},'status':'stopped','console':5000+self.serial}
        self.nodes[name]=obj
        return obj
    def link(self,p1,p2):
        self.counter+=1
        link={'link_id':'link-'+str(self.counter),'nodes':[p1,p2]}
        self.links.append(link)
        return link
    def call(self,method,path,data=None):
        if method=='GET' and path.endswith('/nodes'):return list(self.nodes.values())
        if method=='GET' and path.endswith('/links'):return list(self.links)
        if method=='GET' and path=='/v2/computes':
            return [{'compute_id':'vm','connected':True,'capabilities':{'node_types':['docker','vpcs','qemu','ethernet_switch']}},
                    {'compute_id':'local','connected':True,'capabilities':{'node_types':['ethernet_switch']}}]
        if method=='GET' and path=='/v2/computes/vm/docker/images':return [ent.IMAGE]
        if method=='POST' and path.endswith('/nodes'):
            return self.add(data['name'],data['node_type'],data['compute_id'],data.get('properties'))
        if method=='POST' and path.endswith('/links'):
            return self.link(*data['nodes'])
        if method=='DELETE' and '/links/' in path:
            lid=path.rsplit('/',1)[-1]
            self.links=[x for x in self.links if x['link_id']!=lid];return None
        if method=='DELETE' and '/nodes/' in path:
            nid=path.rsplit('/',1)[-1]
            self.nodes={k:v for k,v in self.nodes.items() if v['node_id']!=nid};return None
        if method=='POST' and path.endswith('/start'):
            nid=path.split('/')[-2]
            for node in self.nodes.values():
                if node['node_id']==nid:node['status']='started';return node
        if method=='POST' and path.endswith('/stop'):
            nid=path.split('/')[-2]
            for node in self.nodes.values():
                if node['node_id']==nid:node['status']='stopped';return node
        raise AssertionError((method,path,data))

class RewireTests(unittest.TestCase):
    def setUp(self):
        self.api=FakeAPI()
        self.path='/v2/projects/381c9ab5-1701-4481-a808-6d13439ddeed'
        self.vm={'host':'fakevm'}
    def check(self,with_probes=False):
        return a.check_topology(self.api,self.path,self.api.nodes,self.api.inv,with_probes)
    def prep(self):
        with patch.object(ent,'phase6_baseline'):
            a.prepare(self.api,self.path,self.vm,self.api.nodes,self.api.inv)
    def test_original_topology(self):
        d=self.check()
        self.assertEqual(d['baseline_links'],22)
        self.assertEqual(d['existing_links'],22)
    def test_prepare_fixture_idempotent_and_restore(self):
        self.prep()
        self.assertEqual((len(self.api.nodes),len(self.api.links)),(25,27))
        self.check(True)
        self.prep()
        self.assertEqual((len(self.api.nodes),len(self.api.links)),(25,27))
        a.restore(self.api,self.path,self.vm,self.api.nodes,self.api.inv)
        self.assertEqual((len(self.api.nodes),len(self.api.links)),(20,22))
        self.check()
    def test_resumes_partial_after_original_link_deleted(self):
        # Simulate process interruption immediately after first CE-PC link delete.
        for sw,info in a.SPLITS.items():
            self.api.add(sw,'ethernet_switch','vm')
        for name in a.NODE_PLAN:
            self.api.add(name,'docker','vm',{'image':ent.IMAGE,'adapters':1,'start_command':a.make_boot_command(name)})
        info=a.SPLITS['LAN-UNIV-SW']
        direct=a.edge(ent.port(self.api.nodes[info['ce']],info['ce_port']),
                      ent.port(self.api.nodes[info['pc']],'Ethernet0'))
        self.api.links=[ln for ln in self.api.links if frozenset(local.epkey(x) for x in ln['nodes'])!=direct]
        self.prep()
        self.check(True)
        self.assertEqual(len(self.api.links),27)
    def test_refuses_unexpected_link(self):
        fake={'link_id':'foreign','nodes':[ent.port(self.api.nodes['PE1'],'GigabitEthernet0/0'),
                                            ent.port(self.api.nodes['PE2'],'GigabitEthernet0/0')]}
        self.api.links.append(fake)
        with self.assertRaises(RuntimeError):self.check()
    def test_refuses_missing_core_link(self):
        self.api.links.pop(0)
        with self.assertRaises(RuntimeError):self.check()
    def test_refuses_other_docker_image(self):
        self.api.add('PROBE-MUNI','docker','vm',{'image':'alpine:other','adapters':1})
        with self.assertRaises(RuntimeError):self.check()

if __name__=='__main__':unittest.main()
