"""Regression: use real IOSvL2 Gi0/0..Gi3/3 layout; handle partial build."""
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import yaml
import nordnet_enterprise as ent


class PortMapping(unittest.TestCase):
    def setUp(self):
        self.inv=yaml.safe_load((ent.BASE/'inventory.yaml').read_text(encoding='utf-8'))
        self.nodes={}
        original=set(ent.old.ROUTERS+ent.old.SWITCHES)
        original.update(e['name'] for e in self.inv['endpoints'])
        for name in original:
            if name in ent.old.SWITCHES:
                ports=[{'name':f'Gi{slot}/{index}', 'adapter_number':slot,'port_number':index}
                       for slot in range(4) for index in range(4)]
                typ='qemu'
            elif name in ent.old.ROUTERS:
                ports=[{'name':f'Gi0/{index}','adapter_number':index,'port_number':0} for index in range(4)]
                typ='qemu'
            else:
                ports=[{'name':'Ethernet0','adapter_number':0,'port_number':0}]
                typ='vpcs'
            self.nodes[name]={'name':name,'node_id':name,'node_type':typ,'compute_id':'vm',
                              'ports':ports,'status':'started','properties':{}}
        self.old_links=[]
        for a,ai,b,bi in ent.old.desired_links(self.inv):
            self.old_links.append({'nodes':[ent.old.endpoint(self.nodes[a],ai),ent.old.endpoint(self.nodes[b],bi)]})
        self.api=Mock()
        self.api.call.return_value=self.old_links
        self.path='/v2/projects/381c9ab5-1701-4481-a808-6d13439ddeed'

    def add_enterprise_nodes(self):
        self.nodes[ent.SERVICE]={
            'name':ent.SERVICE,'node_id':ent.SERVICE,'compute_id':'vm','node_type':'docker',
            'properties':{'image':ent.IMAGE,'adapters':3},
            'ports':[{'name':f'eth{i}','adapter_number':i,'port_number':0} for i in range(3)]}
        for name in ('PC-HQ-DHCP','PC-BR-DHCP'):
            self.nodes[name]={'name':name,'node_id':name,'compute_id':'vm','node_type':'vpcs',
                              'properties':{},'ports':[{'name':'Ethernet0','adapter_number':0,'port_number':0}]}

    def test_iosvl2_real_layout_has_no_gi0_4(self):
        hq=self.nodes['SW-MUNI-HQ']
        with self.assertRaisesRegex(RuntimeError,'cannot find interface'):
            ent.port(hq,'GigabitEthernet0/4')
        self.assertEqual(ent.port(hq,ent.HQ_SERVICE_IFACE)['adapter_number'],1)
        self.assertEqual(ent.port(hq,ent.HQ_DHCP_IFACE)['port_number'],1)

    def test_existing_trunk_and_clients_are_not_reused(self):
        used=set().union(*(set(ent.eid(x) for x in l['nodes']) for l in self.old_links))
        for parent,iface,_,_ in ent.LINKS:
            p=ent.port(self.nodes[parent],iface)
            self.assertNotIn(ent.eid(p),used)

    def test_preflight_checks_all_real_source_ports_before_build(self):
        targets,existing=ent.check_topology(self.api,self.path,self.nodes)
        self.assertEqual(len(targets),0)  # enterprise children not created
        self.assertEqual(len(existing),len(self.old_links))
        self.api.call.assert_called()

    def test_preflight_rejects_missing_interface_with_no_post(self):
        self.nodes['SW-MUNI-HQ']['ports']=[p for p in self.nodes['SW-MUNI-HQ']['ports'] if p['name']!='Gi1/0']
        with self.assertRaisesRegex(RuntimeError,"cannot find interface"):
            ent.check_topology(self.api,self.path,self.nodes)
        self.api.call.assert_called_with('GET',self.path+'/links')

    def test_partial_build_existing_nodes_no_links_is_acceptable(self):
        self.add_enterprise_nodes()
        targets,existing=ent.check_topology(self.api,self.path,self.nodes,expect_built=True)
        self.assertEqual(len(targets),5)
        self.assertEqual(len(existing),len(self.old_links))

    def test_fully_built_links_are_idempotent(self):
        self.add_enterprise_nodes()
        targets,_=ent.check_topology(self.api,self.path,self.nodes,expect_built=True)
        self.api.call.return_value=self.old_links+[{'nodes':list(x)} for x in targets.values()]
        target2,exists=ent.check_topology(self.api,self.path,self.nodes,expect_built=True)
        self.assertEqual(len(target2),5)
        self.assertTrue(set(target2).issubset(exists))

    def test_existing_occupied_hq_port_aborts(self):
        self.add_enterprise_nodes()
        extra={'nodes':[ent.port(self.nodes['SW-MUNI-HQ'],ent.HQ_SERVICE_IFACE),
                        ent.port(self.nodes['PC-BR-SVC'],'Ethernet0')]}
        self.api.call.return_value=self.old_links+[extra]
        with self.assertRaisesRegex(RuntimeError,'Unexpected links'):
            ent.check_topology(self.api,self.path,self.nodes,expect_built=True)

    def test_config_matches_switch_wiring(self):
        hq=ent.config('SW-MUNI-HQ')
        br=ent.config('SW-MUNI-BR')
        for v in (ent.HQ_SERVICE_IFACE,ent.HQ_DHCP_IFACE):
            self.assertIn('interface '+v+'\n',hq)
        self.assertIn('interface '+ent.BR_DHCP_IFACE+'\n',br)
        self.assertNotIn('interface GigabitEthernet0/4',hq)
        self.assertNotIn('interface GigabitEthernet0/5',hq)


if __name__=='__main__':unittest.main()
