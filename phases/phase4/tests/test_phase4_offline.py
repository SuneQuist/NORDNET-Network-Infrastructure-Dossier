import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import nordnet_phase4 as m
from ios_console import last_line


def fake_node(name, count=4):
    return {
        'name': name, 'node_id': 'id-' + name, 'node_type': 'qemu', 'compute_id': 'vm',
        'status': 'started', 'console': 5000,
        'ports': [{'name': f'GigabitEthernet0/{i}', 'adapter_number': i, 'port_number': 0}
                  for i in range(count)]
    }


class FakeAPI:
    def __init__(self, inv):
        self.inv = inv
        self.nodes = {n: fake_node(n) for n in m.EXISTING_NODES}
        self.links = [self.link_item(item) for item in inv['links_existing']]
        self.creates = 0
        self.link_creates = 0

    def link_item(self, item):
        a, ai, b, bi = item
        return {'nodes': [m.port_endpoint(self.nodes[a], ai), m.port_endpoint(self.nodes[b], bi)]}

    def call(self, method, path, body=None):
        if method == 'GET' and path.endswith('/nodes'):
            return list(self.nodes.values())
        if method == 'GET' and path.endswith('/links'):
            return self.links
        if method == 'GET' and path == '/v2/templates':
            return [{'name': self.inv['template_name'], 'template_id': 'template-iosv',
                     'template_type': 'qemu', 'compute_id': 'vm'}]
        if method == 'POST' and path.endswith('/templates/template-iosv'):
            self.creates += 1
            self.nodes[body['name']] = fake_node(body['name'])
            return self.nodes[body['name']]
        if method == 'POST' and path.endswith('/links'):
            self.link_creates += 1
            self.links.append({'nodes': body['nodes']})
            return {'nodes': body['nodes']}
        raise AssertionError(f'unexpected {method} {path}')


class Phase4(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = m.yaml.safe_load((ROOT/'inventory.yaml').read_text(encoding='utf-8'))

    def test_inventory(self):
        self.assertTrue(m.validate_inventory(self.inv))
        self.assertEqual(len(self.inv['links_existing']), 4)
        self.assertEqual(len(self.inv['links_new']), 2)

    def test_render_does_not_change_vpn_config(self):
        m.render(self.inv)
        pe1 = (ROOT/'generated'/'PE1.cfg').read_text()
        p2 = (ROOT/'generated'/'P2.cfg').read_text()
        self.assertIn('interface GigabitEthernet0/2', pe1)
        self.assertIn('ip address 172.20.0.9 255.255.255.252', pe1)
        self.assertNotIn('router bgp', pe1)
        self.assertNotIn('vrf MUNI', pe1)
        self.assertIn('ip address 172.20.255.4 255.255.255.255', p2)
        self.assertEqual(p2.count('ip ospf cost 30'), 2)

    def test_link_creation_and_rerun(self):
        api = FakeAPI(self.inv)
        base = '/v2/projects/example'
        output = m.build(api, base, self.inv, permit_change=True)
        self.assertEqual(set(output), m.EXPECTED_NODES)
        self.assertEqual(api.creates, 1)
        self.assertEqual(api.link_creates, 2)
        m.build(api, base, self.inv, permit_change=True)
        self.assertEqual((api.creates, api.link_creates), (1, 2))

    def test_refuse_overwriting_unexpected_link(self):
        api = FakeAPI(self.inv)
        api.nodes['P2'] = fake_node('P2')
        api.links.append(api.link_item(['PE1', 'GigabitEthernet0/2', 'P1', 'GigabitEthernet0/2']))
        with self.assertRaisesRegex(RuntimeError, 'Unexpected GNS3 links'):
            m.build(api, '/v2/projects/example', self.inv, permit_change=True)

    def test_interface_guard(self):
        show = 'interface GigabitEthernet0/2\n no ip address\n shutdown\n!\n'
        m.ensure_unused_or_expected(show, 'GigabitEthernet0/2', '172.20.0.9')
        with self.assertRaisesRegex(RuntimeError, 'unexpected IP'):
            m.ensure_unused_or_expected(show.replace('no ip address', 'ip address 10.1.1.1 255.255.255.0'), 'GigabitEthernet0/2', '172.20.0.9')
        with self.assertRaisesRegex(RuntimeError, 'incompatible VRF'):
            m.ensure_unused_or_expected(show.replace('no ip address', 'ip vrf forwarding MUNI'), 'GigabitEthernet0/2', '172.20.0.9')

    def test_parser(self):
        ospf = '172.20.255.3     0 FULL/  - 00:00:33 172.20.0.2 GigabitEthernet0/0\n'
        ldp = '''Peer LDP Ident: 172.20.255.3:0; Local LDP Ident 172.20.255.1:0
 TCP connection: 172.20.255.3.646 - 172.20.255.1.36988
 State: Oper; Msgs sent/rcvd: 8/8; Downstream
'''
        self.assertEqual(m.ospf_full_peers(ospf), {'172.20.255.3'})
        self.assertEqual(m.ldp_oper_peers(ldp), {'172.20.255.3'})
        self.assertTrue(m.bgp_established('172.20.255.2 4 65000 13 14 5 0 0 00:01:05 1', '172.20.255.2'))
        self.assertFalse(m.bgp_established('172.20.255.2 4 65000 13 14 5 0 0 00:01:05 Idle', '172.20.255.2'))
        self.assertTrue(m.ping_success('Success rate is 100 percent (5/5)'))
        self.assertFalse(m.ping_success('Success rate is 80 percent (4/5)'))
        self.assertEqual(last_line(b'PE1#\r\n%LINEPROTO-5-UPDOWN: up\r\nPE1#\r\n'), 'PE1#')

if __name__ == '__main__':
    unittest.main()
