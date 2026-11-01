import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import nordnet_phase5 as m
from ios_console import last_line


def fake_node(name):
    return {'name': name, 'node_id': 'id-' + name, 'node_type': 'qemu',
            'compute_id': 'vm', 'status': 'started', 'console': 5000,
            'ports': [{'name': f'GigabitEthernet0/{i}', 'adapter_number': i, 'port_number': 0}
                      for i in range(4)]}


class FakeAPI:
    def __init__(self, inv):
        self.inv = inv
        self.nodes = {n: fake_node(n) for n in m.BASE_NODES}
        self.links = [self.link_item(link) for link in inv['links_existing']]
        self.created_nodes = 0
        self.created_links = 0

    def link_item(self, link):
        a, ai, b, bi = link
        return {'nodes': [m.endpoint(self.nodes[a], ai), m.endpoint(self.nodes[b], bi)]}

    def call(self, method, path, data=None):
        if method == 'GET' and path.endswith('/nodes'):
            return list(self.nodes.values())
        if method == 'GET' and path.endswith('/links'):
            return self.links
        if method == 'GET' and path == '/v2/templates':
            return [{'name': self.inv['template_name'], 'template_id': 't-iosv',
                     'template_type': 'qemu', 'compute_id': 'vm'}]
        if method == 'POST' and path.endswith('/templates/t-iosv'):
            self.created_nodes += 1
            self.nodes[data['name']] = fake_node(data['name'])
            return self.nodes[data['name']]
        if method == 'POST' and path.endswith('/links'):
            self.created_links += 1
            self.links.append({'nodes': data['nodes']})
            return {'nodes': data['nodes']}
        raise AssertionError(f'Unexpected API call {method} {path}')


class Phase5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = m.yaml.safe_load((ROOT/'inventory.yaml').read_text())

    def test_inventory(self):
        self.assertTrue(m.validate_inventory(self.inv))
        bad = copy.deepcopy(self.inv)
        bad['customers']['UNIV']['rt'] = '65000:100'  # accidental MUNI import
        with self.assertRaisesRegex(ValueError, 'differ'):
            m.validate_inventory(bad)

    def test_render_is_additive(self):
        rendered = m.render(self.inv)
        self.assertEqual(set(rendered), {'PE1', 'PE2', 'CE-UNIV', 'CE-HEALTH'})
        self.assertIn('ip vrf UNIV', rendered['PE1'])
        self.assertIn('ip vrf HEALTH', rendered['PE2'])
        self.assertIn('route-target import 65000:200', rendered['PE1'])
        self.assertNotIn('route-target import 65000:100', rendered['PE1'])
        self.assertNotIn('interface GigabitEthernet0/0', rendered['PE1'])
        self.assertNotIn('router ospf', rendered['PE1'])
        self.assertNotIn('mpls ip', rendered['PE1'])
        self.assertIn('network 10.20.10.0 mask 255.255.255.0', rendered['CE-UNIV'])
        self.assertIn('network 10.30.10.0 mask 255.255.255.0', rendered['CE-HEALTH'])

    def test_build_is_idempotent(self):
        api = FakeAPI(self.inv)
        base = '/v2/projects/id'
        result = m.build(api, base, self.inv, change_allowed=True)
        self.assertEqual(set(result), m.ALL_NODES)
        self.assertEqual((api.created_nodes, api.created_links), (2, 2))
        m.build(api, base, self.inv, change_allowed=True)
        self.assertEqual((api.created_nodes, api.created_links), (2, 2))

    def test_reject_existing_port_collision_before_creating(self):
        api = FakeAPI(self.inv)
        api.links.append(api.link_item(['PE1', 'GigabitEthernet0/3', 'P1', 'GigabitEthernet0/2']))
        with self.assertRaisesRegex(RuntimeError, 'Unexpected GNS3 links'):
            m.build(api, '/v2/projects/id', self.inv, change_allowed=True)
        self.assertEqual(api.created_nodes, 0)

    def test_preflight_allows_clean_new_ce(self):
        running = 'interface GigabitEthernet0/0\n no ip address\n shutdown\n!\nrouter bgp 65210\n'
        self.assertTrue(m.preflight_config(running, 'CE-UNIV', self.inv['customers']['UNIV'], 'ce'))
        malformed = running.replace('no ip address', 'ip address 10.1.1.1 255.255.255.0')
        with self.assertRaisesRegex(RuntimeError, 'unexpected IP'):
            m.preflight_config(malformed, 'CE-UNIV', self.inv['customers']['UNIV'], 'ce')

    def test_preflight_rejects_wrong_vrf(self):
        running = 'interface GigabitEthernet0/3\n ip vrf forwarding MUNI\n no ip address\n!\n'
        with self.assertRaisesRegex(RuntimeError, 'conflicting VRF'):
            m.preflight_config(running, 'PE1', self.inv['customers']['UNIV'], 'pe')

    def test_output_parsers(self):
        self.assertTrue(m.parse_bgp_peer('172.21.0.9 4 65000 13 14 5 0 0 00:01:05 0', '172.21.0.9'))
        self.assertFalse(m.parse_bgp_peer('172.21.0.9 4 65000 13 14 5 0 0 00:01:05 Idle', '172.21.0.9'))
        self.assertTrue(m.ping_is_success('Success rate is 100 percent (5/5)'))
        self.assertTrue(m.ping_is_blocked('Success rate is 0 percent (0/5)'))
        self.assertFalse(m.ping_is_blocked('Success rate is 20 percent (1/5)'))
        self.assertIn('10.20.10.0/24', m.routed_prefixes('B        10.20.10.0/24 [20/0] via 172.21.0.10'))
        self.assertEqual(last_line(b'PE1#\r\n%LINK-3-UPDOWN: state up\r\nPE1#\r\n'), 'PE1#')


    def good_verification_data(self):
        # Synthetic fixture tests the decision rules, never claims a live result.
        ospf = {
            'PE1': ['172.20.255.3', '172.20.255.4'],
            'PE2': ['172.20.255.3', '172.20.255.4'],
            'P1': ['172.20.255.1', '172.20.255.2'],
            'P2': ['172.20.255.1', '172.20.255.2'],
        }
        def bgp(ip):
            return f'{ip} 4 65000 15 18 5 0 0 00:05:00 1'
        def ping(ok):
            return 'Success rate is 100 percent (5/5)' if ok else 'Success rate is 0 percent (0/5)'
        data = {name: {} for name in m.VERIFY_CMDS}
        for device, peers in ospf.items():
            data[device]['show ip ospf neighbor'] = '\n'.join(f'{p} 0 FULL/ - 00:00:30 172.20.0.2 GigabitEthernet0/0' for p in peers)
            data[device]['show mpls ldp neighbor'] = '\n'.join(f'Peer LDP Ident: {p}:0; Local LDP Ident: 172.20.255.1:0\n State: Oper' for p in peers)
        data['PE1']['show ip route 172.20.255.2'] = 'Known via "ospf 100"\n  * 172.20.0.2 via GigabitEthernet0/0'
        data['PE1']['show ip bgp vpnv4 all summary'] = bgp('172.20.255.2') + '\n' + bgp('172.21.0.10')
        data['PE2']['show ip bgp vpnv4 all summary'] = bgp('172.20.255.1') + '\n' + bgp('172.21.0.14')
        muni = 'B 10.10.10.0/24 [200/0] via 172.20.255.1\nB 10.11.10.0/24 [20/0] via 172.21.0.6'
        for pe in ('PE1','PE2'):
            data[pe]['show ip route vrf MUNI'] = muni
        data['PE1']['show ip route vrf UNIV'] = 'Gateway of last resort is not set\nB 10.20.10.0/24 [20/0] via 172.21.0.10'
        data['PE2']['show ip route vrf HEALTH'] = 'Gateway of last resort is not set\nB 10.30.10.0/24 [20/0] via 172.21.0.14'
        data['CE-UNIV']['show ip bgp summary'] = bgp('172.21.0.9')
        data['CE-HEALTH']['show ip bgp summary'] = bgp('172.21.0.13')
        data['CE-UNIV']['show ip route'] = 'C 10.20.10.0/24 is directly connected, Loopback10'
        data['CE-HEALTH']['show ip route'] = 'C 10.30.10.0/24 is directly connected, Loopback10'
        for ce in ('CE-MUNI-HQ', 'CE-MUNI-BR'):
            for cmd in m.VERIFY_CMDS[ce]:
                data[ce][cmd] = ping(True)
        for ce in ('CE-UNIV', 'CE-HEALTH'):
            for cmd in m.VERIFY_CMDS[ce]:
                if cmd.startswith('ping '):
                    data[ce][cmd] = ping(False)
        return data

    def test_real_ios_subnet_group_format(self):
        """Regression: IOSv 15.9 sometimes omits /24 on BGP route lines."""
        real_output = '''Routing Table: MUNI
Codes: L - local, C - connected, S - static, B - BGP
Gateway of last resort is not set
      10.0.0.0/24 is subnetted, 2 subnets
B        10.10.10.0 [200/0] via 172.20.255.1, 00:03:15
B        10.11.10.0 [20/0] via 172.21.0.6, 00:02:14
      172.21.0.0/16 is variably subnetted, 2 subnets, 2 masks
C        172.21.0.4/30 is directly connected, GigabitEthernet0/1
L        172.21.0.5/32 is directly connected, GigabitEthernet0/1
'''
        self.assertEqual(m.routed_prefixes(real_output), {
            '10.10.10.0/24', '10.11.10.0/24',
            '172.21.0.4/30', '172.21.0.5/32'
        })

    def test_verifier_accepts_ios_grouped_route_format(self):
        data = self.good_verification_data()
        data['PE1']['show ip route vrf UNIV'] = (
            'Routing Table: UNIV\nGateway of last resort is not set\n'
            '10.0.0.0/24 is subnetted, 1 subnets\n'
            'B 10.20.10.0 [20/0] via 172.21.0.10\n')
        data['PE2']['show ip route vrf HEALTH'] = (
            'Routing Table: HEALTH\nGateway of last resort is not set\n'
            '10.0.0.0/24 is subnetted, 1 subnets\n'
            'B 10.30.10.0 [20/0] via 172.21.0.14\n')
        muni = ('10.0.0.0/24 is subnetted, 2 subnets\n'
                'B 10.10.10.0 [200/0] via 172.20.255.1\n'
                'B 10.11.10.0 [20/0] via 172.21.0.6\n')
        for pe in ('PE1', 'PE2'):
            data[pe]['show ip route vrf MUNI'] = muni
        self.assertEqual(m.verify_checks(data), [])

    def test_unmasked_route_without_group_is_not_guessed(self):
        self.assertEqual(m.routed_prefixes('B 10.20.10.0 [20/0] via 172.21.0.10'), set())

    def test_verifier_accepts_good_synthetic_state(self):
        self.assertEqual(m.verify_checks(self.good_verification_data()), [])

    def test_verifier_rejects_leaked_customer_prefix(self):
        data = self.good_verification_data()
        data['PE1']['show ip route vrf UNIV'] += '\nB 10.30.10.0/24 [200/0] via 172.20.255.2'
        failures = m.verify_checks(data)
        self.assertTrue(any('route leaked' in failure for failure in failures), failures)

if __name__ == '__main__':
    unittest.main()
