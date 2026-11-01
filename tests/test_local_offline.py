import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import nordnet_local as n
import yaml

class LocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv=yaml.safe_load((n.BASE/'inventory.yaml').read_text())

    def test_inventory(self):
        self.assertTrue(n.validate(self.inv))

    def test_exact_links(self):
        links=n.desired_links(self.inv)
        self.assertEqual(len(links),17)
        self.assertEqual(len(links),len(set(links)))
        self.assertIn(('CE-UNIV','GigabitEthernet0/1','PC-UNIV','Ethernet0'),links)

    def test_render_pe_filters(self):
        gen=n.render(self.inv)
        self.assertIn('PL-MUNI-HQ seq 15 permit 10.10.30.0/24',gen['PE1'])
        self.assertIn('PL-MUNI-BR seq 10 permit 10.11.20.0/24',gen['PE2'])

    def test_render_customer_lan(self):
        gen=n.render(self.inv)
        self.assertIn('no interface Loopback10',gen['CE-MUNI-HQ'])
        self.assertIn('encapsulation dot1Q 10',gen['CE-MUNI-HQ'])
        self.assertIn('network 10.11.20.0 mask 255.255.255.0',gen['CE-MUNI-BR'])
        self.assertNotIn('network 10.10.99.0',gen['CE-MUNI-HQ'])

    def test_vlan_isolation(self):
        gen=n.render(self.inv)
        self.assertIn('deny ip 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 log',gen['CE-MUNI-HQ'])
        self.assertIn('switchport trunk allowed vlan 10,20,30,99',gen['SW-MUNI-HQ'])

    def test_no_core_changes(self):
        gen=n.render(self.inv)
        self.assertNotIn('P1',gen)
        self.assertNotIn('P2',gen)
        for name in ('PE1','PE2'):
            self.assertNotIn('router bgp',gen[name])
            self.assertNotIn('mpls',gen[name].lower())

    def test_preflight_guard(self):
        n.preflight_ios('CE-MUNI-HQ','interface Loopback10\n ip address 10.10.10.1 255.255.255.0\n!\ninterface GigabitEthernet0/1\n no ip address\n!')
        with self.assertRaises(RuntimeError):
            n.preflight_ios('CE-MUNI-HQ','interface Loopback10\n ip address 10.99.10.1 255.255.255.0\n!')

if __name__=='__main__': unittest.main()
