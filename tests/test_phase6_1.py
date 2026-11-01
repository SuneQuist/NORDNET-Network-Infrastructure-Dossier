import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ios_console as ios
import nordnet_local as net
import yaml

TRUNK_HQ = """Port        Mode             Encapsulation  Status        Native vlan
Gi0/0       on               802.1q         trunking      1

Port        Vlans allowed on trunk
Gi0/0       10,20,30,99

Port        Vlans allowed and active in management domain
Gi0/0       10,20,30,99

Port        Vlans in spanning tree forwarding state and not pruned
Gi0/0       none
"""

class UpdateTests(unittest.TestCase):
    def test_trunk_working_even_with_stp_none(self):
        ok, detail=net.trunk_state(TRUNK_HQ,'GigabitEthernet0/0',(10,20,30,99))
        self.assertTrue(ok,detail)

    def test_trunk_dynamic_auto_fails(self):
        bad=TRUNK_HQ.replace('on               802.1q         trunking','auto             native        not-trunking')
        self.assertFalse(net.trunk_state(bad,'GigabitEthernet0/0',(10,20,30,99))[0])

    def test_missing_vlan_fails(self):
        bad=TRUNK_HQ.replace('Vlans allowed and active in management domain\nGi0/0       10,20,30,99',
                             'Vlans allowed and active in management domain\nGi0/0       10,20,99')
        self.assertFalse(net.trunk_state(bad,'Gi0/0',(10,20,30,99))[0])

    def test_5_ping_maybe_arp_loss(self):
        self.assertTrue(net.ping_reachable('Success rate is 80 percent (4/5)'))
        self.assertTrue(net.ping_reachable('Success rate is 100 percent (5/5)'))
        self.assertFalse(net.ping_reachable('Success rate is 20 percent (1/5)'))
        self.assertFalse(net.ping_reachable('Error: timeout'))
        self.assertTrue(net.ping_blocked('Success rate is 0 percent (0/5)'))
        self.assertFalse(net.ping_blocked('Success rate is 20 percent (1/5)'))
        self.assertFalse(net.ping_blocked('Error: timeout'))

    def test_vpcs_reply_only(self):
        self.assertTrue(net.vpcs_received_reply('84 bytes from 10.10.10.1 icmp_seq=1 ttl=255 time=5.010 ms'))
        self.assertFalse(net.vpcs_received_reply('10.10.10.10 icmp_seq=1 ttl=64 time=0.001 ms'))
        self.assertFalse(net.vpcs_received_reply('timeout'))

    def test_ios_rejected_commands_caught(self):
        self.assertIsNotNone(ios.CMD_ERROR.search('\r\n% Command rejected: trunk encapsulation is Auto\r\n'))
        self.assertIsNotNone(ios.CMD_ERROR.search('% Invalid input detected at ^ marker.'))
        self.assertIsNone(ios.CMD_ERROR.search('%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up'))

    def test_template_sets_encapsulation_first(self):
        inv=yaml.safe_load((net.BASE/'inventory.yaml').read_text())
        generated=net.render(inv)
        for sw in ('SW-MUNI-HQ','SW-MUNI-BR'):
            cfg=generated[sw]
            self.assertIn('switchport trunk encapsulation dot1q', cfg)
            self.assertLess(cfg.index('switchport trunk encapsulation dot1q'),cfg.index('switchport mode trunk'))

if __name__ == '__main__': unittest.main()
