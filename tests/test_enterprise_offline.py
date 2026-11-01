import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))

# load service file without importing main since no GNS3/Docker available
spec=importlib.util.spec_from_file_location('nordnet_services',ROOT/'services'/'nordnet_services.py')
service=importlib.util.module_from_spec(spec);spec.loader.exec_module(service)

try: import nordnet_enterprise as ent
except ImportError: ent=None  # project installer expects prior nordnet_local.py

class ServiceOffline(unittest.TestCase):
    def test_dns_a(self):
        q=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06portal\x07nordnet\x04test\x00\x00\x01\x00\x01'
        r=service.dns_response(q)
        self.assertIn(b'\x0a\x0a\x1e\xfa',r)
        self.assertEqual(r[:2],b'\x12\x34')
    def test_dns_unknown(self):
        q=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03bad\x07nordnet\x04test\x00\x00\x01\x00\x01'
        r=service.dns_response(q);self.assertEqual(r[3]&15,3)
    def test_dns_malformed(self):
        self.assertIsNone(service.dns_response(b'hi'))
    def test_source_allowlist(self):
        self.assertTrue(service.allow('10.20.10.10'))
        self.assertTrue(service.allow('10.30.254.1'))
        self.assertFalse(service.allow('172.20.255.1'))
        self.assertFalse(service.allow('8.8.8.8'))
        self.assertFalse(service.allow('not an IP'))
    def test_service_forwarding_fail_closed(self):
        text=(ROOT/'services'/'nordnet_services.py').read_text()
        self.assertIn("IPv4 forwarding not disabled; refusing to run",text)

@unittest.skipIf(ent is None,'Install into Phase 6.1 directory with nordnet_local.py')
class EnterpriseOffline(unittest.TestCase):
    def test_pinned_topology(self):
        self.assertEqual(len(ent.LINKS),5)
        self.assertEqual({x[2] for x in ent.LINKS},{ent.SERVICE,'PC-HQ-DHCP','PC-BR-DHCP'})
    def test_no_core_router_configuration(self):
        self.assertEqual(set(ent.CEs+ent.SWs),set(ent.DHCP)|set(ent.SWs))
        for name in ent.CEs+ent.SWs:
            cfg=ent.config(name)
            self.assertNotIn('router bgp',cfg)
            self.assertNotIn('mpls ip',cfg)
            self.assertNotIn('route-target',cfg)
    def test_host_routes_only(self):
        for n,g in [('CE-UNIV','10.20.254.2'),('CE-HEALTH','10.30.254.2')]:
            c=ent.config(n)
            self.assertIn('ip route 10.10.30.250 255.255.255.255 '+g,c)
            self.assertNotIn('ip route 10.10.0.0',c)
    def test_no_dhcp_on_mgmt_vlans(self):
        for ce in ent.CEs:
            c=ent.config(ce)
            self.assertNotIn('10.10.99.',c)
            self.assertNotIn('10.11.99.',c)
    def test_service_ip_never_leased(self):
        self.assertIn('ip dhcp excluded-address 10.10.30.250',ent.config('CE-MUNI-HQ'))

    def test_dhcp_static_addresses_excluded(self):
        for name,config in ((n,ent.config(n)) for n in ent.CEs):
            self.assertIn('ip dhcp excluded-address',config)
            self.assertIn('dns-server 10.10.30.250',config)
    def test_embedded_source_roundtrip(self):
        import shlex,base64,zlib
        cmd=ent.boot_cmd('print("HI")')
        tokens=shlex.split(cmd)
        self.assertEqual(tokens[:3],['python','-u','-c'])
        self.assertIn('base64.b64decode',tokens[3])
    def test_boot_command_contains_complete_service(self):
        import ast,shlex,base64,zlib
        cmd=ent.boot_cmd((ROOT/'services'/'nordnet_services.py').read_text())
        parts=shlex.split(cmd)
        code=parts[3]
        token=code.split("b64decode('")[1].split("')")[0]
        unpacked=zlib.decompress(base64.b64decode(token)).decode()
        self.assertIn('NORDNET_SERVICES_READY',unpacked)
        self.assertIn('IPv4 forwarding enabled; refusing',unpacked)
        self.assertLess(len(cmd),10000)

    def test_additive_interface_scopes(self):
        for n in ent.CEs+ent.SWs:
            cfg=ent.config(n)
            self.assertNotIn('no interface',cfg)
            self.assertNotIn('default interface',cfg)
            self.assertNotIn('router ospf',cfg)
            self.assertNotIn('address-family',cfg)
        self.assertIn('interface GigabitEthernet1/0',ent.config('SW-MUNI-HQ'))
        self.assertIn('interface GigabitEthernet1/1',ent.config('SW-MUNI-HQ'))
        self.assertNotIn('interface GigabitEthernet0/4',ent.config('SW-MUNI-HQ'))
        self.assertIn('interface GigabitEthernet0/3',ent.config('SW-MUNI-BR'))

    def test_guard_invariants(self):
        self.assertTrue(ent.check_invariants({'project':ent.PROJECT,'docker_image':ent.IMAGE,'service_ip':ent.DNS}))
        with self.assertRaises(RuntimeError):
            ent.check_invariants({'project':'WRONG','docker_image':ent.IMAGE,'service_ip':ent.DNS})

class InstallerOffline(unittest.TestCase):
    def test_extension_is_additive(self):
        self.assertTrue((ROOT/'nordnet_enterprise.py').is_file())
        self.assertTrue((ROOT/'services'/'nordnet_services.py').is_file())
        self.assertTrue((ROOT/'nordnet_local.py').is_file())

if __name__=='__main__':unittest.main()
