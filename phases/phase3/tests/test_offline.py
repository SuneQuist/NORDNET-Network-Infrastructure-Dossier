import importlib.util
import pathlib
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('nordnet_phase3', ROOT/'nordnet_phase3.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestPhase3Offline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = yaml.safe_load((ROOT/'inventory.yaml').read_text(encoding='utf-8'))

    def test_inventory(self):
        mod.validate_inventory(self.inv)

    def test_render(self):
        mod.render(self.inv)
        pe = (ROOT/'generated'/'PE1.cfg').read_text()
        br = (ROOT/'generated'/'CE-MUNI-BR.cfg').read_text()
        self.assertIn('neighbor 172.20.255.2 send-community extended', pe)
        self.assertIn('route-target import 65000:100', pe)
        self.assertIn('neighbor 172.21.0.5 remote-as 65000', br)
        self.assertIn('network 10.11.10.0 mask 255.255.255.0', br)

    def test_port_normalization(self):
        self.assertEqual(mod.norm_interface('GigabitEthernet0/1'), 'Gi0/1')

    def test_last_line_binary_and_text(self):
        for value in (b'PE1#\r\n%SYS-5-TEST: something\r\nPE1#\r\n', 'PE1#\r\n'):
            self.assertEqual(mod._last_line(value), 'PE1#')

    def test_no_duplicate_customer_addresses(self):
        import copy
        bad = copy.deepcopy(self.inv)
        bad['routers']['CE-MUNI-BR']['customer_ip'] = bad['routers']['CE-MUNI-HQ']['customer_ip']
        with self.assertRaises(ValueError):
            mod.validate_inventory(bad)


if __name__ == '__main__':
    unittest.main()
