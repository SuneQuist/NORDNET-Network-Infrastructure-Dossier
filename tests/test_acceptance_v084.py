"""Regression test for the Phase 6.1 verify(nodes,host,inv) signature."""
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

class VerifierIntegrationTest(unittest.TestCase):
    def test_acceptance_passes_inventory_to_phase61_verify(self):
        import nordnet_acceptance as acceptance
        nodes = {'PE1': {'name': 'PE1'}}
        inv = {'endpoints': [{'name': 'PC-HQ-STAFF'}]}
        vm = {'host': 'example.invalid'}
        # Do not access a real controller: test the call contract and downstream flow.
        probe_data = {name: {'node': name, 'source_ip': info['ip']} for name, info in acceptance.NODE_PLAN.items()}
        with patch.object(acceptance, 'check_topology', return_value={'status': 'PASS'}), \
             patch.object(acceptance.local, 'verify') as baseline, \
             patch.object(acceptance, 'dhcp_startup_audit', return_value={}), \
             patch.object(acceptance, 'probe_console', side_effect=lambda n,h,**k: probe_data[n['name']]), \
             patch.object(acceptance, 'assess', return_value=[]), \
             patch.object(acceptance, 'vpcs_audit', return_value=({}, [])), \
             patch.object(acceptance, 'ios_persistence', return_value=({}, [])), \
             patch.object(acceptance, 'save_report', return_value=Path('not-written')):
            test_nodes = dict(nodes)
            test_nodes.update({name: {'name': name} for name in acceptance.NODE_PLAN})
            # A two-argument call raises TypeError and fails this test.
            baseline.side_effect = lambda n,h,i: self.assertIs(i, inv)
            acceptance.verify(MagicMock(), '/v2/projects/example', vm, test_nodes, inv, 'example')
            baseline.assert_called_once_with(test_nodes, vm['host'], inv)
