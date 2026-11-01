import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

PKG=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PKG))
# This test suite is run from the NORDNET source directory *after install*,
# where the existing Phase 6.1/v0.7 dependencies are available. For standalone
# testing in the build machine use extra path from bundled reference code.
if os.environ.get('NORDNET_TEST_DEPS'):
    sys.path.append(os.environ['NORDNET_TEST_DEPS'])
import nordnet_acceptance as a

class AcceptanceTests(unittest.TestCase):
    def test_static_vpcs(self):
        t='VPCS> show ip\r\nNAME : VPCS[1]\r\nIP/MASK : 10.10.10.10/24\r\nGATEWAY : 10.10.10.1\r\nVPCS>'
        self.assertEqual(a.parse_vpcs_ip(t),{'ip':'10.10.10.10','prefix':24,'gateway':'10.10.10.1'})
    def test_dynamic_vpcs(self):
        t='NAME : VPCS[1]\nIP/MASK     : 10.10.10.100/24\nGATEWAY     : 10.10.10.1\nDNS : 10.10.30.250'
        self.assertEqual(a.parse_vpcs_ip(t)['ip'],'10.10.10.100')
    def test_no_ip(self):
        with self.assertRaises(ValueError):a.parse_vpcs_ip('VPCS>')
    def test_field_must_not_be_gateway(self):
        with self.assertRaises(ValueError): a.parse_vpcs_ip('GATEWAY : 10.10.10.1\nDNS : 10.10.30.250')
    def test_startup_scripts_idempotent(self):
        api=MagicMock(); api.base='http://127.0.0.1:3080'
        api.s.get.return_value=MagicMock(status_code=200,content=b'ip dhcp\n')
        ns={n:{'node_id':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'} for n in a.DHCP}
        self.assertTrue(all(x['ok'] for x in a.dhcp_startup_audit(api,'/v2/projects/xxx',ns).values()))

    def test_reject_existing_custom_script(self):
        api=MagicMock();api.base='http://127.0.0.1:3080'
        api.s.get.return_value=MagicMock(status_code=200,content=b'ip 192.168.1.2 255.255.255.0 192.168.1.1\n')
        ns={n:{'node_type':'vpcs','compute_id':'vm','node_id':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'} for n in a.DHCP}
        with self.assertRaisesRegex(RuntimeError,'unexpected startup'):
            a.set_dhcp_startup(api,'/v2/projects/prj',ns)
        api.s.post.assert_not_called()

    def test_update_vpcs_node_file_api_verified(self):
        import tempfile
        api=MagicMock();api.base='http://127.0.0.1:3080'
        state={n:b'ip 10.10.10.100 255.255.255.0 10.10.10.1\n' if n=='PC-HQ-DHCP' else b'ip 10.11.10.100 255.255.255.0 10.11.10.1\n'
               for n in a.DHCP}
        ids={'PC-HQ-DHCP':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','PC-BR-DHCP':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
        def get(url,timeout):
            name=next(n for n,uid in ids.items() if uid in url)
            return MagicMock(status_code=200,content=state[name])
        def post(url,data,headers,timeout):
            name=next(n for n,uid in ids.items() if uid in url)
            state[name]=data
            return MagicMock(status_code=204)
        api.s.get.side_effect=get;api.s.post.side_effect=post
        ns={n:{'node_type':'vpcs','compute_id':'vm','node_id':ids[n]} for n in a.DHCP}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(a,'BASE',Path(tmp)):
                a.set_dhcp_startup(api,'/v2/projects/xxx',ns)
                self.assertEqual(len(list((Path(tmp)/'evidence'/'local_acceptance'/'vpcs_startup_backups').glob('*.startup.vpc'))),2)
                a.set_dhcp_startup(api,'/v2/projects/xxx',ns)
        self.assertEqual(api.s.post.call_count,2)
        self.assertEqual(state['PC-BR-DHCP'],b'ip dhcp\n')

    def test_dhcp_boot_wrong_node_type_blocked(self):
        api=MagicMock();api.base='http://127.0.0.1:3080'
        ns={n:{'node_type':'qemu','compute_id':'vm','node_id':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'} for n in a.DHCP}
        with self.assertRaisesRegex(RuntimeError,'not the expected VPCS'):
            a.set_dhcp_startup(api,'/v2/projects/xxx',ns)
        api.s.get.assert_not_called();api.s.post.assert_not_called()

    def test_vpcs_file_404_is_not_configured(self):
        api=MagicMock();api.base='http://127.0.0.1:3080'
        api.s.get.return_value=MagicMock(status_code=404)
        ns={n:{'node_id':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'} for n in a.DHCP}
        checks=a.dhcp_startup_audit(api,'/v2/projects/xxx',ns)
        self.assertTrue(all(not r['ok'] for r in checks.values()))

    def test_server_file_endpoint_not_node_property_put(self):
        self.assertTrue(a.vpcs_file_url('/v2/projects/xxx','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa').endswith('/files/startup.vpc'))
        self.assertTrue(a.approved_previous_vpcs_script(b'ip 10.11.10.100/24 10.11.10.1\n','10.11.10.0/24'))
        self.assertFalse(a.approved_previous_vpcs_script(b'echo unauthorised\n','10.11.10.0/24'))
    def test_native_vpcs_save_syntax_with_selector(self):
        content=(b'1\nset pcname VPCS\nip 10.10.10.100 10.10.10.1 24\n1\n')
        plan=a.parse_previous_vpcs_script(content,'10.10.10.0/24','10.10.10.1')
        self.assertEqual(plan['kind'],'saved_lease')
        self.assertEqual(plan['ip'],'10.10.10.100')
        self.assertEqual(a.make_dhcp_startup(plan), 'set pcname VPCS\nip dhcp\n')

    def test_native_vpcs_save_dns_domain_and_mask(self):
        content=(b'set pcname PC-BR-DHCP\nip 10.11.10.100 10.11.10.1 255.255.255.0\n'
                 b'dns 10.10.30.250\ndomain nordnet.test\n')
        plan=a.parse_previous_vpcs_script(content,'10.11.10.0/24','10.11.10.1')
        self.assertEqual(plan['kind'],'saved_lease')
        self.assertIn('set pcname PC-BR-DHCP',a.make_dhcp_startup(plan))

    def test_native_vpcs_bad_gateway_rejected(self):
        with self.assertRaises(ValueError):
            a.parse_previous_vpcs_script(b'1\nip 10.10.10.100 10.10.10.99 24\n',
                                         '10.10.10.0/24','10.10.10.1')

    def test_other_saved_network_rejected(self):
        self.assertFalse(a.approved_previous_vpcs_script(b'1\nip 10.99.10.100 10.99.10.1 24\n',
                                                          '10.10.10.0/24'))

    def test_unsafe_unknown_commands_rejected(self):
        self.assertFalse(a.approved_previous_vpcs_script(b'1\nip 10.10.10.100 10.10.10.1 24\n'
                                                          b'ping 1.1.1.1\n','10.10.10.0/24'))

    def test_backs_up_both_before_first_post(self):
        import tempfile
        api=MagicMock();api.base='http://127.0.0.1:3080'
        files={'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa':b'1\nip 10.10.10.100 10.10.10.1 24\n',
               'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb':b'1\nip 10.11.10.100 10.11.10.1 24\n'}
        ids={'PC-HQ-DHCP':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
             'PC-BR-DHCP':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
        def get(url,timeout):
            uid=next(uid for uid in files if uid in url)
            return MagicMock(status_code=200,content=files[uid])
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/'evidence'/'local_acceptance'/'vpcs_startup_backups'
            def post(url,data,headers,timeout):
                self.assertEqual(len(list(folder.glob('*.startup.vpc'))),2)
                uid=next(uid for uid in files if uid in url)
                files[uid]=data
                return MagicMock(status_code=204)
            api.s.get.side_effect=get;api.s.post.side_effect=post
            nodes={n:{'node_type':'vpcs','compute_id':'vm','node_id':ids[n]} for n in a.DHCP}
            with patch.object(a,'BASE',Path(tmp)):
                a.set_dhcp_startup(api,'/v2/projects/prj',nodes)
                backups=list(folder.glob('*.startup.vpc'))
                self.assertEqual({b.read_bytes() for b in backups},
                                 {b'1\nip 10.10.10.100 10.10.10.1 24\n',
                                  b'1\nip 10.11.10.100 10.11.10.1 24\n'})
                status=a.dhcp_startup_audit(api,'/v2/projects/prj',nodes)
                self.assertTrue(all(x['ok'] for x in status.values()))
        self.assertEqual(api.s.post.call_count,2)

    def test_readonly_inspect_does_not_post(self):
        api=MagicMock();api.base='http://127.0.0.1:3080'
        api.s.get.return_value=MagicMock(status_code=200,content=b'1\nip 10.10.10.100 10.10.10.1 24\n')
        ids={'PC-HQ-DHCP':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
             'PC-BR-DHCP':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
        nodes={n:{'node_type':'vpcs','compute_id':'vm','node_id':ids[n]} for n in a.DHCP}
        with patch('builtins.print') as printer:
            a.dhcp_startup_inspect(api,'/v2/projects/prj',nodes)
        self.assertIn('UNRECOGNIZED',str(printer.call_args_list))
        api.s.post.assert_not_called()

    def test_probe_script_start_command_contains_python(self):
        for n in a.NODE_PLAN:
            cmd=a.make_boot_command(n)
            self.assertTrue(cmd.startswith('python -u -c '))
            self.assertLess(len(cmd),20000)
    def test_syslog_receive_validation(self):
        now=datetime.now(timezone.utc).isoformat()
        probes={}
        for n,inf in a.NODE_PLAN.items():
            probes[n]={'node':n,'source_ip':inf['ip'],'created_utc':now,
                       'dns_ok':True,'http_ok':True,'events_policy_ok':True,'syslog_sent':True}
        probes['PROBE-MUNI']['events']=[{'source':inf['ip'],'received_utc':now,'message':'NORDNET_ACCEPTANCE:'+n}
                                          for n,inf in a.NODE_PLAN.items()]
        self.assertEqual(a.assess(probes),[])
        probes['PROBE-MUNI']['events'].pop()
        self.assertTrue(any('recent syslog reception' in x for x in a.assess(probes)))
    def test_bad_time(self):
        self.assertFalse(a.fresh('2020-10-31T00:00:00+00:00'))
        self.assertFalse(a.fresh(None))
    def test_syslog_send_not_reception(self):
        now=datetime.now(timezone.utc).isoformat()
        obj={n:{'node':n,'source_ip':v['ip'],'created_utc':now,'dns_ok':True,
                'http_ok':True,'events_policy_ok':True,'syslog_sent':True}
             for n,v in a.NODE_PLAN.items()}
        self.assertEqual(len([x for x in a.assess(obj) if 'recent syslog reception' in x]),3)
    def test_duplicate_ip_prevented(self):
        self.assertEqual(len({x['ip'] for x in a.NODE_PLAN.values()}),3)
    def test_no_router_changes_in_plan(self):
        with patch('builtins.print') as o:
            a.plan()
        text='\n'.join(' '.join(map(str,x.args)) for x in o.call_args_list)
        self.assertIn('not included',text.lower())
    def test_dhcp_start_script_default(self):
        self.assertEqual(a.VPCS_SCRIPT,'ip dhcp\n')


    def test_native_dhcp_startup_equivalence_and_no_rewrite(self):
        """Both forms from the actual GNS3 node-file endpoint already request DHCP."""
        import tempfile
        api=MagicMock();api.base='http://127.0.0.1:3080'
        ids={'PC-HQ-DHCP':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
             'PC-BR-DHCP':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
        files={ids['PC-HQ-DHCP']:b'set pcname VPCS\nip dhcp\n',
               ids['PC-BR-DHCP']:b'set pcname VPCS\ndhcp\n'}
        def get(url,timeout):
            key=next(uid for uid in files if uid in url)
            return MagicMock(status_code=200,content=files[key])
        api.s.get.side_effect=get
        nodes={n:{'node_type':'vpcs','compute_id':'vm','node_id':ids[n]} for n in a.DHCP}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(a,'BASE',Path(tmp)):
                a.set_dhcp_startup(api,'/v2/projects/xxx',nodes)
                self.assertTrue(all(d['ok'] for d in a.dhcp_startup_audit(api,'/v2/projects/xxx',nodes).values()))
                self.assertFalse((Path(tmp)/'evidence').exists())
        api.s.post.assert_not_called()

    def test_gns3_file_post_http_201_is_success(self):
        api=MagicMock();api.base='http://127.0.0.1:3080'
        api.s.post.return_value=MagicMock(status_code=201,text='')
        a.node_file_post(api,'/v2/projects/xxx','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',b'ip dhcp\n')
        api.s.post.assert_called_once()

    def test_gns3_file_post_http_400_is_error(self):
        api=MagicMock();api.base='http://127.0.0.1:3080'
        api.s.post.return_value=MagicMock(status_code=400,text='not allowed')
        with self.assertRaisesRegex(RuntimeError,'HTTP 400'):
            a.node_file_post(api,'/v2/projects/xxx','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',b'ip dhcp\n')

    def test_partial_write_retry_with_http_201(self):
        """Simulates the user's HQ file already updated but branch saved native DHCP."""
        import tempfile
        api=MagicMock();api.base='http://127.0.0.1:3080'
        ids={'PC-HQ-DHCP':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
             'PC-BR-DHCP':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
        files={ids['PC-HQ-DHCP']:b'set pcname VPCS\nip dhcp\n',
               ids['PC-BR-DHCP']:b'set pcname VPCS\ndhcp\n'}
        def get(url,timeout):
            uid=next(uid for uid in files if uid in url)
            return MagicMock(status_code=200,content=files[uid])
        api.s.get.side_effect=get
        nodes={n:{'node_type':'vpcs','compute_id':'vm','node_id':ids[n]} for n in a.DHCP}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(a,'BASE',Path(tmp)):
                a.set_dhcp_startup(api,'/v2/projects/test',nodes)
        api.s.post.assert_not_called()

    def test_true_saved_lease_post_201_readback(self):
        import tempfile
        api=MagicMock();api.base='http://127.0.0.1:3080'
        ids={'PC-HQ-DHCP':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
             'PC-BR-DHCP':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
        files={ids['PC-HQ-DHCP']:b'set pcname VPCS\ndhcp\n',
               ids['PC-BR-DHCP']:b'set pcname VPCS\nip 10.11.10.100 10.11.10.1 24\n'}
        def get(url,timeout):
            uid=next(uid for uid in files if uid in url)
            return MagicMock(status_code=200,content=files[uid])
        def post(url,data,headers,timeout):
            uid=next(uid for uid in files if uid in url)
            files[uid]=data
            return MagicMock(status_code=201,text='')
        api.s.get.side_effect=get;api.s.post.side_effect=post
        nodes={n:{'node_type':'vpcs','compute_id':'vm','node_id':ids[n]} for n in a.DHCP}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(a,'BASE',Path(tmp)):
                a.set_dhcp_startup(api,'/v2/projects/test',nodes)
                backups=list((Path(tmp)/'evidence/local_acceptance/vpcs_startup_backups').glob('*.startup.vpc'))
                self.assertEqual(len(backups),1)
                self.assertTrue(all(d['ok'] for d in a.dhcp_startup_audit(api,'/v2/projects/test',nodes).values()))
        api.s.post.assert_called_once()

if __name__=='__main__':unittest.main()
