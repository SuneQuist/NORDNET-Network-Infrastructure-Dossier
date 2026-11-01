"""NORDNET v0.8.6 regression tests: choose fresh not replayed console heartbeat."""
import json
import sys
import types
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nordnet_acceptance as acceptance


def frame(name, age_seconds):
    obj={
        'node':name,
        'source_ip':acceptance.NODE_PLAN[name]['ip'],
        'created_utc':(datetime.now(timezone.utc)-timedelta(seconds=age_seconds)).isoformat(),
        'dns_ok':True,'http_ok':True,'events_policy_ok':True,'syslog_sent':True,
    }
    return acceptance.MARKER+json.dumps(obj)+'\n'


class FreshConsoleTests(unittest.TestCase):
    def test_newest_heartbeat_overrides_old(self):
        old=frame('PROBE-UNIV',600)
        recent=frame('PROBE-UNIV',3)
        obj=acceptance.newest_probe_heartbeat(old+recent,'PROBE-UNIV')
        self.assertEqual(obj['created_utc'], json.loads(recent[len(acceptance.MARKER):])['created_utc'])

    def test_ignores_wrong_node_and_partial_frame(self):
        data=frame('PROBE-MUNI',1)+frame('PROBE-HEALTH',2)+acceptance.MARKER+'{"node":"PROBE-HEALTH"'
        self.assertEqual(acceptance.newest_probe_heartbeat(data,'PROBE-HEALTH')['node'],'PROBE-HEALTH')
        self.assertIsNone(acceptance.newest_probe_heartbeat(data,'PROBE-UNIV'))

    def test_malformed_and_missing_time_ignored(self):
        bad=acceptance.MARKER+'{"node":"PROBE-UNIV","created_utc":"invalid"}\n'
        self.assertIsNone(acceptance.newest_probe_heartbeat(bad, 'PROBE-UNIV'))

    def test_probe_console_waits_for_fresh_after_stale_replay(self):
        chunks=[frame('PROBE-HEALTH',605).encode(),b'',frame('PROBE-HEALTH',1).encode()]
        class FakeTelnet:
            def __init__(self,*args,**kwargs): pass
            def read_very_eager(self):return chunks.pop(0) if chunks else b''
            def close(self):pass
        fake=types.SimpleNamespace(Telnet=FakeTelnet)
        node={'name':'PROBE-HEALTH','console':5044,'console_host':'127.0.0.1'}
        with patch.object(acceptance.sys,'version_info',(3,12)), \
             patch.dict(sys.modules,{'telnetlib':fake}), \
             patch.object(acceptance,'console_host',return_value='127.0.0.1'), \
             patch.object(acceptance.time,'sleep',return_value=None):
            obj=acceptance.probe_console(node,'127.0.0.1',timeout=10)
        self.assertTrue(acceptance.fresh(obj['created_utc'],seconds=90))
        self.assertEqual(obj['node'],'PROBE-HEALTH')

    def test_probe_console_rejects_stale_only(self):
        chunks=[frame('PROBE-UNIV',900).encode()]
        class FakeTelnet:
            def __init__(self,*args,**kwargs):pass
            def read_very_eager(self):return chunks.pop(0) if chunks else b''
            def close(self):pass
        fake=types.SimpleNamespace(Telnet=FakeTelnet)
        node={'name':'PROBE-UNIV','console':5046,'console_host':'127.0.0.1'}
        times=iter([0,0,2])
        with patch.object(acceptance.sys,'version_info',(3,12)), \
             patch.dict(sys.modules,{'telnetlib':fake}), \
             patch.object(acceptance,'console_host',return_value='127.0.0.1'), \
             patch.object(acceptance.time,'sleep',return_value=None), \
             patch.object(acceptance.time,'monotonic',side_effect=lambda:next(times)):
            with self.assertRaisesRegex(RuntimeError,'no FRESH E2E'):
                acceptance.probe_console(node,'127.0.0.1',timeout=1)

if __name__=='__main__':unittest.main()
