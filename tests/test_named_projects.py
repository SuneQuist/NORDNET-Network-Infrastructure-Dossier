"""Offline named-project creation/isolation tests. No real GNS3 API calls."""
import io
import os
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import patch

import nordnet


class StubProjectAPI:
    def __init__(self):
        self.projects=[{'name':nordnet.PROJECT,'project_id':'main-uuid','status':'opened'}]
        self.nodes={'main-uuid':[{'name':'MAIN-DO-NOT-TOUCH','node_id':'main'}]}
        self.links={'main-uuid':[]}
        self.posts=[]

    def api(self,method,path,payload=None):
        if method=='GET' and path=='/v2/version':return {'version':'2.2.50'}
        if method=='GET' and path=='/v2/computes':return [{'compute_id':'vm','connected':True,'capabilities':{'node_types':['qemu']}}]
        if method=='GET' and path=='/v2/templates':return [{'name':'Cisco IOSv 15.9(3)M8','template_type':'qemu','template_id':'ios','compute_id':'vm','adapters':4}]
        if method=='GET' and path=='/v2/projects':return list(self.projects)
        if method=='POST' and path=='/v2/projects':
            self.posts.append((method,path,payload))
            project={'name':payload['name'],'project_id':'new-uuid','status':'opened'}
            self.projects.append(project);self.nodes['new-uuid']=[];self.links['new-uuid']=[]
            return project
        if method=='GET' and path.endswith('/nodes'):
            return list(self.nodes[path.split('/')[3]])
        if method=='GET' and path.endswith('/links'):
            return list(self.links[path.split('/')[3]])
        if method=='POST' and '/templates/ios' in path:
            self.posts.append((method,path,payload))
            n={'name':payload['name'],'node_id':payload['name']+'-id','template_id':'ios','compute_id':'vm',
               'status':'stopped', 'ports':[{'adapter_number':i,'port_number':0} for i in range(4)]}
            self.nodes[path.split('/')[3]].append(n);return n
        if method=='POST' and path.endswith('/links'):
            self.posts.append((method,path,payload))
            self.links[path.split('/')[3]].append(payload);return payload
        if method=='POST' and path.endswith('/start'):
            self.posts.append((method,path,payload))
            node_id=path.split('/')[-2]
            for n in self.nodes[path.split('/')[3]]:
                if n['node_id']==node_id:n['status']='started';return {}
        raise AssertionError((method,path,payload))

class NamedProjects(unittest.TestCase):
    def test_context_restored_even_on_failure(self):
        previous=os.environ.get(nordnet.ENV_PROJECT)
        with self.assertRaisesRegex(RuntimeError,'stopped'):
            with nordnet.project_context('NORDNET-Build-02'):
                self.assertEqual(os.environ[nordnet.ENV_PROJECT],'NORDNET-Build-02')
                raise RuntimeError('stopped')
        self.assertEqual(os.environ.get(nordnet.ENV_PROJECT),previous)

    def test_reject_invalid_names(self):
        for name in ('',' bad','bad ','x'*101,'foo/bar','foo\\bar','foo\nbar','foo\tbar'):
            with self.subTest(name=repr(name)),self.assertRaisesRegex(RuntimeError,'name'):
                nordnet.valid_name(name)
        self.assertEqual(nordnet.valid_name('NORDNET Test 02'),'NORDNET Test 02')

    def test_old_and_new_target_differ(self):
        class Projects:
            def get(self,path):
                if path=='/v2/projects':
                    return [{'name':nordnet.PROJECT,'project_id':'protected','status':'opened'},
                            {'name':'NORDNET-New','project_id':'new','status':'opened'}]
                if path=='/v2/projects/new/nodes':return []
                if path=='/v2/projects/protected/nodes':return [{'name':'PE1','node_id':'original'}]
                raise AssertionError(path)
        api=Projects()
        with self.assertRaisesRegex(RuntimeError,'REFUSES existing project'):
            nordnet.require_state(api,'fresh','deploy','NORDNET-New')
        p,names,_=nordnet.project_status(api,'NORDNET-New')
        self.assertEqual(p['project_id'],'new')
        self.assertEqual(names,set())
        self.assertEqual(nordnet.project_status(api,nordnet.PROJECT)[0]['project_id'],'protected')

    def test_no_target_does_not_block_when_main_exists(self):
        class MainOnly:
            def get(self,path):
                if path=='/v2/projects':return [{'name':nordnet.PROJECT,'project_id':'protected','status':'opened'}]
                raise AssertionError(path)
        self.assertIsNone(nordnet.require_state(MainOnly(),'fresh','deploy','NORDNET-New')[0])

    def test_stage_1_creates_name_and_never_touches_main(self):
        api=StubProjectAPI()
        with nordnet.project_context('NORDNET-Lab-01'):
            with nordnet.load_stage('phases/phase1/nordnet_gns3_phase1.py', ['--start','--project','NORDNET-Lab-01']) as stage:
                with patch.object(stage,'Gns3',return_value=api),patch.object(stage,'getpass',return_value='dummy'):
                    with redirect_stdout(io.StringIO()):stage.main()
        self.assertEqual(api.projects[-1]['name'],'NORDNET-Lab-01')
        self.assertEqual(len(api.nodes['new-uuid']),3)
        self.assertEqual(len(api.links['new-uuid']),2)
        self.assertEqual(api.nodes['main-uuid'],[{'name':'MAIN-DO-NOT-TOUCH','node_id':'main'}])
        self.assertFalse(any('/main-uuid/' in path for _,path,_ in api.posts))

    def test_all_phases_accept_dynamic_inventory_name(self):
        names=[('phases/phase2/nordnet_phase2.py','validate_design'),
               ('phases/phase3/nordnet_phase3.py','validate_inventory'),
               ('phases/phase4/nordnet_phase4.py','validate_inventory'),
               ('phases/phase5/nordnet_phase5.py','validate_inventory'),
               ('nordnet_local.py','validate'),
               ('nordnet_enterprise.py','check_invariants')]
        class Seen(Exception): pass
        with nordnet.project_context('NORDNET-Automated-Test'):
            for source,method in names:
                with self.subTest(source=source):
                    seen=[]
                    def collect(inv):
                        seen.append(inv['project']);raise Seen()
                    with nordnet.load_stage(source,['--plan'] if source=='nordnet_enterprise.py' else []) as stage:
                        with patch.object(stage,method,side_effect=collect):
                            with self.assertRaises(Seen):stage.main()
                    self.assertEqual(seen,['NORDNET-Automated-Test'])

    def test_orchestrator_propagates_requested_project_to_phase1(self):
        """A same-controller main project does not block a fresh, differently named build."""
        target='NORDNET-2'
        api=StubProjectAPI()
        api.get=lambda path: ({'/v2/version':{'version':'2.2'},
                               '/v2/computes':[{'compute_id':'vm','connected':True,'host':'192.0.2.2','capabilities':{'node_types':['qemu','docker']}}],
                               '/v2/templates':[{'name':n,'template_type':'qemu','template_id':n,'compute_id':'vm'} for n in nordnet.TEMPLATES],
                               '/v2/computes/vm/docker/images':['python:3.12-alpine']}.get(path)
                              if path!='/v2/projects' else list(api.projects))
        stages=[]
        def fake_stage(label,source,params,password,url,user,log):
            self.assertEqual(os.environ[nordnet.ENV_PROJECT],target)
            stages.append((label,source,params))
            if source.endswith('phase1/nordnet_gns3_phase1.py'):
                self.assertEqual(params[-2:],['--project',target])
                api.projects.append({'name':target,'project_id':'new-uuid','status':'opened'})
                api.nodes['new-uuid']=[{'name':n,'node_id':n} for n in nordnet.NAMES_20]
        def project_lookup(_api,name):
            self.assertIs(_api,api)
            self.assertEqual(name,target)
            if not any(p['name']==target for p in api.projects):return None,set(),None
            return api.projects[-1],set(nordnet.NAMES_20),{}
        with patch.object(nordnet,'Controller',return_value=api),patch.object(nordnet,'getpass',return_value='pw'):
            with patch.object(nordnet,'run_stage',side_effect=fake_stage),patch.object(nordnet,'run_with_convergence',side_effect=fake_stage):
                with patch.object(nordnet,'project_status',side_effect=project_lookup),patch.object(nordnet,'renew_dhcp',return_value=None),patch.object(nordnet,'write_run_log'):
                    with patch.object(nordnet.time,'sleep',return_value=None),patch.object(nordnet.sys,'version_info',(3,12)):
                        with redirect_stdout(io.StringIO()):
                            nordnet.main(['deploy','--mode','fresh','--name',target,'--approve-maintenance','--backup-confirmed'])
        self.assertEqual(len(stages),len(nordnet.PHASES)+2)  # final verify + commit
        self.assertEqual(api.projects[0]['name'],nordnet.PROJECT)
        self.assertEqual(os.environ.get(nordnet.ENV_PROJECT),None)

    def test_enterprise_phase6_baseline_uses_target_name(self):
        with nordnet.project_context('NORDNET-Named'):
            with nordnet.load_stage('nordnet_enterprise.py',[]) as stage:
                invs=[]
                def capture(inv):invs.append(inv['project'])
                with patch.object(stage.old,'validate',side_effect=capture),patch.object(stage.old,'verify',return_value=None):
                    with redirect_stdout(io.StringIO()):stage.phase6_baseline({}, {'host':'192.0.2.2'})
                self.assertEqual(invs,['NORDNET-Named'])

if __name__=='__main__':unittest.main()
