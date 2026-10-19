import hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path
from unittest.mock import patch
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.detectors.catalog import build_registry
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench import service, agent

root = Path(tempfile.mkdtemp(prefix='ohscanner-agent-synthetic-'))
repo = root / 'repo'
repo.mkdir()
fixture = Path('/home/audit/ohscanner/worktrees/agent-llm-20261017/tests/detectors/fixtures/cpp_unsafe_calls/positive_unsafe.cpp')
shutil.copyfile(fixture, repo / 'positive_unsafe.cpp')
subprocess.run(['git','init','-q',str(repo)],check=True)
subprocess.run(['git','-C',str(repo),'config','user.name','OHScanner controlled test'],check=True)
subprocess.run(['git','-C',str(repo),'config','user.email','ohscanner-test@example.invalid'],check=True)
subprocess.run(['git','-C',str(repo),'add','positive_unsafe.cpp'],check=True)
subprocess.run(['git','-C',str(repo),'commit','-qm','synthetic fixture only'],check=True)
commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
report=run_reviewed_detectors(repo,'controlled/unsafe-calls',commit,('positive_unsafe.cpp',),build_registry(('ohscanner.cpp.unsafe_memory_call',)))
assert report['diagnostic_count'] >= 5, report['diagnostic_count']
report['_workbench']={'source_inventory':[{'file':'positive_unsafe.cpp','blob':subprocess.check_output(['git','-C',str(repo),'rev-parse',commit+':positive_unsafe.cpp'],text=True).strip(),'sha256':hashlib.sha256((repo/'positive_unsafe.cpp').read_bytes()).hexdigest()}]}
settings=Settings(root/'data',(root,)); app=create_app(settings); store=app.state.store
repo_row=store.add_repository('controlled/unsafe-calls',str(repo))
job_id='a'*32
spec={'commit':commit,'git_tree':report['git_tree'],'include_paths':['positive_unsafe.cpp']}
encoded=(json.dumps(report,ensure_ascii=False,separators=(',',':'))+'\n').encode()
artifact=service.artifact_dir(settings,job_id); artifact.mkdir(parents=True)
(artifact/'report.json').write_bytes(encoded)
with store.connect() as db:
    db.execute('INSERT INTO jobs(id,repository_id,spec,status,stage,created_at,report_sha256) VALUES(?,?,?,?,?,?,?)',(job_id,repo_row['id'],json.dumps(spec),'completed','complete','2026-10-18T00:00:00Z',hashlib.sha256(encoded).hexdigest()))
job=store.job(job_id)
candidate=service.findings(report)[0]
class Ops:
    def __init__(self): self.events=[]
    def get(self,key): return {'cancel_requested':False}
    def event(self,*args): self.events.append(args)
class Fake:
    def create(self,payload):
        final={'summary':'The controlled scanner fixture produced a static candidate; product impact is unverified.','assessment':'needs_more_evidence','supported_claims':[],'unsupported_claims':['This fixture does not prove a product vulnerability.'],'unknowns':['Reachability in a real product build','Attacker control and CIA impact'],'next_steps':['Human review of the bound source and product path']}
        return {'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':json.dumps(final)}]}],'usage':{'input_tokens':100,'output_tokens':100,'total_tokens':200}}
with patch.dict(os.environ,{'OHSCANNER_LLM_MODEL':'fake-test-only','OHSCANNER_LLM_API_KEY':'fake-not-a-secret'},clear=False):
    provider=agent.ProviderConfig.from_env()
    task_spec={'job_id':job_id,'candidate_id':candidate['id'],'mode':'single_shot','max_steps':1,'max_output_tokens':256,'max_total_input_tokens':24000,'max_total_output_tokens':512,'timeout_seconds':90,'source_submission_approved':True,'provider_fingerprint':provider.fingerprint,'prompt_version':agent.PROMPT_VERSION,'tool_policy_version':agent.TOOL_POLICY_VERSION}
    preview=agent.consent_preview(settings,store,job,report,candidate,task_spec,provider)
    task_spec['source_consent_sha256']=preview['consent_sha256']; task_spec['consent_preview_version']=agent.CONSENT_PREVIEW_VERSION
    events=Ops(); result=agent.execute_agent(settings,store,events,{'id':'b'*32,'spec':task_spec},client=Fake())
    print(json.dumps({'control_fixture':'positive_unsafe.cpp','commit':commit,'detector_id':candidate['detector_id'],'candidate_id':candidate['id'],'diagnostic_count':report['diagnostic_count'],'agent_mode':result['mode'],'assessment':result['agent_assessment']['assessment'],'vulnerability_state':result['vulnerability_state'],'validated_vulnerability':result['validated_vulnerability'],'model_calls':len(result['model_calls']),'source_consent_sha256':result['source_submission']['consent_sha256'],'operation_events':len(events.events)},ensure_ascii=False))
shutil.rmtree(root)