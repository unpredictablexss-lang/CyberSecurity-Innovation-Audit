from __future__ import annotations
import csv, hashlib, json, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
QUEUE=ROOT/'research/deliveries/cpp/a0_triage_20261019/queue.csv'
QUEUE_JSON=ROOT/'research/deliveries/cpp/a0_triage_20261019/queue.json'
RAW=HERE/'d36_preferences_basevalue_20261024.json'
OUT=HERE/'d36_preferences_basevalue_replay_20261024.json'
OBJECTS=Path(r'D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git')
COMMIT='bff9efd79afc0d7d1ed22a63ff355f1600404596'; TREE='7761d9e273ae7007046ae115797f255e554523ae'
REPO='openharmony/distributeddatamgr_preferences'
SRC='test/native/fuzztest/dbpreferencesbasevalue_fuzzer/dbpreferencesbasevalue_fuzzer.cpp'
BUILD='test/native/fuzztest/dbpreferencesbasevalue_fuzzer/BUILD.gn'
IDS=[f'CR-{i:04d}' for i in range(41,66)]
def git(*args, data=None): return subprocess.check_output(['git',f'--git-dir={OBJECTS}',*args],input=data)
def binding(path):
 b=git('show',f'{COMMIT}:{path}')
 return {'path':path,'blob':git('hash-object','--stdin',data=b).decode().strip(),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)}
def main():
 rows=list(csv.DictReader(QUEUE.open(encoding='utf-8-sig',newline='')))
 jq=json.loads(QUEUE_JSON.read_text(encoding='utf8'))['queue']; cmap={r['queue_id']:r for r in rows}; jmap={r['queue_id']:r for r in jq}
 assert len(rows)==len(jq)==len(cmap)==len(jmap)==345 and set(cmap)==set(jmap)
 assert git('show','-s','--format=%T',COMMIT).decode().strip()==TREE
 src,build=binding(SRC),binding(BUILD); raw=json.loads(RAW.read_text(encoding='utf8')); run=raw['detector_runs'][0]
 assert raw['commit']==COMMIT and raw['git_tree']==TREE and raw['repository']==REPO and raw['status']=='completed'
 assert raw['source_parsing']['parsing_status']=={'complete':1}
 assert (run['tool'],run['tool_version'],run['status'],run['diagnostic_count'])==('ohscanner.cpp.shared_ptr_race','0.5.1','completed',25)
 ds=[d for d in run['diagnostics'] if d['file']==SRC]; byline={d['line']:d for d in ds}; assert len(ds)==25
 items=[]
 for qid in IDS:
  a,j=cmap[qid],jmap[qid]
  for k in ('candidate_id','repository','commit','tree','path','line','blob','source_sha256','original_status','queue_status'): assert str(a[k])==str(j[k]),(qid,k)
  assert (a['repository'],a['commit'],a['tree'],a['path'])==(REPO,COMMIT,TREE,SRC)
  assert a['blob']==src['blob'] and a['source_sha256'].lower()==src['sha256']
  assert (a['original_status'],a['queue_status'])==('not_testable','paused_pending_evidence')
  d=byline[int(a['line'])]; assert d['rule_id']=='ohcpp-shared-ptr-race-candidate-001'
  items.append({'queue_id':qid,'candidate_id':a['candidate_id'],'source':{**src,'repository':REPO,'commit':COMMIT,'tree':TREE,'line':int(a['line'])},'original_a0':{'original_status':a['original_status'],'queue_status':a['queue_status']},'replay':{'detector':run['tool'],'version':run['tool_version'],'parse_status':'complete','coverage':'syntax_candidate','finding_line':d['line'],'symbol':d['symbol'],'rule_id':d['rule_id'],'diagnostic_id':d['diagnostic_id']},'disposition':'PARTIAL','reason':'Exact BUILD target is ohos_fuzztest in a testonly group; this establishes a fuzz harness, not a product race. The harness uses shared Preferences state, but scanner syntax candidates do not establish concurrent overlapping accesses, shipped reachability, or CIA impact.','queue_preserved':True})
 assert {int(cmap[q]['line']) for q in IDS}==set(byline)
 report={'schema_version':'d36-preferences-basevalue-source-replay-v1','task':'D36','source':{'repository':REPO,'commit':COMMIT,'tree':TREE,'file':src},'build_target':{'file':build,'target':'ohos_fuzztest(DBPreferencesBaseValueFuzzTest)','test_group':'group("fuzztest") [testonly = true]','harness_entry':'LLVMFuzzerTestOneInput','production_evidence':False},'queue':{'total_rows':345,'audited_ids':IDS,'a0_status_unchanged':True},'cli':{'raw':RAW.name,'detector':run['tool'],'version':run['tool_version'],'status':run['status'],'scope_files':run['scope_files'],'scope_loc':run['scope_loc'],'parse':raw['source_parsing']['parsing_status'],'findings':run['diagnostic_count'],'command':'python -m src.cli.main ohscan-run --repo-dir <pinned-source-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesbasevalue_fuzzer/dbpreferencesbasevalue_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race'},'items':items,'overall_disposition':'PARTIAL','detector_change':'none; all 25 exact A0 lines replay; findings are confined to a test-only fuzz harness and do not establish product races','queue_states_changed':False,'structured_vibe_prompt':{'role':'A 线 Preferences shared_ptr_race 开发线负责人','sustained_goal':'持续区分 test-only fuzz harness 语法候选与生产可达并发根因，防止重复行误当独立漏洞并保持来源可复现。','input':'D36 exact source identity and CLI replay; CR-0022–CR-0065 family evidence.','steps':['Inspect production call paths and BUILD inclusion separate from fuzz targets.','Trace same-object shared_ptr copies, actual dereferences/writes, locks/atomics, and thread creation/join or task dispatch.','Only change shared_ptr_race when a production-source missed root cause is demonstrated with source, safe, unrelated, renamed, and partial controls.','Bind all results to commit/tree/blob/SHA and retain A0 rows unchanged.'],'completion_gate':'Independent reproduction on exact source; product target/reachability and concurrent same-object unsynchronized access established before labeling product vulnerability; otherwise report PARTIAL/BLOCK with precise missing evidence.','boundaries':['No CVE/repository/name/hash hardcoding.','No promotion of syntax findings to vulnerabilities.','No A0 status edits or shared API/Catalog changes.']}}
 OUT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8'); print(f'wrote {OUT.name}; {len(items)} IDs; {len(ds)} findings')
if __name__=='__main__': main()

