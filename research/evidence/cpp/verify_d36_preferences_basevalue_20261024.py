from __future__ import annotations
import collections,csv,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[2]
QUEUE=ROOT/'research/deliveries/cpp/a0_triage_20261019/queue.csv'; QJSON=ROOT/'research/deliveries/cpp/a0_triage_20261019/queue.json'
RAW=HERE/'d36_preferences_basevalue_20261024.json'; REPORT=HERE/'d36_preferences_basevalue_replay_20261024.json'
def main():
 subprocess.check_call([sys.executable,str(HERE/'d36_preferences_basevalue_replay_20261024.py')])
 rows=list(csv.DictReader(QUEUE.open(encoding='utf-8-sig',newline=''))); jq=json.loads(QJSON.read_text(encoding='utf8'))['queue']; m={x['queue_id']:x for x in rows}
 assert len(rows)==len(jq)==len(m)==345
 counts={k:dict(collections.Counter(r[k] for r in rows)) for k in ('original_status','queue_status')}
 assert counts['original_status']=={'not_testable':336,'not_reproduced':9}
 assert counts['queue_status']=={'paused_pending_evidence':331,'queued_not_reproduced':9,'queued_first_batch':5}
 raw=json.loads(RAW.read_text(encoding='utf8')); run=raw['detector_runs'][0]; rep=json.loads(REPORT.read_text(encoding='utf8'))
 assert raw['source_parsing']['parsing_status']=={'complete':1}; assert (run['tool'],run['tool_version'],run['diagnostic_count'])==('ohscanner.cpp.shared_ptr_race','0.5.1',25)
 assert rep['task']=='D36' and rep['queue_states_changed'] is False and rep['overall_disposition']=='PARTIAL'
 assert len(rep['items'])==25 and {i['queue_id'] for i in rep['items']}=={f'CR-{x:04d}' for x in range(41,66)}
 diags={d['line']:d for d in run['diagnostics'] if d['file']==rep['source']['file']['path']}; assert len(diags)==25
 for i in rep['items']:
  q=m[i['queue_id']]; assert q['path']==rep['source']['file']['path'] and q['line']==str(i['source']['line'])
  assert q['blob']==i['source']['blob'] and q['source_sha256'].lower()==i['source']['sha256']
  assert (q['original_status'],q['queue_status'])==('not_testable','paused_pending_evidence')
  assert i['replay']['finding_line']==i['source']['line'] and i['replay']['diagnostic_id']==diags[i['source']['line']]['diagnostic_id']
 assert rep['build_target']['target']=='ohos_fuzztest(DBPreferencesBaseValueFuzzTest)' and rep['build_target']['production_evidence'] is False
 print('PASS D36: exact commit/tree/source/build identities; 25/25 A0 rows replay; complete parse')
 print('PASS A0: 345 rows and original status counts preserved')
 print('PASS classification: test-only fuzz target; PARTIAL; no detector changes')
if __name__=='__main__': main()
