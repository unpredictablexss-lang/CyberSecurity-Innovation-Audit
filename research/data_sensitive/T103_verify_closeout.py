"""Independent frozen-source closeout runner. Does not execute target code or push."""
from __future__ import annotations
import argparse, concurrent.futures, hashlib, io, json, pathlib, re, subprocess, sys, tarfile, tempfile

ROOT=pathlib.Path(__file__).resolve().parents[2]
PYTHON=sys.executable
SUITES={
 'focused':['-B','-m','unittest','tests.detectors.data.test_d101_comma_result_proof','tests.detectors.data.test_t100_comma_values_and_effects','tests.test_cpp_assignment_comma','tests.detectors.data.test_t101_assignment_comma_parser','-q'],
 'data':['-B','-m','unittest','discover','-s','tests/detectors/data','-q'],
 'compat':['-B','-m','unittest','tests.test_ast','tests.test_ast_scanner','tests.test_cpp_empty_linkage','tests.test_t87_cpp_linkage_guards','tests.test_cpp_assignment_comma','tests.detectors.test_known_disclosed_cves','tests.detectors.test_known_case_corpus','-q']}

def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args])
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--revision',required=True);p.add_argument('--cache',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);args=p.parse_args()
 revision=git('rev-parse',args.revision).decode().strip()
 # Historical tests read their pinned baselines and replay modules; include the
 # whole research directory and samples rather than misclassifying absent inputs.
 paths=['src','tests','config','scripts','samples','research/data_sensitive']
 archive=git('archive',revision,*paths);args.cache.mkdir(parents=True,exist_ok=True)
 snapshot=pathlib.Path(tempfile.mkdtemp(prefix='t103_'+revision[:10]+'_',dir=args.cache.resolve()))
 with tarfile.open(fileobj=io.BytesIO(archive)) as t:t.extractall(snapshot,filter='data')
 def suite(item):
  name,command=item;done=subprocess.run([PYTHON,*command],cwd=snapshot,capture_output=True,timeout=180)
  log=done.stdout+done.stderr;match=re.search(rb'Ran (\d+) tests?',log)
  return name,{'command':[PYTHON,*command],'exit_code':done.returncode,'tests':int(match[1]) if match else None,'log_sha256':sha(log),'log':log.decode('utf-8',errors='replace'),'passed':done.returncode==0 and b'\nOK' in log}
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:suites=dict(pool.map(suite,SUITES.items()))
 manifest=snapshot/'research/data_sensitive/T102_SOURCE_MANIFEST.json';replay=snapshot/'real.json'
 command=[PYTHON,'-B',str(snapshot/'research/data_sensitive/T102_verify_real_slice.py'),'--snapshot-root',str(snapshot),'--revision',revision,'--git-dir','D:/openHarmonyScanner/openharmony/.repo/project-objects/arkui_napi.git','--manifest',str(manifest),'--output',str(replay)]
 run=subprocess.run(command,cwd=snapshot,capture_output=True,timeout=120)
 source=json.loads(replay.read_text(encoding='utf-8')) if replay.exists() else {'status':'not_run'}
 def worker(name):
  done=subprocess.run([PYTHON,'-B',str(snapshot/'research/data_sensitive'/name),'--worker',str(snapshot)],cwd=snapshot,capture_output=True,timeout=120)
  if done.returncode:raise RuntimeError(name+': '+done.stderr.decode('utf-8',errors='replace'))
  return json.loads(done.stdout)
 d103=worker('D103_replay_real_cpp.py')
 # Reuse the independent fixed source contract (profile and to_dict schema),
 # rather than D92's older synthetic request defaults/dataclass serialization.
 t101_output=snapshot/'t101-final.json'
 done=subprocess.run([PYTHON,'-B',str(snapshot/'research/data_sensitive/T101_verify_assignment_comma.py'),'--snapshot-root',str(snapshot),'--revision',revision,'--cert-git-dir','D:/openHarmonyScanner/openharmony/.repo/project-objects/security_certificate_framework.git','--output',str(t101_output)],cwd=snapshot,capture_output=True,timeout=120)
 if done.returncode:raise RuntimeError(done.stderr.decode('utf-8',errors='replace'))
 t101=json.loads(t101_output.read_text(encoding='utf-8'))
 t85={k:t101[k] for k in ['direct','runner','coverage','snapshot_sha256','parse_status']}
 t85['calls']=[{'file':path,**{k:v for k,v in c.items() if k!='original_span_sha256'},'raw_span_sha256':c['original_span_sha256']} for path,rows in t101['call_positions'].items() for c in rows]
 previous=json.loads(git('show',revision+':research/data_sensitive/T102_FIXED_REAL_REPLAY.json'))['runs'][1]
 comparison={k:source.get(k)==previous[k] for k in ['snapshot_sha256','raw_checks','features','call_facts','source_profile','coverage']}
 comparison.update(direct_findings_equal=source.get('direct',{}).get('findings')==previous['direct']['findings'],runner_diagnostics_equal=source.get('runner',{}).get('diagnostics')==previous['runner']['diagnostics'],direct_limitations_equal=source.get('direct',{}).get('limitations')==previous['direct']['limitations'])
 reference_checks=[]
 for report in ['D102_VALIDATION_20261020.json','D103_VALIDATION_20261020.json']:
  d=json.loads(git('show',revision+':research/data_sensitive/'+report));delivery=d['independent_delivery']
  for row in delivery['files']:
   raw=git('show',delivery['commit']+':'+row['path']);blob=git('rev-parse',delivery['commit']+':'+row['path']).decode().strip();current=git('show',revision+':'+row['path'])
   reference_checks.append({'report':report,'commit':delivery['commit'],'path':row['path'],'blob':blob,'sha256':sha(raw),'bytes':len(raw),'fixed_reference_matches':blob==row['blob'] and sha(raw)==row['sha256'] and len(raw)==row['bytes'],'integrated_bytes_equal':raw==current})
 tree_raw=git('show',revision+':research/data_sensitive/D_LINE_TASK_TREE_20261020.json');duplicates=[]
 def pairs(rows):
  out={}
  for key,value in rows:
   if key in out:duplicates.append(key)
   out[key]=value
  return out
 tree=json.loads(tree_raw,object_pairs_hook=pairs)
 selected_tasks=[x for x in tree['tasks'] if x['id'] in ['D101','T100','D102','T101','D103','T102','D104','T103']]
 prior=json.loads(git('show',revision+':research/data_sensitive/T101_FIXED_PARSER_REPLAY.json'))
 old=prior['runs'][-1]
 old_calls=sorted((path,c['name'],tuple(c['arguments']),c['line'],c['start_byte'],c['end_byte'],c['original_span_sha256']) for path,calls in old['call_positions'].items() for c in calls)
 calls=sorted((c['file'],c['name'],tuple(c['arguments']),c['line'],c['start_byte'],c['end_byte'],c['raw_span_sha256']) for c in t85['calls'])
 t85_comparison={'direct_findings_equal':t85['direct']['findings']==old['direct']['findings'],'runner_diagnostics_equal':t85['runner']['diagnostics']==old['runner']['diagnostics'],'coverage_equal':t85['coverage']==old['coverage'],'parse_status_equal':t85['parse_status']==old['parse_status'],'all_638_calls_equal':calls==old_calls,'call_count':len(calls),'original_890_915':[c for c in t85['calls'] if c['line'] in [890,915] and c['name']=='napi_get_value_string_utf8']}
 result={'schema':1,'revision':revision,'src_tree':git('rev-parse',revision+':src').decode().strip(),'src_archive_sha256':sha(git('archive',revision,'src')),'test_input_archive_sha256':sha(archive),'suites':suites,'real_replay_exit':run.returncode,'real_replay_stderr':run.stderr.decode('utf-8',errors='replace'),'real_replay':source,'comparison_to_T102':comparison,'reference_checks':reference_checks,'task_tree_sha256':sha(tree_raw),'task_tree_duplicate_keys':duplicates,'task_tree_selected_tasks':selected_tasks,'current_versions':tree['current_versions'],'closeout_plan':tree['closeout_plan'],'prior_known_gap_evidence_sha256':sha(git('show',revision+':research/data_sensitive/T101_FIXED_PARSER_REPLAY.json')),'prior_known_gap_top_level_keys':list(prior),'interpretation':'Passing scanner tests and blocked zero-candidate real replay are different evidence. No target build, product safety, precision/recall or remote delivery is established.'}
 result.update(d103_worker=d103,d103_worker_same_direct=d103['direct']==source['direct'],d103_worker_same_coverage=d103['coverage']==source['coverage'],t85_replay=t85,t85_comparison=t85_comparison,current_t101_parser_controls={'tests':t101['tests'],'independent_role_cases':t101['independent_role_cases'],'negative_parse_controls':t101['negative_parse_controls']},direct_limitation_delta={'removed':[x for x in previous['direct']['limitations'] if x not in source['direct']['limitations']],'added':[x for x in source['direct']['limitations'] if x not in previous['direct']['limitations']]})
 required_comparison=[v for k,v in comparison.items() if k!='direct_limitations_equal']
 result['closeout_checks']={
  'suites_pass':all(x['passed'] for x in suites.values()),
  'source_pipeline_executed':run.returncode==0,
  'source_compatibility_preserved':all(required_comparison),
  'source_zero_retains_blocked':source['runner']['status']=='blocked' and source['direct']['status']=='blocked',
  'source_retains_three_partial':source['coverage']['detectors']['ohscanner.data.sensitive_exposure']['coverage_counts']=={'complete':0,'partial':3,'not_analyzed':0,'failed':0},
  'developer_worker_matches':result['d103_worker_same_direct'] and result['d103_worker_same_coverage'],
  'fixed_references_integrated':all(x['fixed_reference_matches'] and x['integrated_bytes_equal'] for x in reference_checks),
  'task_tree_keys_unique':not duplicates,
  'certificate_pipeline_compatibility':all(t85_comparison[k] for k in ['direct_findings_equal','runner_diagnostics_equal','coverage_equal','parse_status_equal','all_638_calls_equal']),
  'core_parser_methods_pass':t101['tests']['count']==18 and t101['tests']['failures']==0 and t101['tests']['errors']==0,
  'negative_and_unmatched_controls_retain_partial_blocked':len(t101['negative_parse_controls'])==12 and all(x['frontend_parse_status']=='partial' and x['runner']['status']=='blocked' for x in t101['negative_parse_controls'])}
 args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'revision':revision,'suites':{k:(v['tests'],v['passed']) for k,v in suites.items()},'source_status':source.get('runner',{}).get('status'),'comparison':comparison,'reference_checks_pass':all(x['fixed_reference_matches'] and x['integrated_bytes_equal'] for x in reference_checks)}))
 if not all(result['closeout_checks'].values()):raise SystemExit(1)

if __name__=='__main__':main()
