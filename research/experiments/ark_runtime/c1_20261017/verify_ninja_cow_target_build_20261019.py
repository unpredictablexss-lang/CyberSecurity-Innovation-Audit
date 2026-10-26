#!/usr/bin/env python3
"""Read-only verifier for captured C1 exact-profile COW Ninja object builds."""
from __future__ import annotations
import hashlib,json,shlex
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROJECT=HERE.parents[3]
EVIDENCE=HERE/'ninja_cow_target_build_20261019'
PROFILE=HERE/'product_profile_20261019.v1.json'
OBS=EVIDENCE/'observation.v1.json'

def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def main()->int:
 profile=json.loads(PROFILE.read_text(encoding='utf-8'))
 obs=json.loads(OBS.read_text(encoding='utf-8'))
 errors=[]
 if obs.get('status')!='two_exact_profile_arm_object_targets_built':errors.append('status')
 if not obs.get('execution_boundary',{}).get('root_filesystem_read_only'):errors.append('root_not_read_only')
 if obs.get('execution_boundary',{}).get('source_overlay_upper_change_count')!=0:errors.append('read_only_replay_source_upper_not_empty')
 boundary=(EVIDENCE/'attempt7/execution_boundary.txt').read_text(encoding='utf-8')
 for required in ['root_mount=/      ro','root_readonly_probe=write_rejected','source_view_mount=/src   ro','output_root_mount=/src/out rw','ruby_mount=']:
  if required not in boundary:errors.append('boundary_missing:'+required)
 actions={x['object_output']:x for x in profile['runs'][0]['target_source_actions'] if x.get('target')=='arm-linux-ohos'}
 for i,row in enumerate(obs.get('targets',[]),1):
  expected=actions.get(row.get('ninja_target'))
  if expected is None:errors.append(f'target_{i}_not_in_profile');continue
  if row.get('returncode')!=0:errors.append(f'target_{i}_rc')
  if row.get('profile_command_sha256')!=expected.get('command_sha256'):errors.append(f'target_{i}_profile_hash')
  command_path=PROJECT/row['ninja_command_capture_path']
  command=command_path.read_text(encoding='utf-8').rstrip('\n')
  if shlex.split(command)!=shlex.split(expected['command']):errors.append(f'target_{i}_argv_mismatch')
  obj=PROJECT/row['object']['path']
  if sha(obj)!=row['object']['sha256'] or obj.stat().st_size!=row['object']['bytes']:errors.append(f'target_{i}_object_identity')
  log=(EVIDENCE/f'attempt7/target-{i}.log').read_text(encoding='utf-8',errors='replace')
  if f'[1/1] CXX {row["ninja_target"]}' not in log or 'FAILED:' in log:errors.append(f'target_{i}_not_rebuilt')
  status=(EVIDENCE/f'attempt7/target-{i}.status').read_text(encoding='utf-8')
  if 'returncode=0' not in status or row['ninja_target'] not in status:errors.append(f'target_{i}_status_mismatch')
 for f in obs.get('captured_files',[]):
  p=PROJECT/f['path']
  if not p.is_file() or sha(p)!=f['sha256'] or p.stat().st_size!=f['bytes']:errors.append('captured_file_mismatch:'+f['path'])
 packages=obs.get('runtime_tools',{}).get('ruby_packages',[])
 if len(packages)!=2 or not all(p.get('matches_expected') for p in packages):errors.append('ruby_package_hashes')
 prior=obs.get('prerequisite_closure_attempt',{})
 if prior.get('target1_returncode')!=0 or prior.get('target2_returncode')!=0 or prior.get('target1_last_progress')!='136/136' or prior.get('target2_last_progress')!='6/6':errors.append('prerequisite_closure_not_complete')
 if not prior.get('all_existing_upper_files_identical_to_lower'):errors.append('prerequisite_cow_lower_mismatch')
 if errors:
  print(json.dumps({'status':'invalid','errors':errors},indent=2));return 1
 print(json.dumps({'status':'valid','targets':2,'root_read_only_replay':True,'profile_argv_matches':[True,True],'prerequisite_closure_progress':['136/136','6/6'],'c4_bound_objects':[x['object']['sha256'] for x in obs['targets']],'limitations':obs['execution_boundary']['limitations']},ensure_ascii=False,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
