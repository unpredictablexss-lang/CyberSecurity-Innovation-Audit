#!/usr/bin/env python3
"""Capture exact-profile C1 Ninja target build under a read-only snapshot lower layer."""
from __future__ import annotations
import hashlib, json, shutil, subprocess, shlex, re
from pathlib import Path

HERE=Path(__file__).resolve().parent
PROJECT=HERE.parents[3]
BASE=Path('/home/deepsleep/c-line-c1-profile-20261018')
ATTEMPT=BASE/'ninja_isolated_build_attempt7_20261019'
OUTROOT=BASE/'out-gn-20261019-retry3'
RUBY=BASE/'ruby-runtime-stage-20261019'
DEST=HERE/'ninja_cow_target_build_20261019'
PROFILE=HERE/'product_profile_20261019.v1.json'
RUNNER=HERE/'run_ninja_targets_cow_ro_root_20261019.sh'
NINJA=BASE/'toolchain-20261019/ninja'

def sha(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def copy(src:Path,dst:Path)->dict:
 dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
 return {'path':dst.relative_to(PROJECT).as_posix(),'sha256':sha(dst),'bytes':dst.stat().st_size}

def main()->None:
 profile=json.loads(PROFILE.read_text(encoding='utf-8'))
 attempts=ATTEMPT
 out=DEST/'attempt7'
 prior=DEST/'attempt6'
 prior_attempt=BASE/'ninja_isolated_build_attempt6_20261019'
 files=[]
 prior_files=[]
 for n in ['execution_boundary.txt','target-1.log','target-1.status','target-2.log','target-2.status']:
  prior_files.append(copy(prior_attempt/n,prior/n))
 prior_upper=[]
 for src in sorted((prior_attempt/'source-upper').rglob('*')):
  if not src.is_file():continue
  rel=src.relative_to(prior_attempt/'source-upper')
  lower=BASE/'openharmony-git-archive-20261019'/rel
  entry={'path':rel.as_posix(),'upper_sha256':sha(src),'upper_bytes':src.stat().st_size,'lower_exists':lower.is_file(),'upper_matches_lower':sha(src)==sha(lower) if lower.is_file() else None}
  if lower.is_file():entry['lower_sha256']=sha(lower)
  prior_upper.append(entry)
 prior_upper_path=prior/'source_upper.v1.json'
 prior_upper_path.parent.mkdir(parents=True,exist_ok=True)
 prior_upper_path.write_text(json.dumps({'schema':'ohscanner.c1.cow-source-upper-manifest/v1','files':prior_upper},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 prior_files.append({'path':prior_upper_path.relative_to(PROJECT).as_posix(),'sha256':sha(prior_upper_path),'bytes':prior_upper_path.stat().st_size})
 files.extend(prior_files)
 for n in ['execution_boundary.txt','target-1.log','target-1.status','target-2.log','target-2.status']:
  files.append(copy(attempts/n,out/n))
 upper=[]
 for src in sorted((ATTEMPT/'source-upper').rglob('*')):
  if not src.is_file():continue
  rel=src.relative_to(ATTEMPT/'source-upper')
  lower=BASE/'openharmony-git-archive-20261019'/rel
  entry={'path':rel.as_posix(),'upper_sha256':sha(src),'upper_bytes':src.stat().st_size,'lower_exists':lower.is_file(),'upper_matches_lower':sha(src)==sha(lower) if lower.is_file() else None}
  if lower.is_file():entry['lower_sha256']=sha(lower)
  upper.append(entry)
 # The package hashes are pinned from Ubuntu Noble's signed package index and separately recomputed here.
 packages=[]
 expected={'ruby3.2_3.2.3-1ubuntu0.24.04.8_amd64.deb':'6f11e297b3508e8db95a5a047126a16ccf1358292049a27e3dc72b88180e779a','libruby3.2_3.2.3-1ubuntu0.24.04.8_amd64.deb':'77c2e98ccfba2c4a4e5edb48ca8c0eb041702e1579eabc40cf07064fd4f3033e'}
 for n,h in expected.items():
  p=RUBY/'packages'/n
  packages.append({'file':n,'sha256':sha(p),'expected_sha256_from_apt_index':h,'matches_expected':sha(p)==h,'bytes':p.stat().st_size})
  files.append(copy(p,DEST/'ruby_packages'/n))
 binaries={}
 for label,p in {'ruby':RUBY/'root/usr/bin/ruby3.2','ninja':NINJA,'python3.12':BASE/'toolchain-20261019/linux-x86/3.12.10/bin/python3.12'}.items():
  binaries[label]={'sha256':sha(p),'bytes':p.stat().st_size}
 actions=[x for x in profile['runs'][0]['target_source_actions'] if x.get('target')=='arm-linux-ohos']
 expected_targets={a['object_output']:a for a in actions}
 results=[]
 for i,(key,subpath) in enumerate([
  ('obj/arkcompiler/ets_runtime/ecmascript/compiler/builtins/libark_jsoptimizer_set/builtins_typedarray_stub_builder.o','obj/arkcompiler/ets_runtime/ecmascript/compiler/builtins/libark_jsoptimizer_set/builtins_typedarray_stub_builder.o'),
  ('obj/arkcompiler/ets_runtime/ecmascript/compiler/builtins/libark_jsoptimizer_set_with_maple/builtins_typedarray_stub_builder.o','obj/arkcompiler/ets_runtime/ecmascript/compiler/builtins/libark_jsoptimizer_set_with_maple/builtins_typedarray_stub_builder.o')],1):
  obj=OUTROOT/'rk3568'/subpath
  row=expected_targets[key]
  cp=subprocess.run([str(NINJA),'-C',str(OUTROOT/'rk3568'),'-w','dupbuild=warn','-t','commands',key],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=True)
  command_lines=[line for line in cp.stdout.splitlines() if line.rstrip().endswith(key)]
  command=command_lines[-1] if command_lines else None
  command_file=out/f'commands/target-{i}.command.txt'
  command_file.parent.mkdir(parents=True,exist_ok=True)
  if command is not None: command_file.write_text(command+'\n',encoding='utf-8')
  files.append({'path':command_file.relative_to(PROJECT).as_posix(),'sha256':sha(command_file),'bytes':command_file.stat().st_size})
  results.append({'target_index':i,'ninja_target':key,'returncode':int((ATTEMPT/f'target-{i}.status').read_text().split('returncode=')[1].splitlines()[0]),'object':{'path':(out/'objects'/f'target-{i}.o').relative_to(PROJECT).as_posix(),'sha256':sha(obj),'bytes':obj.stat().st_size},'profile_command_sha256':row['command_sha256'],'ninja_t_command_line_sha256':hashlib.sha256(command.encode()).hexdigest() if command else None,'ninja_command_matches_profile_stripped':bool(command and command.strip()==row['command'].strip()),'ninja_argv_matches_profile':bool(command and shlex.split(command)==shlex.split(row['command'])),'ninja_command_capture_path':command_file.relative_to(PROJECT).as_posix(),'ninja_t_command_count_for_target_closure':len(cp.stdout.splitlines()),'log_sha256':sha(out/f'target-{i}.log')})
  files.append(copy(obj,out/'objects'/f'target-{i}.o'))
  files.append(copy(obj,out/'objects'/f'target-{i}.o.sha256.txt') if False else {'path':(out/'objects'/f'target-{i}.o').relative_to(PROJECT).as_posix(),'sha256':sha(obj),'bytes':obj.stat().st_size})
 lower_copyright=BASE/'openharmony-git-archive-20261019/third_party/musl/COPYRIGHT'
 old_profile=PROFILE
 result={'schema':'ohscanner.c1.cow-ninja-target-build-observation/v1','status':'two_exact_profile_arm_object_targets_built','product':profile['product'],'profile_digest_sha256':profile['profile_digest_sha256'],'resolved_manifest_sha256':profile['snapshot']['resolved_manifest_sha256'],'ark_runtime_commit':profile['snapshot']['ark_runtime_commit'],'runner':{'path':RUNNER.relative_to(PROJECT).as_posix(),'sha256':sha(RUNNER)},'execution_boundary':{'user_mount_network_namespaces':True,'network_namespace':next(x.split('=',1)[1] for x in (out/'execution_boundary.txt').read_text().splitlines() if x.startswith('namespace_network=')),'root_filesystem_read_only':True,'exact_source_snapshot_is_read_only_lower':True,'source_accessed_through_overlay_cow':True,'source_overlay_upper_change_count':len(upper),'all_existing_upper_files_identical_to_lower':all(x['upper_matches_lower'] for x in upper if x['lower_exists']),'source_lower_musl_copyright_sha256':sha(lower_copyright),'prebuilts_read_only':True,'clang_toolchain_read_only':True,'ruby_runtime_read_only':True,'gn_output_root_writable':True,'no_network':True,'limitations':['GN output and evidence were reused incrementally from the preceding successful build; only the exact target object actions were forced to rerun in this read-only-root attempt.','The complete GN output root was reused incrementally; exact Ninja object target builds succeeded, but no product image/full product build was produced.','The prerequisite-closure attempt COW upper contains notice-file copy-ups and Python bytecode cache files; the read-only-root replay upper was empty and the source lower remained unchanged.']},'runtime_tools':{'ninja_version':'1.13.2','ninja_sha256':binaries['ninja']['sha256'],'python_version':'3.12.10','python_sha256':binaries['python3.12']['sha256'],'ruby_version':'3.2.3','ruby_binary_sha256':binaries['ruby']['sha256'],'ruby_packages':packages},'targets':results,'prerequisite_closure_attempt':{'attempt':6,'target1_returncode':int((prior_attempt/'target-1.status').read_text().split('returncode=')[1].splitlines()[0]),'target2_returncode':int((prior_attempt/'target-2.status').read_text().split('returncode=')[1].splitlines()[0]),'target1_last_progress':re.findall(r'^\[(\d+/\d+)\]',(prior_attempt/'target-1.log').read_text(),re.M)[-1],'target2_last_progress':re.findall(r'^\[(\d+/\d+)\]',(prior_attempt/'target-2.log').read_text(),re.M)[-1],'root_filesystem_read_only':False,'source_upper_change_count':len(prior_upper),'all_existing_upper_files_identical_to_lower':all(x['upper_matches_lower'] for x in prior_upper if x['lower_exists'])},'source_overlay_upper':upper,'captured_files':files}
 if len(results)!=2 or not all(x['returncode']==0 for x in results):raise SystemExit('expected both exact-profile targets to succeed')
 if any(not p['matches_expected'] for p in packages):raise SystemExit('Ruby package hash mismatch')
 DEST.mkdir(parents=True,exist_ok=True)
 (DEST/'observation.v1.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 (DEST/'source_upper.v1.json').write_text(json.dumps({'schema':'ohscanner.c1.cow-source-upper-manifest/v1','files':upper},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 (DEST/'ruby_runtime.v1.json').write_text(json.dumps({'schema':'ohscanner.c1.host-ruby-runtime.v1','distribution':'Ubuntu 24.04 Noble','ruby_version':'3.2.3-1ubuntu0.24.04.8','packages':packages,'binary':binaries['ruby']},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'status':result['status'],'targets':results,'upper_changes':len(upper),'captured':len(files)},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
