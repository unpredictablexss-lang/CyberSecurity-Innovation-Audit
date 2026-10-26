#!/usr/bin/env python3
"""Recompute C2 dependency object identities and raw diffs from the local Ark Runtime Git DB."""
from __future__ import annotations
import hashlib, json, re, subprocess
from pathlib import Path
HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
COMPONENT = Path('/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime')
C3 = PROJECT / 'research/experiments/ark_runtime/c3_20261018'
COMPARISON = C3 / 'model_dependency_comparison.json'
SOURCE_REVIEW = C3 / 'source_drift_review.json'
DETAILS = PROJECT.parent / 'CyberSecurity-Innovation-Audit-c3-review/research/experiments/ark_runtime/c3_20261018/dependency-review-20261018.md'
C1_EVIDENCE = PROJECT / 'research/experiments/ark_runtime/c1_20261017/source_evidence.json'
C1_RECHECK = PROJECT / 'research/experiments/ark_runtime/c1_20261017/profile_recheck_20261018.md'
C1_PROFILE = PROJECT / 'research/experiments/ark_runtime/c1_20261017/product_profile_20261019.v1.json'
C1_ARGS = PROJECT / 'research/experiments/ark_runtime/c1_20261017/product_args_20261019.args.gn'
C1_PREPROCESSOR = PROJECT / 'research/experiments/ark_runtime/c1_20261017/preprocessor_success_20261019/results/preprocessor_observation.json'
C1_SUCCESS = PROJECT / 'research/experiments/ark_runtime/c1_20261017/preprocessor_success_20261019'
C4_DIR = PROJECT / 'research/experiments/ark_runtime/c4_20261018'
C4_ACTIVE_CLOSURE = C4_DIR / 'active_include_closure_20261019.bound.json'
C4_GENERATED_CLOSURE = C4_DIR / 'generated_input_graph_closure_20261019.json'
C2_ACTION_CENSUS = HERE / 'new_profile_product_action_census_20261019.json'
C2_ACTION_CENSUS_CAPTURE = HERE / 'capture_new_profile_product_action_census.py'
C2_HISTORICAL_PROFILE_AUDIT = HERE / 'historical_profile_candidate_audit_20261019.json'
C2_HISTORICAL_PROFILE_AUDIT_SCRIPT = HERE / 'audit_old_revision_manifest_candidates.py'
C2_FULL_MANIFEST_HISTORY = HERE / 'full_manifest_history_audit_20261019.json'
C2_FULL_MANIFEST_HISTORY_SCRIPT = HERE / 'audit_full_manifest_history.py'
C2_ALL_OLD_ARK_PINS = HERE / 'all_old_ark_manifest_pins_20261019.json'
C2_ALL_OLD_ARK_PINS_SCRIPT = HERE / 'audit_all_old_ark_manifest_pins_20261019.py'
C1_SNAPSHOT_AUDIT = PROJECT / 'research/experiments/ark_runtime/c1_20261017/snapshot_gitlink_linkfile_audit_20261019.json'
C1_SNAPSHOT_AUDIT_SCRIPT = PROJECT / 'research/experiments/ark_runtime/c1_20261017/audit_snapshot_gitlink_linkfile_20261019.py'
C1_GITLINK_ORIGINS = PROJECT / 'research/experiments/ark_runtime/c1_20261017/nested_gitlink_origins_20261019.json'
C1_GITLINK_ORIGINS_SCRIPT = PROJECT / 'research/experiments/ark_runtime/c1_20261017/audit_nested_gitlink_origins_20261019.py'
C2_FULL_MANIFEST_SUPPORT = [HERE / name for name in ['manifest_advertised_refs_full_20261019.txt','manifest_commit_graph_full_20261019.txt','manifest_local_refs_full_20261019.txt','manifest_mirror_fsck_20261019.log','manifest_old_ark_pin_history_matches_20261019.txt']]
C1_NINJA_QUERY = PROJECT / 'research/experiments/ark_runtime/c1_20261017/preprocessor_attempt_20261019/ninja_query.log'
C1_HB_LOG = PROJECT / 'research/experiments/ark_runtime/c1_20261017/hb_probe_20261019_replay2.log'
OUT = HERE / 'object_verification.json'
PATCH = HERE / 'source-diffs.patch'
EXCEPTION_OLD = {18:'c758818dbfd0b146a908d43d21f6ca1706c33783', 19:'81ca57487d04ea30cd11c271e86494a4e130f43e'}
def git(*args: str) -> bytes:
    return subprocess.run(['git','-C',str(COMPONENT),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
def git_text(*args: str) -> str: return git(*args).decode('utf-8').strip()
def sha_file(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()
def compress(values: set[int]) -> list[list[int]]:
    ordered=sorted(values)
    if not ordered: return []
    out=[]; start=prior=ordered[0]
    for value in ordered[1:]:
        if value==prior+1: prior=value; continue
        out.append([start,prior]); start=prior=value
    out.append([start,prior])
    return out
def load_profile_context(action_number: int, paths: list[str]) -> dict[str,dict]:
    result={p:{'dependency_list_contains':False,'preprocessed_file_markers':0,
               'active_source_lines':set(),'preprocessed_output_lines':set()} for p in paths}
    dep=(C1_SUCCESS/'results'/f'ark-runtime-arm-action-{action_number}.d').read_text(encoding='utf-8')
    dep=dep.replace('\\\n',' ')
    for path in paths:
        result[path]['dependency_list_contains']=f'arkcompiler/ets_runtime/{path}' in dep
    marker=re.compile(r'^#\s+(\d+)\s+"([^"]+)"')
    current=None; source_line=0
    ii=C1_SUCCESS/'results'/f'ark-runtime-arm-action-{action_number}.ii'
    with ii.open(encoding='utf-8',errors='replace') as stream:
        for output_line,line in enumerate(stream,1):
            m=marker.match(line)
            if m:
                source_line=int(m.group(1)); marker_path=m.group(2).replace('\\','/')
                current=next((p for p in paths if marker_path.endswith('arkcompiler/ets_runtime/'+p)),None)
                if current is not None: result[current]['preprocessed_file_markers']+=1
                continue
            if current is not None:
                result[current]['active_source_lines'].add(source_line)
                result[current]['preprocessed_output_lines'].add(output_line)
            source_line+=1
    for item in result.values():
        source_lines=item.pop('active_source_lines')
        item['active_source_line_count']=len(source_lines)
        item['active_source_line_ranges']=compress(source_lines)
        item['preprocessed_output_line_ranges']=compress(item.pop('preprocessed_output_lines'))
    return result
def profile_diff_evidence(path: str, patch: bytes, contexts: dict[int,dict]) -> dict:
    hunks=[]; additions=set(); current_new=None
    for line in patch.decode('utf-8',errors='replace').splitlines():
        m=re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@',line)
        if m:
            start=int(m.group(1)); count=int(m.group(2) or 1)
            current_new=start
            if count: hunks.append([start,start+count-1])
            continue
        if current_new is None or line.startswith('\\') or line.startswith('+++') or line.startswith('---'):
            continue
        if line.startswith('+'):
            additions.add(current_new); current_new+=1
        elif line.startswith('-'):
            continue
        elif line.startswith(' '):
            current_new+=1
    out={'new_diff_hunk_ranges':hunks,'actions':{}}
    out['new_added_line_ranges']=compress(additions)
    for action_number,context in contexts.items():
        item=context.get(path,{'dependency_list_contains':False,'preprocessed_file_markers':0,
                               'active_source_line_count':0,'preprocessed_output_line_ranges':[]})
        active=set()
        # Reconstruct active source line numbers from their compressed ranges captured for this action.
        for start,end in item.get('active_source_line_ranges',[]): active.update(range(start,end+1))
        hits=active & additions
        out['actions'][str(action_number)]={**item,
          'changed_new_source_lines_emitted':len(hits),
          'changed_new_source_line_ranges':compress(hits)}
    present=any(x['dependency_list_contains'] or x['preprocessed_file_markers'] for x in out['actions'].values())
    emitted=sum(x['changed_new_source_lines_emitted'] for x in out['actions'].values())
    if present:
        out['minimum_missing_proof']='Preprocess the corresponding old source under a profile-matched build; use the C4-verified new-profile closure and capture the matching old-profile dependency closure; trace changed lines to modeled call/guard/sink and compare old/new IR/CFG or equivalent effect evidence.'
    else:
        out['minimum_missing_proof']='Find this path’s exact product compile action and caller/registration chain in both revisions; prove whether it is in modeled scope; capture the old-profile dependency closure and compare old/new profile-matched semantic/IR evidence.'
    out['changed_line_presence_interprets_as']='source-line activation only; it does not prove modeled reachability, changed semantics, or unaffected status'
    out['new_added_lines_emitted_total']=emitted
    return out
def main() -> None:
    cmp=json.loads(COMPARISON.read_text(encoding='utf-8'))
    review=json.loads(SOURCE_REVIEW.read_text(encoding='utf-8'))
    c1=json.loads(C1_EVIDENCE.read_text(encoding='utf-8'))
    profile=json.loads(C1_PROFILE.read_text(encoding='utf-8'))
    preprocessor=json.loads(C1_PREPROCESSOR.read_text(encoding='utf-8'))
    c4_active=json.loads(C4_ACTIVE_CLOSURE.read_text(encoding='utf-8'))
    c4_generated=json.loads(C4_GENERATED_CLOSURE.read_text(encoding='utf-8'))
    c4_generated_ref=c4_active['producer_graph']['recursive_input_closure']
    assert c4_active['status']=='verified_active_generated_input_closure'
    assert c4_generated['status']=='verified_declared_generated_input_graph_closure'
    assert c4_generated_ref['sha256']==sha_file(C4_GENERATED_CLOSURE)
    assert c4_generated['terminal_input_origin_status_counts']=={'verified_pinned_git_blob':1828}
    assert cmp['dependency_count']==19 and cmp['changed_count']==18
    assert review['dependency_rows']==19 and review['changed_rows']==18
    assert all(a[o]['returncode']==0 for a in preprocessor['actions'] for o in ['preprocess','dependency_scan','macro_dump'])
    for action in preprocessor['actions']:
        assert action['command_sha256'] in {'c6d7959215306a67152ac3c2bf1f5012ba919107e27380691c0f9c32e6a6fa88',
                                            '7471f97a0bfab59e0e350be060391af4f17511aa4c019a861822f5154750e82a'}
        for operation in ['preprocess','dependency_scan','macro_dump']:
            output=C1_SUCCESS/'results'/Path(action[operation]['output_path']).name
            assert sha_file(output)==action[operation]['output_sha256']
    new_commit=cmp['commit']; new_tree=git_text('rev-parse',f'{new_commit}^{{tree}}')
    assert new_tree==review['new_tree']
    component_head=git_text('rev-parse','HEAD'); component_tree=git_text('rev-parse','HEAD^{tree}')
    status=git_text('status','--porcelain=v1')
    rows=[]; patch_parts=[]; patch_by_index={}
    for i,dep in enumerate(cmp['dependencies'],1):
        old_commit=EXCEPTION_OLD.get(i,c1['target']['fixed_commit']); path=dep['path']
        old_tree=git_text('rev-parse',f'{old_commit}^{{tree}}')
        old_blob=git_text('rev-parse',f'{old_commit}:{path}'); new_blob=git_text('rev-parse',f'{new_commit}:{path}')
        assert old_blob==dep['expected_blob'] and new_blob==dep['current_blob']
        old_raw=git('cat-file','blob',old_blob); new_raw=git('cat-file','blob',new_blob)
        old_sha=hashlib.sha256(old_raw).hexdigest(); new_sha=hashlib.sha256(new_raw).hexdigest()
        expected=review['entries'][i-1]
        assert old_sha==expected['old_sha256'] and new_sha==expected['new_sha256']
        assert len(old_raw)==expected['bytes_old'] and len(new_raw)==expected['bytes_new']
        patch=git('diff','--no-ext-diff','--no-textconv','--no-renames','--no-color','--no-indent-heuristic','--full-index','--function-context',old_commit,new_commit,'--',path)
        patch_by_index[i]=patch
        patch_header=f'# dependency {i}: {old_commit}:{path} -> {new_commit}:{path}\n'.encode()
        patch_parts.append(patch_header+patch)
        rows.append({'index':i,'kind':dep['kind'],'path':path,
          'old':{'commit':old_commit,'tree':old_tree,'path':path,'blob_oid':old_blob,'source_sha256':old_sha,'bytes':len(old_raw)},
          'new':{'commit':new_commit,'tree':new_tree,'path':path,'blob_oid':new_blob,'source_sha256':new_sha,'bytes':len(new_raw)},
          'diff':{'command':'git diff --no-ext-diff --no-textconv --no-renames --no-color --no-indent-heuristic --full-index --function-context OLD NEW -- PATH','sha256':hashlib.sha256(patch).hexdigest(),'utf8_bytes':len(patch),'artifact':'source-diffs.patch'},
          'source_identity_changed':old_blob!=new_blob,'semantic_status':'unknown' if old_blob!=new_blob else 'unchanged-source-control-only'})
    changed=[r for r in rows if r['source_identity_changed']]
    assert len(changed)==18 and len(rows)-len(changed)==1
    PATCH.write_bytes(b'\n'.join(patch_parts))
    changed_paths=[r['path'] for r in changed]
    contexts={i:load_profile_context(i,changed_paths) for i in (1,2)}
    for row in changed:
        row['profile_context']=profile_diff_evidence(row['path'],patch_by_index[row['index']],contexts)
    matrix_path=HERE/'triage_matrix.json'
    matrix=json.loads(matrix_path.read_text(encoding='utf-8'))
    action_census=json.loads(C2_ACTION_CENSUS.read_text(encoding='utf-8'))
    historical_profile_audit=json.loads(C2_HISTORICAL_PROFILE_AUDIT.read_text(encoding='utf-8'))
    census_rows={item['path']:item for item in action_census['source_rows']}
    matrix_rows={x['index']:x for x in matrix['dependencies']}
    for row in changed:
        matrix_rows[row['index']]['exact_profile_context']=row['profile_context']
        matrix_rows[row['index']]['semantic_status']='unknown'
        matrix_rows[row['index']]['profile_status']='new_profile_context_captured_old_profile_missing'
        census_row=census_rows.get(row['path'])
        if row['path'].endswith('.cpp') and census_row is not None:
            binding={k:census_row[k] for k in ('new_profile_source_action_count','action_binding_status')}
            binding['census_artifact']='new_profile_product_action_census_20261019.json'
            matrix_rows[row['index']]['new_profile_product_actions']=binding
            if census_row['new_profile_source_action_count']:
                matrix_rows[row['index']]['profile_status']='new_profile_product_action_captured_old_revision_profile_missing'
        elif row['path'].endswith('.h'):
            matrix_rows[row['index']]['new_profile_product_actions']={
                'action_binding_status':'header_context_observed_in_selected_target_TUs',
                'census_artifact':'new_profile_product_action_census_20261019.json',
                'note':'Headers are not compile database source entries; active include and added-line context is recorded in exact_profile_context.'}
        request=matrix_rows[row['index']].get('minimum_evidence_request','')
        request=re.sub(
            r'(?:old-profile\s+)*include closure(?:\s*\((?:the )?selected new-profile closure is (?:now )?bound in C4\))*',
            'old-profile include closure (selected new-profile closure is bound in C4)',
            request,
        )
        matrix_rows[row['index']]['minimum_evidence_request']=request
    profile_run=profile['runs'][0]
    profile_actions=[{'object_output':a['object_output'],'command_sha256':a['command_sha256'],
                      'preprocess':{k:a['preprocess'][k] for k in ['returncode','output_sha256','output_bytes']},
                      'dependency_scan':{k:a['dependency_scan'][k] for k in ['returncode','output_sha256','output_bytes']},
                      'macro_dump':{k:a['macro_dump'][k] for k in ['returncode','output_sha256','output_bytes']},
                      'stderr_sha256':a['preprocess']['stderr_sha256']}
                     for a in preprocessor['actions']]
    generated_header_paths=[
      'generated/arkcompiler/runtime_core/libpandabase/include/logger_enum_gen.h',
      'generated/arkcompiler/runtime_core/libpandafile/type.h',
      'generated/arkcompiler/runtime_core/libpandafile/include/file_format_version.h',
      'generated/arkcompiler/runtime_core/libpandafile/include/source_lang_enum.h',
      'generated/arkcompiler/runtime_core/libpandafile/include/bytecode_instruction_enum_gen.h',
      'generated/arkcompiler/runtime_core/libpandafile/include/bytecode_instruction-inl_gen.h']
    generated_headers={p:{'sha256':sha_file(C1_SUCCESS/p),'bytes':(C1_SUCCESS/p).stat().st_size} for p in generated_header_paths}
    census_counts={item['path']:item['new_profile_source_action_count'] for item in action_census['source_rows']}
    census_summary={'artifact':str(C2_ACTION_CENSUS.relative_to(PROJECT)).replace('\\','/'),
      'sha256':sha_file(C2_ACTION_CENSUS),'schema':action_census['schema'],
      'capture_script':str(C2_ACTION_CENSUS_CAPTURE.relative_to(PROJECT)).replace('\\','/'),
      'capture_script_sha256':sha_file(C2_ACTION_CENSUS_CAPTURE),
      'compile_database_sha256':action_census['compile_database_identity']['sha256'],
      'compile_database_bytes':action_census['compile_database_identity']['bytes'],
      'source_entry_count':action_census['compile_database_identity']['observed_source_entry_count'],
      'changed_cpp_path_count':len(action_census['source_rows']),
      'paths_with_product_actions':sum(1 for count in census_counts.values() if count),
      'total_product_actions':sum(census_counts.values()),'per_path_action_counts':census_counts,
      'semantic_limit':action_census['semantic_limit']}
    old_profile_summary={'artifact':str(C2_HISTORICAL_PROFILE_AUDIT.relative_to(PROJECT)).replace('\\','/'),
      'sha256':sha_file(C2_HISTORICAL_PROFILE_AUDIT),'capture_script':str(C2_HISTORICAL_PROFILE_AUDIT_SCRIPT.relative_to(PROJECT)).replace('\\','/'),
      'capture_script_sha256':sha_file(C2_HISTORICAL_PROFILE_AUDIT_SCRIPT),
      'bounded_refs_checked':sum(1 for item in historical_profile_audit['inspected_refs'] if item.get('status')!='not_materialized_locally'),
      'exact_old_commit_pin_refs':[item['ref'] for item in historical_profile_audit['inspected_refs'] if item.get('exact_old_commit_pinned')],
      'v5_0_3_ark_pin':historical_profile_audit['inspected_refs'][1].get('nearest_release_snapshot',{}).get('pins',{}).get('arkcompiler_ets_runtime'),
      'v5_0_3_old_commit_is_ancestor':historical_profile_audit['inspected_refs'][1].get('nearest_release_snapshot',{}).get('old_commit_is_ancestor_of_candidate'),
      'conclusion':historical_profile_audit['conclusion']}
    full_history=json.loads(C2_FULL_MANIFEST_HISTORY.read_text(encoding='utf-8'))
    full_history_summary={'artifact':str(C2_FULL_MANIFEST_HISTORY.relative_to(PROJECT)).replace('\\','/'),'sha256':sha_file(C2_FULL_MANIFEST_HISTORY),'capture_script':str(C2_FULL_MANIFEST_HISTORY_SCRIPT.relative_to(PROJECT)).replace('\\','/'),'capture_script_sha256':sha_file(C2_FULL_MANIFEST_HISTORY_SCRIPT),'status':full_history['status'],'remote':full_history['remote'],'captured_at_utc':full_history['captured_at_utc'],'advertised_refs':full_history['mirror']['advertised_ref_count'],'local_refs':full_history['mirror']['local_ref_count'],'reachable_commits':full_history['mirror']['reachable_commit_count'],'history_matches':full_history['historical_exact_pin_search']['match_count'],'scope_limit':'All refs advertised by the recorded GitCode remote at capture time and their reachable history; third-party and unadvertised/unreachable refs are outside scope.'}
    all_old_pins=json.loads(C2_ALL_OLD_ARK_PINS.read_text(encoding='utf-8'))
    expected_old_commits=sorted({row['old']['commit'] for row in matrix['dependencies']})
    if all_old_pins.get('old_ark_commits')!=expected_old_commits or all_old_pins.get('status')!='complete_no_exact_pins_found':
      raise SystemExit('all-old-Ark-pin audit does not cover the matrix commits or is incomplete')
    all_old_pins_summary={'artifact':str(C2_ALL_OLD_ARK_PINS.relative_to(PROJECT)).replace('\\','/'),'sha256':sha_file(C2_ALL_OLD_ARK_PINS),'capture_script':str(C2_ALL_OLD_ARK_PINS_SCRIPT.relative_to(PROJECT)).replace('\\','/'),'capture_script_sha256':sha_file(C2_ALL_OLD_ARK_PINS_SCRIPT),'status':all_old_pins['status'],'old_commit_count':all_old_pins['old_commit_count'],'match_counts':{commit:item['match_count'] for commit,item in all_old_pins['searches'].items()},'reachable_commits':all_old_pins['mirror']['reachable_commit_count'],'scope_limit':all_old_pins['excluded_scope']}
    snapshot_audit=json.loads(C1_SNAPSHOT_AUDIT.read_text(encoding='utf-8'))
    gitlink_origins=json.loads(C1_GITLINK_ORIGINS.read_text(encoding='utf-8'))
    ninja_logs={p.name:sha_file(p) for p in sorted((C1_SUCCESS/'ninja').glob('*.log'))}
    result={'schema':'c2-ark-runtime-drift-object-verification-v1','target_repository':cmp['repository'],
      'target_commit':new_commit,'target_tree':new_tree,'component_checkout_head_observed':component_head,
      'component_checkout_tree_observed':component_tree,'component_worktree_porcelain':status or 'clean',
      'counts':{'dependencies':19,'changed':18,'unchanged':1,'changed_semantic_status_unknown':18},
      'profile_context_artifacts':{'action_1_dependency_sha256':sha_file(C1_SUCCESS/'results/ark-runtime-arm-action-1.d'),
        'action_2_dependency_sha256':sha_file(C1_SUCCESS/'results/ark-runtime-arm-action-2.d'),
        'action_1_preprocessed_sha256':sha_file(C1_SUCCESS/'results/ark-runtime-arm-action-1.ii'),
        'action_2_preprocessed_sha256':sha_file(C1_SUCCESS/'results/ark-runtime-arm-action-2.ii'),
        'note':'Per-row path and changed-line presence is derived from exact new-revision dependency lists, preprocessed line markers, and the recorded old/new Git diff. Presence is not semantic reachability proof.'},
      'new_profile_product_action_census':census_summary,
      'old_revision_manifest_candidate_audit':old_profile_summary,
      'full_manifest_history_audit':full_history_summary,
      'all_old_ark_manifest_pin_audit':all_old_pins_summary,
      'snapshot_materialization_audit':{'artifact':str(C1_SNAPSHOT_AUDIT.relative_to(PROJECT)).replace('\\','/'),'sha256':sha_file(C1_SNAPSHOT_AUDIT),'status':snapshot_audit['status'],'manifest_projects':snapshot_audit['materialization_manifest']['project_count'],'nested_gitlinks':snapshot_audit['gitlinks']['declared_count'],'nested_gitlink_contents_not_materialized':snapshot_audit['gitlinks']['archive_commit_content_not_materialized_count'],'linkfiles':snapshot_audit['linkfiles']['declared_count'],'missing_exact_linkfile_sources':snapshot_audit['linkfiles']['missing_exact_sources'],'origins_artifact_sha256':sha_file(C1_GITLINK_ORIGINS),'gitlinks_with_declared_origin':gitlink_origins['gitlinks_with_declared_origin'],'gitlinks_without_declared_origin':gitlink_origins['gitlinks_without_declared_origin']},
      'profile':{'status':'new_profile_active_closure_verified_old_revision_profile_missing','product':profile['product'],
        'artifact':str(C1_PROFILE.relative_to(PROJECT)).replace('\\','/'),
        'artifact_sha256':sha_file(C1_PROFILE),'profile_digest_sha256':profile['profile_digest_sha256'],
        'normalized_args_sha256':profile_run['args_gn_normalized_sha256'],
        'compile_database_sha256':profile_run['compile_commands_sha256'],
        'compile_database_commands':234245,'build_ninja_sha256':profile_run['build_ninja_sha256'],
        'source_materialization_status':profile['snapshot']['materialization_status'],
        'target_arm_actions':profile_actions,
        'preprocessor_success_observation_sha256':sha_file(C1_PREPROCESSOR),
        'c4_active_include_closure':{'path':str(C4_ACTIVE_CLOSURE.relative_to(PROJECT)).replace('\\','/'),
          'sha256':sha_file(C4_ACTIVE_CLOSURE),'status':c4_active['status'],
          'unique_dependencies':c4_active['unique_dependency_count']},
        'c4_generated_input_graph_closure':{'path':str(C4_GENERATED_CLOSURE.relative_to(PROJECT)).replace('\\','/'),
          'sha256':sha_file(C4_GENERATED_CLOSURE),'status':c4_generated['status'],
          'producer_outputs':c4_generated['recursive_producer_output_count'],
          'pinned_source_inputs':c4_generated['terminal_input_origin_status_counts']},
        'captured_generated_headers':generated_headers,
        'musl_features_header':{'path':'obj/third_party/musl/usr/include/arm-linux-ohos/features.h',
          'present_in_both_dependency_scans_and_preprocessed_TUs':True,
          'content_hash_bound_in_c2':True,'verified_in_c4_active_closure':True},
        'ninja_target_logs_sha256':ninja_logs,
        'preprocessor_observation_sha256':sha_file(C1_PREPROCESSOR),
        'ninja_query_log_sha256':sha_file(C1_NINJA_QUERY),
        'blockers':['The generated build graph reports duplicate-output warnings and the full Ninja graph query remains blocked at Contacts_DataAbility.stamp; full product build is not established.',
          'The source archive omits 19 nested gitlink commit trees; only 16 of the 19 have a parent .gitmodules URL. The exact vendor/ohemu/common/qemu-run linkfile source is missing.',
          'A full-history audit of all 10,315 refs advertised by the recorded GitCode manifest remote found no exact old Ark commit pin in 10,420 reachable commits; third-party and unadvertised/unreachable refs remain outside scope. The nearest HiHope v5.0.3 snapshot pins a different, non-descendant Ark commit; no matching old product profile is established. The new-revision compile database lists source actions but does not prove action execution or old/new semantic IR/CFG equivalence.']},
      'input_artifacts':{p.name:sha_file(p) for p in [COMPARISON,SOURCE_REVIEW,DETAILS,C1_EVIDENCE,C1_RECHECK,C1_PROFILE,C1_ARGS,C1_PREPROCESSOR,C1_NINJA_QUERY,C1_HB_LOG,C1_PREPROCESSOR,C1_SNAPSHOT_AUDIT,C1_SNAPSHOT_AUDIT_SCRIPT,C1_GITLINK_ORIGINS,C1_GITLINK_ORIGINS_SCRIPT,C4_ACTIVE_CLOSURE,C4_GENERATED_CLOSURE,C2_ACTION_CENSUS,C2_ACTION_CENSUS_CAPTURE,C2_HISTORICAL_PROFILE_AUDIT,C2_HISTORICAL_PROFILE_AUDIT_SCRIPT,C2_FULL_MANIFEST_HISTORY,C2_FULL_MANIFEST_HISTORY_SCRIPT,C2_ALL_OLD_ARK_PINS,C2_ALL_OLD_ARK_PINS_SCRIPT,*C2_FULL_MANIFEST_SUPPORT,HERE/'verify_c2_evidence.py',*[C1_SUCCESS/'results'/n for n in ['ark-runtime-arm-action-1.ii','ark-runtime-arm-action-1.d','ark-runtime-arm-action-1.macros','ark-runtime-arm-action-2.ii','ark-runtime-arm-action-2.d','ark-runtime-arm-action-2.macros']],*[C1_SUCCESS/p for p in generated_header_paths],*sorted((C1_SUCCESS/'ninja').glob('*.log'))]},
      'diff_artifact':{'path':PATCH.name,'sha256':sha_file(PATCH),'bytes':PATCH.stat().st_size},
      'dependencies':rows,'reproduction':{'command':'python3 verify_c2_evidence.py','git_database':str(COMPONENT)+'/ .git object store','note':'Run from the same checkout under Kali WSL; reads only pinned objects.'}}
    OUT.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    matrix['effective_profile_status']='new_profile_active_include_and_generated_input_closure_verified_old_revision_profile_missing'
    matrix['semantic_gate_passed']=False
    matrix['classification_policy']['semantic_status']='all 18 changed dependencies remain unknown; new-profile line activation and active dependency content are bound, but profile-matched old-revision comparison and modeled call/guard/sink proof remain incomplete'
    matrix['profile_evidence']['row_context_source']='object_verification.json dependencies[].profile_context and exact_profile_context'
    matrix['full_manifest_history_audit']={'artifact':str(C2_FULL_MANIFEST_HISTORY.relative_to(PROJECT)).replace('\\','/'),'sha256':sha_file(C2_FULL_MANIFEST_HISTORY),'capture_script':str(C2_FULL_MANIFEST_HISTORY_SCRIPT.relative_to(PROJECT)).replace('\\','/'),'capture_script_sha256':sha_file(C2_FULL_MANIFEST_HISTORY_SCRIPT),**{k:full_history_summary[k] for k in ['status','captured_at_utc','advertised_refs','local_refs','reachable_commits','history_matches','scope_limit']}}
    matrix['all_old_ark_manifest_pin_audit']=all_old_pins_summary
    matrix['source_materialization_audit']=result['snapshot_materialization_audit']
    matrix['profile_evidence']['status']='new_profile_active_include_and_generated_input_closure_verified_old_revision_profile_missing'
    matrix['profile_evidence']['blockers']=[
      'The generated build graph reports duplicate-output warnings and the full Ninja graph query remains blocked at Contacts_DataAbility.stamp; a full product build is not established.',
      'The source archive omits 19 nested gitlink commit trees; only 16 of the 19 have a parent .gitmodules URL. The exact vendor/ohemu/common/qemu-run linkfile source is missing.',
      'A full-history audit of all refs advertised by the recorded GitCode manifest remote found no exact old Ark commit pin in 10,420 reachable commits; third-party and unadvertised/unreachable refs remain outside scope. The nearest HiHope v5.0.3 snapshot pins a different, non-descendant Ark commit, so a matching old product profile remains unavailable.'
    ]
    matrix['profile_evidence']['c4_active_include_closure']={
      'path':str(C4_ACTIVE_CLOSURE.relative_to(PROJECT)).replace('\\','/'),
      'sha256':sha_file(C4_ACTIVE_CLOSURE),'status':c4_active['status'],
      'unique_dependencies':c4_active['unique_dependency_count']}
    matrix['profile_evidence']['c4_generated_input_graph_closure']={
      'path':str(C4_GENERATED_CLOSURE.relative_to(PROJECT)).replace('\\','/'),
      'sha256':sha_file(C4_GENERATED_CLOSURE),'status':c4_generated['status'],
      'producer_outputs':c4_generated['recursive_producer_output_count'],
      'pinned_source_inputs':c4_generated['terminal_input_origin_status_counts']}
    matrix['profile_evidence']['new_profile_product_action_census']=census_summary
    matrix['profile_evidence']['old_revision_manifest_candidate_audit']=old_profile_summary
    matrix_path.write_text(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'output':str(OUT),'head':component_head,'tree':component_tree,'worktree':status or 'clean','dependencies':19,'changed':18,'unknown':18,'patch_sha256':result['diff_artifact']['sha256']},ensure_ascii=False,indent=2))
if __name__=='__main__': main()


