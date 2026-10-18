import json, hashlib, subprocess, pathlib, re
project=pathlib.Path(__file__).resolve().parents[4]
root=project.parent
repo=root/'openharmony/arkcompiler/ets_runtime'
exp=project/'research/experiments/ark_runtime/c3_20261018'
comp=json.loads((exp/'model_dependency_comparison.json').read_text())
old_commit='a0e30483ab3e4aead67ecfb5c708489915e447f9'
new_commit=comp['commit']
def git(*args): return subprocess.check_output(['git','-C',repo,*args])
def show(rev,path): return git('show',f'{rev}:{path}')
rows=[]
for i,d in enumerate(comp['dependencies'],1):
 p=d['path']; item_old_commit=old_commit if i <= 17 else ('c758818dbfd0b146a908d43d21f6ca1706c33783' if i == 18 else '81ca57487d04ea30cd11c271e86494a4e130f43e'); old=show(item_old_commit,p); new=show(new_commit,p)
 oldblob=git('rev-parse',f'{item_old_commit}:{p}').decode().strip(); newblob=git('rev-parse',f'{new_commit}:{p}').decode().strip()
 # raw unified diff, retain all semantic lines but cap display to focused excerpts
 diff=subprocess.run(['git','-C',repo,'diff','--no-ext-diff','--unified=0',f'{item_old_commit}:{p}',f'{new_commit}:{p}'],capture_output=True).stdout.decode('utf-8','replace')
 changed=[x for x in diff.splitlines() if x.startswith(('+','-')) and not x.startswith(('+++','---'))]
 identifiers=sorted({m.group(1) for x in changed for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_:]*)\s*\(', x[1:]) if m.group(1) not in {'if','for','while','switch','sizeof','decltype','static_cast','reinterpret_cast','assert'}})
 hunks=re.findall(r'^@@ .*? @@(.*)$',diff,re.M)
 rows.append(dict(id=f'D{i:02}',kind=d['kind'],path=p,old_commit=item_old_commit,old_tree=git('rev-parse',f'{item_old_commit}^{{tree}}').decode().strip(),old_blob=oldblob,old_sha256=hashlib.sha256(old).hexdigest(),new_commit=new_commit,new_tree=git('rev-parse',f'{new_commit}^{{tree}}').decode().strip(),new_blob=newblob,new_sha256=hashlib.sha256(new).hexdigest(),model_expected_blob=d['expected_blob'],model_current_blob=d['current_blob'],matches_model_oids=(oldblob==d['expected_blob'] and newblob==d['current_blob']),bytes_old=len(old),bytes_new=len(new),change_count=len(changed),hunk_count=len(hunks),functions_types_macros_calls=identifiers[:120],rule_applicability='unknown',rationale='Source bytes and diff are bound; impact on modeled assumptions requires semantic review of these exact changes and the build/preprocessor context.'))
out={'schema':'c3-model-source-drift-review.v1','repository':comp['repository'],'model_version':comp['model_version'],'model_sha256':comp['model_sha256'],'parser':'tree-sitter 0.26.0 / tree-sitter-cpp 0.23.4','profile':'light-ast','old_commit':old_commit,'old_tree':rows[0]['old_tree'],'new_commit':new_commit,'new_tree':rows[0]['new_tree'],'dependency_rows':len(rows),'changed_rows':sum(x['old_blob']!=x['new_blob'] for x in rows),'entries':rows,'policy':'Unknown is not interpreted as unaffected. Exact-source and partial gates unchanged.'}
(exp/'source_drift_review.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
md=['# C3 model source dependency drift review','',f"Model `{comp['model_version']}` SHA-256 `{comp['model_sha256']}`; parser Tree-sitter 0.26.0 / tree-sitter-cpp 0.23.4; profile `light-ast`.",'',f"Old source revision `{old_commit}` tree `{out['old_tree']}`; current `{new_commit}` tree `{out['new_tree']}`.",'', 'This inventory binds the exact raw source bytes and diffs. Semantic applicability remains `unknown` until each listed changed hunk is reviewed against macro expansion and the product build profile; no unchanged-impact inference is made. Exact-source binding and the partial gate are unchanged.','', '| ID | Kind | Path | Old blob / SHA-256 | New blob / SHA-256 | Changed lines | Functions/types/macros/calls | Rule applicability |','|---|---|---|---|---|---:|---|---|']
for r in rows:
 md.append(f"| {r['id']} | {r['kind']} | `{r['path']}` | `{r['old_blob']}` / `{r['old_sha256']}` | `{r['new_blob']}` / `{r['new_sha256']}` | {r['change_count']} | unknown | unknown |")
md += ['', '## Per-item change evidence','']
for r in rows:
 md += [f"### {r['id']} — `{r['path']}`",'',f"Model expected/current blobs match bound revisions: `{str(r['matches_model_oids']).lower()}`. Raw byte lengths: {r['bytes_old']} → {r['bytes_new']}.",'','Change cues:']
 # record changed symbol identifiers from lines but don't invent semantic classifications
 md += ['', f"Changed diff-line count: {r['change_count']}; hunk count: {r['hunk_count']}.", f"Identifier cues (textual only, not semantic findings): {', '.join(r['functions_types_macros_calls']) or 'none'}.", '', '**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.','']
md += ['## Parent/fix and control replay','', 'Parent/fix, safe, and unrelated controls were not replayed as part of this dependency inventory. Keep their prior exact-bound replay evidence separate; missing objects or partial parsing remain unknown. See `README.md` for reproducible source identity and Runner commands.','']
(exp/'source_drift_review.md').write_text('\n'.join(md).rstrip()+'\n',encoding='utf-8')
