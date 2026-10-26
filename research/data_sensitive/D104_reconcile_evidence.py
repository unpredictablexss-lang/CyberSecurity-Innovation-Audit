"""D104 bounded immutable task/report/version reconciliation; no old test reruns."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

REPO=Path(__file__).resolve().parents[2]
BASE='8ff44ec699a1b3e353261e73034d75959f9c54bc'
FINAL='03479dc007c00d70186b528eeb6d570ecb06cae1'
TREE='research/data_sensitive/D_LINE_TASK_TREE_20261020.json'
DETECTOR='src/ohscanner/detectors/data/sensitive_exposure.py'


def git(*args):return subprocess.check_output(['git',*args],cwd=REPO)

def identity(revision,path):
    raw=git('show',revision+':'+path)
    return {'path':path,'blob':git('rev-parse',revision+':'+path).decode().strip(),
        'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}


def read_tree(revision):
    duplicates=[]
    def hook(pairs):
        d={}
        for key,value in pairs:
            if key in d:duplicates.append({'task':d.get('id'),'key':key})
            d[key]=value
        return d
    return json.loads(git('show',revision+':'+TREE).decode(),object_pairs_hook=hook),duplicates


def versions(revision,path):
    root=ast.parse(git('show',revision+':'+path).decode());constants={};result={}
    for node in root.body:
        if isinstance(node,ast.Assign):
            try:value=ast.literal_eval(node.value)
            except (ValueError,TypeError):continue
            for name in node.targets:
                if isinstance(name,ast.Name):constants[name.id]=value
    for node in root.body:
        if not isinstance(node,ast.ClassDef):continue
        for assignment in node.body:
            if not isinstance(assignment,ast.Assign):continue
            if not any(isinstance(target,ast.Name) and target.id=='version' for target in assignment.targets):continue
            value=assignment.value
            result[node.name]=constants.get(value.id,'unknown') if isinstance(value,ast.Name) else ast.literal_eval(value)
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D104_BOUNDED_TREE_AUDIT_20261020.json');args=parser.parse_args()
    before,old_duplicates=read_tree(BASE);tree,duplicates=read_tree(FINAL)
    paths=git('ls-tree','-r','--name-only',FINAL,'research/data_sensitive').decode().splitlines()
    selected=[]
    for task in tree['tasks']:
        if not re.fullmatch(r'[DT][0-9]+',task['id']):continue
        n=int(task['id'][1:]);isdev=task['id'][0]=='D'
        if not ((isdev and 83<=n<=103) or (not isdev and 83<=n<=102)):continue
        commits=[]
        for key,value in task.items():
            values=value if isinstance(value,list) else [value]
            if 'commit' not in key:continue
            for ref in values:
                if not isinstance(ref,str) or not re.fullmatch('[a-f0-9]{7,40}',ref):continue
                resolved=git('rev-parse','--verify',ref+'^{commit}').decode().strip()
                commits.append({'field':key,'recorded':ref,'resolved':resolved})
        reports=[p for p in paths if p.startswith('research/data_sensitive/'+task['id']+'_') and p.endswith('.md')]
        links=[]
        for path in reports:
            raw=git('show',FINAL+':'+path).decode('utf-8-sig')
            for link in re.findall(r'\]\(([^)]+)\)',raw):
                if link.startswith(('http://','https://')):
                    links.append({'report':path,'target':link,'check':'external link retained, network availability not asserted'})
                elif '://' in link:links.append({'report':path,'target':link,'check':'non-file scheme retained'})
                else:
                    target=link.split('#')[0].split(':')[0] if not re.match(r'^[A-Za-z]:[/\\]',link) else re.sub(r':\d+$','',link)
                    local=Path(target)
                    if not local.is_absolute():local=REPO/Path(path).parent/target
                    links.append({'report':path,'target':link,'local_exists':local.exists()})
        code=task.get('revision_commit') or (task.get('code_commits') or [None])[-1] or task.get('commit')
        detector_path='src/ohscanner/detectors/known_cves.py' if task['id']=='D83' else DETECTOR
        selected.append({'task':task['id'],'kind':task['kind'],'status':task['status'],
            'historical_validation':task.get('validation','not recorded in tree; see fixed reports'),
            'commits':commits,'latest_recorded_code_commit':code if isdev else None,
            'historical_detector_versions':versions(code,detector_path) if isdev and code else {},
            'reports':[identity(FINAL,p) for p in reports],'report_links':links})
    old=git('show',BASE+':'+DETECTOR);new=git('show',FINAL+':'+DETECTOR)
    previous=b'Detailed private Tree-sitter statements pending owner-approved shared expression facts; no new global frontend.'
    current=b'Shared AST indexes functions/calls; bounded private expression analysis retains syntax, type and alias limitations.'
    assert old.replace(previous,current)==new
    assert len(old_duplicates)==13 and not duplicates
    assert all(t['status']=='COMPLETED_INTEGRATED' for t in selected)
    assert len([t for t in selected if t['kind']=='development'])==21
    result={'schema':1,'scope':'D83-D103 and T83-T102 immutable references only; no old matrices rerun',
        'owner_base':BASE,'final_patch':FINAL,'task_tree':identity(FINAL,TREE),
        'duplicate_keys_before':old_duplicates,'duplicate_keys_after':duplicates,
        'tree_delta':'Removed duplicate status/completion keys only; D103/T102 actual completion retained; developer D102 compatibility69 corrected. D104/T103 remain in progress pending owner integration.',
        'source_metadata_change':{'old':previous.decode(),'new':current.decode(),'exact_single_replacement_only':True,'versions_before':versions(BASE,DETECTOR),'versions_after':versions(FINAL,DETECTOR)},
        'tasks':selected,'development_tasks':sum(t['kind']=='development' for t in selected),
        'test_tasks':sum(t['kind']=='testing' for t in selected),
        'all_selected_statuses_integrated':True,'all_recorded_commit_refs_resolve':True,
        'tests_semantics':'Historical test counts are per fixed slice and fixture version; not additive, not current suite totals. Current431/69/51 command outputs recorded separately.',
        'legacy_reports':'Historical known_gap/blocked/not_run records are retained at their original hashes, with superseding fixes and remaining limits mapped in D104 report.'}
    Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('D83-D10321 development + T83-T10220 testing entries; all commit refs resolve; report identities fixed; duplicate keys13→0.')


if __name__=='__main__':main()
