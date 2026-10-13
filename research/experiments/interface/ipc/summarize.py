"""Offline, conservative experiment normalization; never infers safety from empty output."""
import argparse,csv,hashlib,json,re
from pathlib import Path

def load(p): return json.loads(p.read_text())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def regions(sample,root):
    # Lexical declaration/braces locator only for aligning baseline rows, not detection.
    # Erase comments/literals while preserving line offsets; use exact reviewed qualified symbols.
    result=[]
    for p in root.rglob('*.cpp'):
        raw=p.read_bytes().decode('utf-8')
        text=re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"',lambda m:''.join('\n' if c=='\n' else ' ' for c in m[0]),raw,flags=re.S)
        for symbol in sample['affected_symbols']:
            for match in re.finditer(r'(?<![\w:])'+re.escape(symbol)+r'\s*\([^;{]*\)\s*(?:const\s*)?\{',text):
                begin=text.index('{',match.start());depth=1;end=begin+1
                while end<len(text) and depth:
                    depth+=(text[end]=='{')-(text[end]=='}');end+=1
                result.append((str(p.relative_to(root)),text[:match.start()].count('\n')+1,text[:end].count('\n')+1))
    return result

def normalize(a,unit,tool):
    if tool=='Semgrep':
        runs=[r for r in load(a/'semgrep-file-runs.json') if r['unit']==unit]
        return [(m['path'],m['start']['line'],m['extra']['metadata']['family']) for r in runs for m in r['matches']], any(r['errors'] or r['exit'] for r in runs)
    if tool=='Joern':
        n='joern-synthetic-v2.json' if unit=='synthetic' else 'joern-'+unit+'.json'
        return [(m['file'],m['line'],m['family']) for m in load(a/n)], False
    n='codeql-synthetic-v2.sarif' if unit=='synthetic' else 'codeql-'+unit+'.sarif'
    rows=[]
    for run in load(a/n)['runs']:
        for m in run.get('results',[]):
            for loc in m['locations']:
                x=loc['physicalLocation'];rows.append((x['artifactLocation']['uri'],x['region']['startLine'],m['message']['text'].split(':')[0]))
    return rows,False

def supported(tool,sample):
    f=sample['family']
    if tool=='Clang': return f=='DATA-01' and sample.get('sample_id')!='cve-2024-0285'
    if tool=='Semgrep': return f!='AUTH-03' and sample.get('sample_id')!='cve-2024-0285'
    if tool=='Joern': return f in ('AUTH-01','AUTH-02','CAP-01') or (f=='AUTH-03' and sample.get('expected_rule')=='ipc.auth.service-identity')
    if tool=='CodeQL': return f in ('AUTH-01','AUTH-02','CAP-01') or (f=='DATA-01' and sample.get('sample_id')!='cve-2024-0285') or (f=='AUTH-03' and sample.get('expected_rule')=='ipc.auth.service-identity')
    return True

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--workspace',type=Path,required=True);args=ap.parse_args()
    b=Path(__file__).resolve().parents[4];a=args.workspace/'artifacts';out=b/'research/experiments/interface/ipc/results';out.mkdir(exist_ok=True)
    samples=[json.loads(s) for s in (b/'research/corpus/interface/ipc/verified_pairs.jsonl').read_text().splitlines()]
    own={(r['sample_id'],r['revision']):r for r in load(a/'own-runs.json')};rows=[]
    for s in samples:
        for rev in ('vulnerable','fixed'):
            unit=s['sample_id']+'-'+rev; rr=regions(s,args.workspace/'pairs'/s['sample_id']/rev)
            for tool in ('OHScanner','Semgrep','Joern','CodeQL'):
                usable=supported(tool,s);partial=False;count=None
                if tool=='OHScanner':
                    r=own[s['sample_id'],rev];count=r['root_candidates'];partial=r['execution_status']!='completed'
                elif usable:
                    hits,partial=normalize(a,unit,tool)
                    count=sum(f==s['family'] and any(path.endswith(p) and lo<=line<=hi for p,lo,hi in rr) for path,line,f in hits)
                    # AST/no-build extraction is not proof of full OpenHarmony preprocessing/type resolution.
                    if tool in ('Joern','CodeQL'): partial=True
                status='NA' if not usable else 'unknown' if partial else 'candidate' if count else 'not_observed'
                rows.append(dict(sample_id=s['sample_id'],external_ids=';'.join(s['external_ids']),family=s['family'],revision=rev,tool=tool,root_candidates=count,status=status,commit=s[rev+'_commit'],source=s['pr_url'],note='Design-set S2 static patch comparison; not S3 or independent recall. Unknown may retain candidates.'))
    synth=[];full={r['sample_id']:r for r in load(a/'ablation-results.json') if r['profile']=='full'}
    for s in load(b/'tests/fixtures/ipc/manifest.json'):
        for tool in ('OHScanner','Semgrep','Joern','CodeQL','Clang'):
            usable=supported(tool,s);count=None;partial=False
            if tool=='OHScanner':
                rules=full[s['sample_id']]['reported_rules']
                family_rules={'AUTH-01':{'ipc.relay.descriptor-boundary'},'AUTH-02':{'ipc.auth.missing'},'AUTH-03':{'ipc.auth.service-identity','ipc.auth.request-identity','ipc.auth.object-owner','ipc.auth.caller-class'},'AUTH-04':{'ipc.auth.guard-coverage'},'DATA-01':{'ipc.parcel.copy-range','ipc.parcel.position-range'},'CAP-01':{'ipc.capability.export'}}
                count=len(set(rules)&family_rules[s['family']])
            elif usable and tool!='Clang':
                hits,partial=normalize(a,'synthetic',tool);count=sum(Path(p).name==s['file'] and f==s['family'] for p,_,f in hits)
            elif usable:
                r=next(r for r in load(a/'clang-runs.json') if Path(r['file']).name==s['file']);partial=r['exit']!=0
                count=len(re.findall(r'warning:.*\[',Path(r['native_report']).read_text()))
            expected=bool(s['expected_rule']);met=None if not usable or partial else bool(count)==expected
            synth.append(dict(sample_id=s['sample_id'],family=s['family'],tool=tool,expected_positive=expected,candidates=count,status='NA' if not usable else 'unknown' if partial else 'met' if met else 'miss' if expected else 'false_positive',file=s['file']))
    for name,data in [('historical',rows),('synthetic',synth)]:
        (out/(name+'.json')).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
        with (out/(name+'.csv')).open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(data[0]),lineterminator="\n");w.writeheader();w.writerows(data)
    manifests=['own-runs.json','semgrep-file-runs.json','joern-runs.json','codeql-runs.json','clang-runs.json','ablation-results.json','generated-holdout-results.json']
    (out/'evidence_manifest.json').write_text(json.dumps({n:sha(a/n) for n in manifests},indent=2)+'\n')
    for tool in ('OHScanner','Semgrep','Joern','CodeQL','Clang'):
        subset=[x for x in synth if x['tool']==tool]; print(tool,{v:sum(x['status']==v for x in subset) for v in ('met','miss','false_positive','NA','unknown')})
if __name__=='__main__':main()
