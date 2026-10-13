"""Offline seed import: user inventory -> official pinned Git blobs, no verdicts."""
from pathlib import Path
import re,json,hashlib,subprocess,argparse

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--inventory',type=Path,required=True);ap.add_argument('--security-repo',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    text=a.inventory.read_text(encoding='utf-8');section=text[text.index('## 2.'):text.index('## 3.')]
    head=subprocess.check_output(['git','-C',str(a.security_repo),'rev-parse','HEAD'],text=True).strip()
    records=[]
    for line in section.splitlines():
        if not line.startswith('| ['):continue
        cols=line.strip('|').split('|');label,url=re.search(r'\[([^]]+)\]\(([^)]+)\)',cols[0]).groups()
        ids=re.findall(r'(?:OpenHarmony-SA-\d{4}-\d{4}|CVE-\d{4}-\d+)',label)
        path=url.split('/blob/master/')[-1]
        run=subprocess.run(['git','-C',str(a.security_repo),'show',head+':'+path],capture_output=True)
        body=run.stdout.decode('utf-8') if run.returncode==0 else ''
        rows=[l for l in body.splitlines() if any(i in l for i in ids)]
        patches=re.findall(r'https://(?:gitee|gitcode)\.com/[^)\s]+',cols[-1])
        records.append(dict(sample_id=re.sub(r'[^A-Za-z0-9.-]+','_',label),external_ids=ids,families_provisional=re.findall(r'(?:AUTH|DATA|CAP)-\d\d',cols[1]),ipc_relevance='core' if '核心' in cols[1] else 'adjacent',advisory_url=url,official_blob_url=f'https://github.com/openharmony/security/blob/{head}/{path}',official_source_commit=head,official_source_sha256=hashlib.sha256(run.stdout).hexdigest() if body else None,official_matching_rows=rows,advisory_id_match=bool(rows),patch_reference_urls=patches,reported_component=cols[2].strip().strip('`'),summary=cols[3].strip(),verification_level='S1' if rows else 'unverified_seed',label_quality='unverified_patch',vulnerable_commit=None,fixed_commit=None,root_cause_instance_id=None,split=None,ipc_relevance_verified=False))
    for r in records:r['shared_patch_sample_ids']=[q['sample_id'] for q in records if q is not r and set(q['patch_reference_urls'])&set(r['patch_reference_urls'])]
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in records),encoding='utf-8')
    print(json.dumps(dict(records=len(records),official_matches=sum(bool(r['official_matching_rows']) for r in records),security_commit=head)))
if __name__=='__main__':main()
