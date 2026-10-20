#!/usr/bin/env python3
"""Verify D42 A0 source bindings, current IPC replays, and queue preservation."""
from __future__ import annotations
import argparse, csv, hashlib, json, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
COMMIT='71ab1e0881e0a79f2b9528742677467e7bb8dde5'
TREE='9cc6c53506a70424485885c4c10b29dfbfaa8d1b'
IDS={f'CR-{n:04d}' for n in range(174,197)}
REPORT=ROOT/'research/evidence/cpp/d42_player_framework_ipc_source_audit_20261025.json'
CLI=ROOT/'research/evidence/cpp/d42_player_framework_cli_20261025.json'
CLI_H=ROOT/'research/evidence/cpp/d42_player_framework_cli_with_headers_20261025.json'
QUEUE=ROOT/'research/deliveries/cpp/a0_triage_20261019/queue.csv'

def git(git_dir: str,*args: str)->bytes:
    return subprocess.check_output(['git',f'--git-dir={git_dir}',*args],stderr=subprocess.PIPE)

def sha(path: Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--git-dir',required=True)
    ap.add_argument('--queue',type=Path,default=QUEUE)
    ap.add_argument('--report',type=Path,default=REPORT)
    ap.add_argument('--cli',type=Path,default=CLI)
    ap.add_argument('--cli-with-headers',type=Path,default=CLI_H)
    a=ap.parse_args()
    report=json.loads(a.report.read_text(encoding='utf-8'))
    rows=list(csv.DictReader(a.queue.open(encoding='utf-8-sig',newline='')))
    assert len(rows)==345
    selected={r['queue_id']:r for r in rows if r['queue_id'] in IDS}
    assert set(selected)==IDS
    assert git(a.git_dir,'rev-parse',f'{COMMIT}^{{tree}}').decode().strip()==TREE
    assert report['source']['commit']==COMMIT and report['source']['tree']==TREE
    assert len(report['mapping'])==23 and report['disposition']=='PARTIAL/BLOCK'
    cli=json.loads(a.cli.read_text(encoding='utf-8')); cli_h=json.loads(a.cli_with_headers.read_text(encoding='utf-8'))
    assert cli['commit']==COMMIT and cli['git_tree']==TREE
    assert cli['validated_vulnerability']==0 and cli['diagnostic_count']==24
    assert cli['source_parsing']['parsing_status']=={'complete':1,'partial':10}
    assert cli_h['commit']==COMMIT and cli_h['git_tree']==TREE and cli_h['diagnostic_count']==24
    assert cli_h['source_parsing']['parsing_status']=={'complete':6,'partial':16}
    assert sha(a.cli)==report['cli']['raw_cli_sha256']
    assert sha(a.cli_with_headers)==report['cli']['header_replay']['raw_cli_sha256']
    diags=[d for run in cli['detector_runs'] for d in run['diagnostics']]
    mapping={r['queue_id']:r for r in report['mapping']}
    assert set(mapping)==IDS
    for ident,row in selected.items():
        m=mapping[ident]
        for key in ('repository','commit','tree','path','blob','source_sha256','rule','original_status','queue_status'):
            assert row[key]==m[key],(ident,key,row[key],m[key])
        assert int(row['line'])==int(m['line'])
        matches=[d for d in diags if d['file']==m['path'] and d['line']==int(m['line']) and d['rule_id']==m['rule'] and d['diagnostic_id']==m['current_finding_id']]
        assert len(matches)==1,(ident,matches)
    for p,evidence in report['source']['files'].items():
        data=git(a.git_dir,'show',f'{COMMIT}:{p}')
        assert git(a.git_dir,'rev-parse',f'{COMMIT}:{p}').decode().strip()==evidence['blob']
        assert len(data)==evidence['bytes'] and hashlib.sha256(data).hexdigest()==evidence['sha256']
        lines=data.decode(errors='replace').splitlines()
        guard=min(i for i,line in enumerate(lines) if 'ReadInterfaceToken' in line)
        descriptor=min(i for i,line in enumerate(lines) if 'GetDescriptor()' in line and i>=guard)
        dispatch=min(i for i,line in enumerate(lines) if 'switch (' in line or 'auto itFunc =' in line)
        assert guard <= descriptor < dispatch,p
    for p,evidence in report['source']['supporting_proxy_and_registration_sources'].items():
        data=git(a.git_dir,'show',f'{COMMIT}:{p}')
        assert git(a.git_dir,'rev-parse',f'{COMMIT}:{p}').decode().strip()==evidence['blob']
        assert len(data)==evidence['bytes'] and hashlib.sha256(data).hexdigest()==evidence['sha256']
        lines=data.decode(errors='replace').splitlines()
        assert [i for i,line in enumerate(lines,1) if 'WriteInterfaceToken' in line]==evidence['write_interface_token_lines']
        assert [i for i,line in enumerate(lines,1) if 'SendRequest(' in line]==evidence['send_request_lines']
    for p,evidence in report['source']['headers'].items():
        data=git(a.git_dir,'show',f'{COMMIT}:{p}')
        assert git(a.git_dir,'rev-parse',f'{COMMIT}:{p}').decode().strip()==evidence['blob']
        assert len(data)==evidence['bytes'] and hashlib.sha256(data).hexdigest()==evidence['sha256']
        assert b'IRemoteStub<' in data,p
    states={(r['original_status'],r['queue_status']) for r in selected.values()}
    assert states=={('not_testable','paused_pending_evidence')}
    print(json.dumps({'overall_ok':True,'queue_rows':len(rows),'d42_ids':len(selected),'exact_cli_hits':23,'cli_total_findings':24,'header_context_findings':24,'source_cpp_files':len(report['source']['files']),'supporting_headers':len(report['source']['headers']),'parse_status':cli['source_parsing']['parsing_status'],'queue_preserved':True,'disposition':'PARTIAL/BLOCK'},indent=2))
    return 0
if __name__=='__main__': raise SystemExit(main())
