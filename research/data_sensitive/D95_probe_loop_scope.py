"""Frozen whole-src reproduction of the D95 for-header shadow failure."""
import argparse
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

REPO=Path(__file__).resolve().parents[2]
REVISIONS=('82827ca79e8b71505b9941f5cad7f50e4695e748','c4605710ac517ca5b61f48fef03b31860fb88966')
SOURCE='\n'.join(('void Callback(const char *key,bool flag){',
    'unsigned outer=0,inner=0;unsigned *p=&outer;',
    'for(unsigned *p=&inner;flag;){break;}',
    '*p=(unsigned char)key[0];',
    'HILOG_INFO(1,"%{public}u",outer);',
    'HILOG_INFO(1,"%{public}u",inner);','}'))


def worker(snapshot):
    sys.path.insert(0,snapshot)
    from src.ohscanner.contracts import ScanContext,ScanRequest
    from src.ohscanner.detectors.data.models import SensitiveSourceModel
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
    raw=SOURCE.encode();oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    units,ast,_=index_sources((GitSource('service.cpp','cpp',oid,raw),))
    model=SensitiveSourceModel('fixture/d95','d'*40,parameters=(('service.cpp','Callback',0),),
                              provenance='Synthetic lexical loop-scope control; no target execution')
    request=ScanRequest('d95-loop',model.repository,model.commit,snapshot_digest(units),'current-component:'+model.repository)
    context=ScanContext(request,units,{'ast':ast});detector=SensitiveExposureDetector(model)
    direct=detector.detect(context,units);registry=DetectorRegistry();registry.register(detector)
    reports,coverage=run_all_with_coverage(context,registry)
    return {'version':detector.version,'direct':asdict(direct),'runner':asdict(reports[0]),'coverage':coverage}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D95_LOOP_SCOPE_20261020.json')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker),ensure_ascii=False));return
    result={'schema':1,'study':'D95 loop-header shadow restores outer binding','source':SOURCE,
            'source_sha256':hashlib.sha256(SOURCE.encode()).hexdigest(),'expected_sink_line':5,'runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D95_loop_scope_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        run=json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
                                               '--worker',str(snapshot)],cwd=snapshot))
        run.update({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest()})
        result['runs'].append(run)
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    for run in result['runs']:
        print(run['version'],'direct lines',[f['line'] for f in run['direct']['findings']],
              'Runner lines',[f['line'] for f in run['runner']['diagnostics']])


if __name__=='__main__':main()
