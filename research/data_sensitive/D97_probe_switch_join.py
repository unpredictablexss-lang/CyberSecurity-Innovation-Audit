"""Frozen D97 exact switch join and unsupported-exit observations."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import D95_probe_loop_scope as support

REVISIONS=('73b9a761eb06b11a383793e24ccc6a01b2e4c440',
           'ae71c3c8e099c42b1d5df81b1fe9c32cddd2a39a',
           '4958df655f86c1199bc326138aaf3b4ecaf9587e')
CASES={
    'two_exact_arms':'case 0:p=&second;break;default:p=&second;break;',
    'three_exact_arms':'default:p=&second;break;case 0:p=&second;break;case 3:p=&second;break;',
    'initializer_exact_arms':'case 0:p=&second;break;default:p=&second;break;',
    'missing_default':'case 0:p=&second;break;',
    'divergent_targets':'case 0:p=&first;break;default:p=&second;break;',
    'unknown_target':'case 0:p=GetDestination();break;default:p=&second;break;',
    'fallthrough':'case 0:p=&first;default:p=&second;break;',
    'return_live':'case 0:return;default:p=&second;break;',
    'duplicate_case':'case 0:p=&second;break;case 0:p=&second;break;default:p=&second;break;',
    'macro_override':'case 0:p=&second;break;default:p=&second;break;',
    'literal_only':'case 0:p=&second;break;default:p=&second;break;',
    'partial_header':'case 0:p=&second;break;default:p=&second;break;',
    'all_return_known_gap':'case 0:return;default:return;',
}


def worker(snapshot,case):
    support.SOURCE=source(case)
    if case!='partial_header':return support.worker(snapshot)
    sys.path.insert(0,snapshot)
    from dataclasses import asdict
    from src.ohscanner.contracts import ScanContext,ScanRequest
    from src.ohscanner.detectors.data.models import SensitiveSourceModel
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
    sources=[]
    for path,text in (('service.cpp',source(case)),('partial.h','struct Incomplete {')):
        raw=text.encode();oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        sources.append(GitSource(path,'cpp',oid,raw))
    units,ast,_=index_sources(tuple(sorted(sources,key=lambda u:u.path)))
    model=SensitiveSourceModel('fixture/d95','d'*40,parameters=(('service.cpp','Callback',0),),
                              provenance='Synthetic lexical control with selected partial header')
    request=ScanRequest('d97-partial-header',model.repository,model.commit,snapshot_digest(units),'current-component:'+model.repository)
    context=ScanContext(request,units,{'ast':ast});detector=SensitiveExposureDetector(model)
    direct=detector.detect(context,units);registry=DetectorRegistry();registry.register(detector)
    reports,coverage=run_all_with_coverage(context,registry)
    return {'version':detector.version,'direct':asdict(direct),'runner':asdict(reports[0]),
            'coverage':coverage,'selected_parse_status':{u.path:u.parse_status for u in units}}


def source(case):
    prefix='#define p GetDestination()' if case=='macro_override' else ''
    initial='&first' if case=='all_return_known_gap' else 'nullptr'
    condition='unsigned*q=&first;selector' if case=='initializer_exact_arms' else 'selector'
    write='*p=7;' if case=='literal_only' else '*p=(unsigned char)key[0];'
    return '\n'.join((prefix,'void Callback(const char*key,int selector){',
        'unsigned first=0,second=0;unsigned*p='+initial+';',
        'switch('+condition+'){'+CASES[case]+'}',write,
        'HILOG_INFO(1,"%{public}u",first);',
        'HILOG_INFO(1,"%{public}u",second);','}'))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--case')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D97_SWITCH_JOIN_20261020.json')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker,args.case),ensure_ascii=False));return
    result={'schema':1,'study':'D97 exact switch join; unsupported cases remain unknown',
            'cases':{k:{'source':source(k),'sha256':hashlib.sha256(source(k).encode()).hexdigest(),
                        'known_gap':k=='all_return_known_gap'} for k in CASES},'runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=support.REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D97_switch_join_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        runs={k:json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
              '--worker',str(snapshot),'--case',k],cwd=snapshot)) for k in CASES}
        result['runs'].append({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest(),'cases':runs})
        print(revision[:8],{k:[(f['rule_id'],f['line']) for f in v['direct']['findings']] for k,v in runs.items()})
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
