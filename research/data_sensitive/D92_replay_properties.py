"""Fixed whole-src D92 probes and original T85 three-object replay."""
import argparse
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

REPO = Path(__file__).resolve().parents[2]
STORE = 'D:/openHarmonyScanner/openharmony/.repo/project-objects/security_certificate_framework.git'


def worker(snapshot):
    sys.path.insert(0,snapshot)
    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

    def context(sources,repository,commit):
        units,ast,_ = index_sources(tuple(sources))
        units = tuple(sorted(units,key=lambda u:u.path))
        request = ScanRequest('d92-frozen',repository,commit,snapshot_digest(units),
                              'current-component:'+repository)
        return ScanContext(request,units,{'ast':ast})

    def scan(ctx):
        detector = SensitiveExposureDetector()
        direct = detector.detect(ctx,ctx.units)
        registry = DetectorRegistry()
        registry.register(detector)
        reports,coverage = run_all_with_coverage(ctx,registry)
        calls=[]
        for unit in ctx.units:
            for call in ctx.shared_facts['ast'][unit.path]['calls']:
                start,end = call['start_byte'],call['end_byte']
                calls.append({'file':unit.path,**call,
                    'raw_span_sha256':hashlib.sha256(unit.text.encode()[start:end]).hexdigest()})
        return {'direct':asdict(direct),'runner':asdict(reports[0]),'coverage':coverage,
                'snapshot_sha256':ctx.request.snapshot_sha256,
                'parse_status':{u.path:u.parse_status for u in ctx.units},'calls':calls}

    key='const std::string CERT_PRIVATE_KEY="key";\n'
    get='napi_get_named_property(env,obj,CERT_PRIVATE_KEY.c_str(),&data);'
    has='napi_has_named_property(env,obj,CERT_PRIVATE_KEY.c_str(),&present);'
    cases={'get_key_only':key+'void f(){napi_value data=nullptr;'+get+'}',
           'has_key_only':key+'void f(){bool present=false;'+has+'}',
           'ordinary_output_to_consume':key+'void f(){napi_value data=nullptr;'+get+'\nConsume(data);}',
           'ordinary_output_to_getter':key+'void f(){napi_value data=nullptr;'+get+'\nnapi_get_value_string_utf8(env,data,buffer,32,&length);}',
           'unknown_wrapper':key+'void f(){UnknownWrapper(CERT_PRIVATE_KEY.c_str());}'}
    result={'version':SensitiveExposureDetector.version,'probes':{}}
    for name,text in cases.items():
        raw=text.encode(); oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        result['probes'][name]=scan(context((GitSource('service.cpp','cpp',oid,raw),),
                                              'fixture/d92','f'*40))
    cert=next(c for c in json.loads((REPO/'research/data_sensitive/T85_SOURCE_MANIFEST.json').read_text())['components']
              if c['key']=='cert')
    source=[]
    for item in cert['files']:
        oid=subprocess.check_output(['git','--git-dir',STORE,'rev-parse',cert['commit']+':'+item['path']]).decode().strip()
        raw=subprocess.check_output(['git','--git-dir',STORE,'cat-file','blob',oid])
        assert oid==item['blob'] and len(raw)==item['bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256']
        source.append(GitSource(item['path'],'cpp',oid,raw))
    result['source']=cert
    result['strict_t85']=scan(context(source,cert['repository'],cert['commit']))
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--worker')
    parser.add_argument('--before',default='86ba349249e02320c92805da27d9962eeead8d21')
    parser.add_argument('--after',default='0420a3905b1558e1d1251ac11e5e2034e6c3e45d')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D92_DEVELOPER_REPLAY_20261020.json')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker),ensure_ascii=False))
        return
    result={'schema':1,'study':'D92 exact schema input and fetched-key output','runs':[]}
    for revision in (args.before,args.after):
        archive=subprocess.check_output(['git','archive',revision,'src/'],cwd=REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D92_developer_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(snapshot,filter='data')
        run=json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
                                               '--worker',str(snapshot)],cwd=snapshot))
        run.update({'revision':revision,'src_archive_sha256':hashlib.sha256(archive).hexdigest()})
        result['runs'].append(run)
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    for run in result['runs']:
        print(run['version'],{name:(len(p['direct']['findings']),len(p['runner']['diagnostics']))
                              for name,p in run['probes'].items()},
              'strict=',len(run['strict_t85']['direct']['findings']),len(run['strict_t85']['runner']['diagnostics']))


if __name__=='__main__':
    main()
