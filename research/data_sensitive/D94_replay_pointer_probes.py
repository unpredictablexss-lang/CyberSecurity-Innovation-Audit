"""Whole-src owner/initial/final snapshots for D94 named material-write probes."""
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
REVISIONS=('fd36dc2e61abfe01c1a2e244b97d75254ffd5f82',
           '5d33abf99857584a7194cb466590592e397e9339',
           'fe8080e4cd48a53422f4647981b3871575a31f01')


def worker(snapshot):
    sys.path.insert(0,snapshot)
    from src.ohscanner.contracts import ScanContext,ScanRequest
    from src.ohscanner.detectors.data.models import SensitiveSourceModel
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
    cases={
        'd93_exact':json.loads((REPO/'research/data_sensitive/D93_POINTER_OUTPUT_GAP_20261020.json').read_text())['source'],
        'unknown_write':'void Callback(const char *key,unsigned *out){*out=(unsigned char)key[0];}',
        'local_pointer':'void Callback(const char *key){unsigned output=0;unsigned *p=&output;*p=(unsigned char)key[0];HILOG_INFO(1,"%{public}u",output);}',
        'member_output':'struct Box{unsigned count;};void Write(const char *value,Box *out){out->count=(unsigned char)value[0];}void Callback(const char *key){Box output={0};Write(key,&output);HILOG_INFO(1,"%{public}u",output.count);}',
        'literal_metadata':'void Write(const char *value,unsigned *out){*out=7;}void Callback(const char *key){unsigned output=0;Write(key,&output);HILOG_INFO(1,"%{public}u",output);}',
        'input_not_output':'void Read(char *value){}void Callback(char *key){Read(key);HILOG_INFO(1,"%{public}s",key);}',
        'local_rebind':'void Rebind(const char *secret,char *out){out=(char*)secret;}void Callback(const char *key){char buffer[32]={0};Rebind(key,buffer);HILOG_INFO(1,"%{public}s",buffer);}',
        'genuine_copy':'void Copy(const char *secret,char *out){memcpy_s(out,32,secret,31);}void Callback(const char *key){char buffer[32]={0};Copy(key,buffer);HILOG_INFO(1,"%{public}s",buffer);}',
        'null_cast':'struct PrivateKeyInfo{int unused;};void sample(PrivateKeyInfo **output){*output=static_cast<PrivateKeyInfo *>(nullptr);}',
    }
    result={'version':SensitiveExposureDetector.version,'probes':{}}
    model=SensitiveSourceModel('fixture/d94','d'*40,parameters=(('service.cpp','Callback',0),),
                              provenance='Synthetic explicit material argument only; no target execution')
    for name,text in cases.items():
        raw=text.encode();oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        units,ast,_=index_sources((GitSource('service.cpp','cpp',oid,raw),))
        request=ScanRequest('d94',model.repository,model.commit,snapshot_digest(units),'current-component:'+model.repository)
        context=ScanContext(request,units,{'ast':ast})
        detector=SensitiveExposureDetector() if name=='null_cast' else SensitiveExposureDetector(model)
        direct=detector.detect(context,units);registry=DetectorRegistry();registry.register(detector)
        reports,coverage=run_all_with_coverage(context,registry)
        result['probes'][name]={'source':text,'source_sha256':hashlib.sha256(raw).hexdigest(),
            'direct':asdict(direct),'runner':asdict(reports[0]),'coverage':coverage}
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D94_POINTER_PROBES_20261020.json')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker),ensure_ascii=False));return
    result={'schema':1,'study':'D94 input value versus actual pointee write; cast failure closure','runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D94_pointer_probes_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        run=json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
                                               '--worker',str(snapshot)],cwd=snapshot))
        run.update({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest(),
                    'src_tree':subprocess.check_output(['git','rev-parse',revision+':src'],cwd=REPO).decode().strip()})
        result['runs'].append(run)
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    for run in result['runs']:
        print(run['revision'][:10],{name:(len(p['direct']['findings']),len(p['runner']['diagnostics']))
                                  for name,p in run['probes'].items()})


if __name__=='__main__':main()
