"""Reproducible fixed-src callable probes and pinned upstream cleanup facts.

Only reads Git objects; runs scanner Python, never upstream target code.
"""
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
UPSTREAM = Path('D:/openHarmonyScanner/openharmony/.repo/project-objects/security_certificate_framework.git')
COMMIT = 'e270363a042bf8f0126881c76d1341ad457cc187'
PATHS = (
    'frameworks/js/napi/certificate/src/napi_cert_utils.cpp',
    'frameworks/js/napi/certificate/inc/napi_cert_defines.h',
    'frameworks/common/v1.0/inc/cf_log.h',
    'frameworks/common/v1.0/src/cf_memory.c',
    'frameworks/common/v1.0/inc/cf_memory.h',
    'frameworks/common/v1.0/src/cf_blob.c',
    'interfaces/inner_api/common/cf_blob.h',
)


def upstream(*args):
    return subprocess.check_output(['git', '--git-dir', str(UPSTREAM), *args])


def worker(snapshot):
    sys.path.insert(0, snapshot)
    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.detectors.data.models import SensitiveSourceModel
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

    def context(sources, repository, commit):
        units, ast, _ = index_sources(tuple(sources))
        units = tuple(sorted(units,key=lambda unit:unit.path))
        request = ScanRequest('d90-probe', repository, commit, snapshot_digest(units),
                              'current-component:' + repository)
        return ScanContext(request, units, {'ast': ast})

    def scan(ctx, detector):
        direct = detector.detect(ctx, ctx.units)
        registry = DetectorRegistry()
        registry.register(detector)
        reports, coverage = run_all_with_coverage(ctx, registry)
        return {'direct': asdict(direct), 'runner': asdict(reports[0]), 'coverage': coverage}

    model = SensitiveSourceModel('fixture/d90-probe', 'd'*40,
        parameters=(('service.cpp', 'Callback', 0),),
        provenance='Synthetic callable identity control only')
    probes = {
        'callable_parameter': 'void Callback(const char *key,void(*CfFree)(const char*)){CfFree(key);}',
        'local_alias': 'void Callback(const char *key,void(*handler)(const char*)){auto CfFree=handler;CfFree(key);}',
        'ordinary_argument': 'void Callback(const char *key,void(*CfFree)(const char*)){CfFree("ordinary");}',
        'visible_wrapper_unproved_free': '#include <stdlib.h>\nvoid CfFree(void *addr){if(addr!=NULL){free(addr);}}\nvoid Callback(char *key){CfFree(key);}',
    }
    result = {'version': SensitiveExposureDetector.version, 'probes': {}}
    for name, text in probes.items():
        data = text.encode()
        oid = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ctx = context((GitSource('service.cpp','cpp',oid,data),), model.repository, model.commit)
        result['probes'][name] = scan(ctx, SensitiveExposureDetector(model))
    sources = []
    facts = []
    for path in PATHS:
        oid = upstream('rev-parse', COMMIT+':'+path).decode().strip()
        data = upstream('cat-file','blob',oid)
        sources.append(GitSource(path, 'c' if path.endswith('.c') else 'cpp', oid, data))
        facts.append({'path':path,'blob':oid,'bytes':len(data),
                      'sha256':hashlib.sha256(data).hexdigest()})
    result['source'] = {'commit':COMMIT, 'tree':upstream('rev-parse',COMMIT+'^{tree}').decode().strip(),
                        'files':facts}
    bounds_store = UPSTREAM.with_name('third_party_bounds_checking_function.git')
    bounds_commit = '2ae82839ecaaa7d031e66ccbd2076d671acfd615'
    def bounds(*args):
        return subprocess.check_output(['git','--git-dir',str(bounds_store),*args])
    dependency_files = []
    for path in ('include/securec.h','src/memset_s.c'):
        oid = bounds('rev-parse',bounds_commit+':'+path).decode().strip()
        data = bounds('cat-file','blob',oid)
        dependency_files.append({'path':path,'blob':oid,'bytes':len(data),
                                 'sha256':hashlib.sha256(data).hexdigest()})
    result['supplementary_memset_dependency'] = {
        'repository':'openharmony/third_party_bounds_checking_function',
        'commit':bounds_commit,'tree':bounds('rev-parse',bounds_commit+'^{tree}').decode().strip(),
        'files':dependency_files,
        'scope':'Research only, not asserted as certificate linked build or scanner input'}
    result['scopes'] = {}
    for name, selected in (('strict_t85_three',sources[:3]), ('extended_seven',sources)):
        ctx = context(selected, 'openharmony/security_certificate_framework', COMMIT)
        result['scopes'][name] = {'snapshot_sha256':ctx.request.snapshot_sha256,
            'parse_status':{u.path:u.parse_status for u in ctx.units},
            **scan(ctx, SensitiveExposureDetector())}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker')
    parser.add_argument('--before',default='5c82be52e05a814e7d29a43c6627b5e53a1ad2c0')
    parser.add_argument('--after',default='ef7cb1c2abc8cdab6b13c3db92bd7c985ceb00cb')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D90_DEVELOPER_PROBES_20261020.json')
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker),ensure_ascii=False))
        return
    result = {'schema':1,'study':'D90 callable regression and cleanup proof boundaries','runs':[]}
    for revision in (args.before,args.after):
        archive = subprocess.check_output(['git','archive',revision,'src/'],cwd=REPO)
        snapshot = Path('D:/openHarmonyScanner/records/D90_developer_20261020') / revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(snapshot,filter='data')
        run = json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
                         '--worker',str(snapshot)],cwd=snapshot))
        run.update({'revision':revision,'src_archive_sha256':hashlib.sha256(archive).hexdigest()})
        result['runs'].append(run)
    output = Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    for run in result['runs']:
        print(run['revision'], run['version'],
              {name:(len(p['direct']['findings']),len(p['runner']['diagnostics']))
               for name,p in run['probes'].items()},
              {name:(len(s['direct']['findings']),len(s['runner']['diagnostics']))
               for name,s in run['scopes'].items()})


if __name__ == '__main__':
    main()
