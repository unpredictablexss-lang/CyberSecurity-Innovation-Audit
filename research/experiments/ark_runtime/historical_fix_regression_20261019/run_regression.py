from __future__ import annotations
import hashlib, json, resource, subprocess
from pathlib import Path
D=Path('/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/historical_fix_regression_20261019')
BASE=Path('/home/deepsleep/c-line-c1-profile-20261018/out-gn-20261019-replay2/rk3568')
ES=BASE/'clang_x64/arkcompiler/ets_frontend/es2abc'
VM=BASE/'arkcompiler/ets_runtime/ark_js_vm'
Q=Path('/tmp/c-line-qemu-8.2.2/extracted/usr/bin/qemu-arm-static')
SYSROOT=Path('/home/deepsleep/c-line-c1-profile-20261018/qemu-runtime-20261019/sysroot')

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def no_core(): resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def execute(name,source,abc):
    cp=subprocess.run([str(ES),'--output',str(abc),str(source),'--target-api-sub-version=beta3'],capture_output=True,timeout=60)
    (D/f'{name}_es2abc.stdout').write_bytes(cp.stdout); (D/f'{name}_es2abc.stderr').write_bytes(cp.stderr)
    if cp.returncode: return {'compile_exit':cp.returncode,'compile_sha256':sha(abc) if abc.exists() else None}
    try:
        rp=subprocess.run([str(Q),'-L',str(SYSROOT),str(VM),'--asm-interpreter=false','--test-assert=true','--enable-print-execute-time=true',str(abc)],capture_output=True,timeout=30,env={'LD_LIBRARY_PATH':'/lib'},preexec_fn=no_core)
        code=rp.returncode; out=rp.stdout; err=rp.stderr
    except subprocess.TimeoutExpired as e:
        code='timeout'; out=e.stdout or b''; err=e.stderr or b''
    (D/f'{name}_vm.stdout').write_bytes(out); (D/f'{name}_vm.stderr').write_bytes(err)
    return {'compile_exit':cp.returncode,'run_exit':code,'abc_sha256':sha(abc),'stdout_sha256':hashlib.sha256(out).hexdigest(),'stderr_sha256':hashlib.sha256(err).hexdigest(),'stdout':out.decode('utf-8','replace')[-300:],'stderr_tail':err.decode('utf-8','replace')[-600:]}

exact=D/'typedarrayfilter.ts'; exact_abc=D/'typedarrayfilter.abc'
harness=D/'typedarrayfilter_harness.ts'; harness.write_bytes(exact.read_bytes()+b'\ntest_end();\n')
harness_abc=D/'typedarrayfilter_harness.abc'
qv=subprocess.run([str(Q),'--version'],capture_output=True,text=True,timeout=10).stdout.strip()
result={'historical_fix_commit':'a0e30483ab3e4aead67ecfb5c708489915e447f9','c1_runtime_commit':'a65a2853ccae13da167d9aa4720ab8b11ec16656','qemu_version':qv,'qemu_sha256':sha(Q),'vm_sha256':sha(VM),'es2abc_sha256':sha(ES),'source_blob_oid':subprocess.check_output(['git','--git-dir=/mnt/d/openHarmonyScanner/openharmony/.repo/projects/arkcompiler/ets_runtime.git','hash-object',str(exact)],text=True).strip(),'exact':execute('exact',exact,exact_abc),'harness_source_sha256':sha(harness),'harness':execute('harness',harness,harness_abc)}
(D/'execution_record.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
