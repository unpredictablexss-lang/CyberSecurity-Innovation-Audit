from __future__ import annotations
import json
from pathlib import Path
import re

DIR = Path(__file__).resolve().parents[1]
WORK = DIR / "_work"
EXEC = json.loads((WORK / "c7_execution_results.json").read_text(encoding="utf-8"))

def summary(name: str) -> dict:
    text = (WORK / f"{name}.stderr.txt").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"Ran (\d+) tests? in ([^\r\n]+)", text)
    ran = int(m.group(1)) if m else 0
    errors = 0
    em = re.search(r"FAILED \(errors=(\d+)", text)
    if em:
        errors = int(em.group(1))
    skipped = 0
    sm = re.search(r"skipped=(\d+)", text)
    if sm:
        skipped = int(sm.group(1))
    ok = "OK" in text.splitlines()[-3:] or "\nOK\n" in text
    status = "passed" if ok and errors == 0 else "failed_fail_closed"
    return {
        "suite": name,
        "tests_run": ran,
        "passed": max(0, ran - errors - skipped),
        "errors": errors,
        "skipped": skipped,
        "status": status,
        "log": f"_work/{name}.stderr.txt",
    }

suites = [summary(x) for x in (
    "unittest", "test_exception_guard", "test_detector_cases",
    "test_c3_mechanisms", "test_type_origin", "test_ir_path", "test_parser_owner"
)]
obj_by_id = {x["id"]: x for x in EXEC["object_results"]}
dep_by_id = {x["id"]: x for x in EXEC["dependency_results"]}

def object_record(spec: dict, result: dict) -> dict:
    metadata_ok = (
        result.get("commit") == spec.get("commit")
        and result.get("tree") == spec.get("expected_tree")
        and result.get("actual_blob") == spec.get("expected_blob")
    ) if spec.get("commit") else False
    return {
        "id": spec["id"],
        "role": spec["role"],
        "repository_declared": result.get("repository_declared"),
        "object_ref": result.get("object_ref"),
        "commit": result.get("commit"),
        "expected_commit": spec.get("commit"),
        "tree": result.get("tree"),
        "expected_tree": spec.get("expected_tree"),
        "parents": result.get("parents", []),
        "expected_parent": spec.get("expected_parent"),
        "path": result.get("path"),
        "actual_blob": result.get("actual_blob"),
        "expected_blob": spec.get("expected_blob"),
        "expected_source_sha256": spec.get("expected_source_sha256"),
        "actual_source_sha256": result.get("actual_source_sha256"),
        "expected_bytes": spec.get("expected_bytes"),
        "actual_bytes": result.get("actual_bytes"),
        "metadata_commit_tree_path_blob_verified": bool(metadata_ok),
        "source_bytes_verified": result.get("status") == "verified",
        "status": result.get("status"),
        "fail_closed_reason": result.get("fail_closed_reason"),
        "assessment": "candidate/unassessed" if spec["role"] not in {"safe_control_not_verdict", "unrelated"} else "unknown; control role is not a verdict",
    }

object_specs = [
    {"id":"C1_TYPE_ORIGIN_PARENT","role":"parent","commit":"830e85b40240677039719fcbf14f721ad3b19050","expected_tree":"579712c1ebbb703d17cea422b1572023bed5d8a4","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","expected_blob":"054451b1be4f39254d56a1683cc9d1c1b5e55018","expected_source_sha256":"847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422","expected_bytes":150433},
    {"id":"C1_TYPE_ORIGIN_FIX","role":"fix","commit":"a0e30483ab3e4aead67ecfb5c708489915e447f9","expected_tree":"82af11ced4297818410ccf61906b703d25b69165","expected_parent":"830e85b40240677039719fcbf14f721ad3b19050","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","expected_blob":"95f54f2875f401afe3167c62f8c1e7799782be8c","expected_source_sha256":"8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e","expected_bytes":150509},
    {"id":"EXCEPTION_PATH_PARENT","role":"unknown","commit":"c758818dbfd0b146a908d43d21f6ca1706c33783","expected_tree":"5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","expected_blob":"857ad416bc102fcd5d462e9702d2ba7c51f29b6d","expected_source_sha256":"984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9"},
    {"id":"EXCEPTION_PATH_FIX","role":"fix","commit":"81ca57487d04ea30cd11c271e86494a4e130f43e","expected_tree":"f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5","expected_parent":"c758818dbfd0b146a908d43d21f6ca1706c33783","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","expected_blob":"3b9de9d915d767d7a67316145451da2446162884","expected_source_sha256":"4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0"},
    {"id":"CURRENT_BOUND_CONTROL","role":"safe_control_not_verdict","commit":"a65a2853ccae13da167d9aa4720ab8b11ec16656","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","expected_blob":"68fb3b0adc4f9062889a861be51b7be90362e37a","expected_source_sha256":"76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c"},
    {"id":"CURRENT_UNBOUND_PARENT_CONTROL","role":"unrelated","object_ref":"a65a2853ccae13da167d9aa4720ab8b11ec16656^","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"},
]
dep_specs = [
    {"id":"C1_CREATOR_DEPENDENCY","role":"dependency","commit":"830e85b40240677039719fcbf14f721ad3b19050","expected_tree":"579712c1ebbb703d17cea422b1572023bed5d8a4","path":"ecmascript/compiler/new_object_stub_builder.cpp","expected_blob":"757b8d050d306d349822600deacb295c7a54245e","expected_source_sha256":"3fd7e99e957fb5b7793cb7c36c01b370208c05645aa93551da6abeecaf2e7198","expected_bytes":126036},
    {"id":"EXCEPTION_CREATOR_DEPENDENCY_PARENT","role":"dependency","commit":"c758818dbfd0b146a908d43d21f6ca1706c33783","expected_tree":"5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a","path":"ecmascript/compiler/new_object_stub_builder.cpp","expected_blob":"05dda56de74949f07a241942be6465beaf94b52a","expected_source_sha256":"c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e"},
    {"id":"EXCEPTION_CREATOR_DEPENDENCY_FIX","role":"dependency","commit":"81ca57487d04ea30cd11c271e86494a4e130f43e","expected_tree":"f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5","path":"ecmascript/compiler/new_object_stub_builder.cpp","expected_blob":"05dda56de74949f07a241942be6465beaf94b52a","expected_source_sha256":"c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e"},
]

inventory = {
    "schema":"c7-object-inventory-v2",
    "generated_at":"2026-10-19T00:00:00+08:00",
    "evidence_policy":"fail_closed",
    "project_checkout":{"head":"0f8e6403095ea0fd8d6c8ac41a4789299915d139","branch":"codex/full-runtime-performance-audit-20261014","remote":"https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git"},
    "pinned_baseline":{"commit":"b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df","tree":"f4db05167c5cec007270c782c6bb97711e6414ae","availability":"present"},
    "ark_git_store":{"path":"E:/网安/_oh_targets/arkcompiler_ets_runtime","head_observed":"138cdd847e552a842f4a4fe065708f9d5e08a76c","partial_clone_filter":"blob:none","network_policy":"GIT_NO_LAZY_FETCH=1; no fetch/checkout"},
    "model_binding":{"detector_id":"ohscanner.ark.runtime.type_safety","version":"0.6.2","source":"b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df:src/ohscanner/detectors/ark_runtime/model.py"},
    "objects":[object_record(s, obj_by_id[s["id"]]) for s in object_specs],
    "dependencies":[object_record(s, dep_by_id[s["id"]]) for s in dep_specs],
    "summary":{"object_slots":6,"metadata_commit_tree_path_blob_verified":sum(object_record(s,obj_by_id[s["id"]])["metadata_commit_tree_path_blob_verified"] for s in object_specs),"source_bytes_verified":sum(object_record(s,obj_by_id[s["id"]])["source_bytes_verified"] for s in object_specs),"fail_closed_slots":sum(not object_record(s,obj_by_id[s["id"]])["source_bytes_verified"] for s in object_specs),"validated_vulnerability":0},
}

replays = {
    "schema":"c7-replay-results-v2",
    "generated_at":"2026-10-19T00:00:00+08:00",
    "status":"executed_fail_closed",
    "network_used":False,
    "external_scanner_used":False,
    "dynamic_attack_executed":False,
    "baseline_replay_source":"_work/baseline extracted from git object b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df",
    "tests":suites,
    "replays":[
        {"id":"C2_EXISTING_REPLAY","execution_status":"failed_fail_closed","exit_code":EXEC["replays"]["c2"]["exit_code"],"output_created":False,"reason":"missing_local_git_object 054451b1be4f39254d56a1683cc9d1c1b5e55018 under blob:none partial clone; no lazy fetch","stdout_file":"_work/replay_c2.stdout.txt","stderr_file":"_work/replay_c2.stderr.txt"},
        {"id":"C3_EXISTING_REPLAY","execution_status":"failed_fail_closed","exit_code":EXEC["replays"]["c3"]["exit_code"],"output_created":False,"reason":"missing_local_git_object 054451b1be4f39254d56a1683cc9d1c1b5e55018 under blob:none partial clone; no lazy fetch","stdout_file":"_work/replay_c3.stdout.txt","stderr_file":"_work/replay_c3.stderr.txt"},
    ],
    "historical_object_test_observation":{"expected_object_dependent_tests":6,"executed":6,"passed":1,"errors":4,"skipped":1,"skip_reason":"Bound commit parent is absent from supplied component Git store","fail_closed":"skip is not pass; errors are not safe/miss"},
    "metrics":{"precision":None,"recall":None,"false_positive_rate":None,"false_negative_rate":None,"reason":"no independent reliable labels; historical exact replay blocked by absent blobs"},
    "verdict":"candidate/unassessed","validated_vulnerability":0,
}

controls = {
    "schema":"c7-controls-matrix-v2",
    "generated_at":"2026-10-19T00:00:00+08:00",
    "policy":"partial/failed/unexecuted/unknown never become safe or miss",
    "controls":[
        {"control":"parent","object":"830e85b40240677039719fcbf14f721ad3b19050","local_synthetic_control":"candidate semantics implemented","historical_status":"metadata verified; blob/source bytes unavailable","replay_status":"failed_fail_closed","classification":"candidate/unassessed"},
        {"control":"fix","object":"a0e30483ab3e4aead67ecfb5c708489915e447f9","local_synthetic_control":"fixed/zero-candidate semantics implemented","historical_status":"metadata and parent relation verified; blob/source bytes unavailable","replay_status":"failed_fail_closed","classification":"candidate/unassessed"},
        {"control":"safe","object":"a65a2853ccae13da167d9aa4720ab8b11ec16656","local_synthetic_control":"safe/unknown control semantics exercised in local tests","historical_status":"commit unresolved","replay_status":"failed_fail_closed","classification":"unknown; safe is a control role, never verdict"},
        {"control":"unrelated","object":"a65a2853ccae13da167d9aa4720ab8b11ec16656^","local_synthetic_control":"wrong-version/not-admitted semantics exercised in local tests","historical_status":"parent ref unresolved","replay_status":"failed_fail_closed","classification":"unknown; unrelated is a control role, never verdict"},
        {"control":"unknown","object":"c758818dbfd0b146a908d43d21f6ca1706c33783 -> 81ca57487d04ea30cd11c271e86494a4e130f43e","local_synthetic_control":"exception-path and unknown-effect controls exercised in local tests","historical_status":"metadata and parent relation verified; target/dependency blob bytes unavailable","replay_status":"failed_fail_closed","classification":"unknown; runtime effect and CIA unresolved"},
    ],
    "local_control_suites":{"test_detector_cases":"12/12 passed","test_c3_mechanisms":"29/29 passed","test_type_origin":"20/20 passed","test_ir_path":"13/13 passed","test_exception_guard":"10 passed, 2 historical errors","test_parser_owner":"7 passed, 1 source-file error"},
    "all_historical_controls_executed":False,
    "validated_vulnerability":0,
}

next_manifest = {
    "schema":"c7-next-object-manifest-v2",
    "generated_at":"2026-10-19T00:00:00+08:00",
    "policy":"local object supply only; no implicit fetch",
    "minimum_missing_object_list":[
        {"kind":"commit+tree+blob+source_sha256","object":"a65a2853ccae13da167d9aa4720ab8b11ec16656","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","blob":"68fb3b0adc4f9062889a861be51b7be90362e37a","sha256":"76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c"},
        {"kind":"commit+tree+blob+source_sha256","object":"a65a2853ccae13da167d9aa4720ab8b11ec16656^","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","resolution":"full parent commit and exact blob/hash required"},
        {"kind":"blob","object":"054451b1be4f39254d56a1683cc9d1c1b5e55018","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","sha256":"847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422"},
        {"kind":"blob","object":"95f54f2875f401afe3167c62f8c1e7799782be8c","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","sha256":"8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e"},
        {"kind":"blob","object":"757b8d050d306d349822600deacb295c7a54245e","path":"ecmascript/compiler/new_object_stub_builder.cpp","sha256":"3fd7e99e957fb5b7793cb7c36c01b370208c05645aa93551da6abeecaf2e7198"},
        {"kind":"blob","object":"857ad416bc102fcd5d462e9702d2ba7c51f29b6d","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","sha256":"984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9"},
        {"kind":"blob","object":"3b9de9d915d767d7a67316145451da2446162884","path":"ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp","sha256":"4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0"},
        {"kind":"blob","object":"05dda56de74949f07a241942be6465beaf94b52a","path":"ecmascript/compiler/new_object_stub_builder.cpp","sha256":"c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e"},
    ],
    "verification_commands":["git cat-file -e <blob>^{blob}","git ls-tree <commit> -- <path>","sha256(git cat-file blob <blob>)"],
    "network_supplement_required":False,
    "next_action":"supply a local complete object store/alternates or local blob pack, then rerun _work/run_c7_replay.py; do not fetch",
}

readme = """# C7-REPLAY 历史对象审计与 replay 结果

日期：2026-10-19（Asia/Shanghai）

## 已执行事实

- 固定基线 `b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df` 已从本地 Git object 解包到 `_work/baseline/`，未 checkout、fetch 或修改上游对象库。
- Ark store `E:/网安/_oh_targets/arkcompiler_ets_runtime` 为 `blob:none` partial clone。`GIT_NO_LAZY_FETCH=1` 下确认四个历史 commit/tree 与路径 blob OID 链，但所有所需 blob 字节均不可本地读取，因此 source SHA 无法核验。
- `a65a2853ccae13da167d9aa4720ab8b11ec16656` 与 `a65a2853^` 未能解析；safe/unrelated 只保留控制角色和 fail-closed 缺口，不写 safe/miss。
- 历史测试实际执行 6 项：1 passed、4 errors、1 skipped；skip 原因是 bound commit parent 缺失。`test_exception_guard` 12 项中 10 passed、2 historical errors。C2/C3 replay 均因 `054451b1...` blob 缺失而 fail-closed。
- 本地合成控制通过：`test_detector_cases` 12/12、`test_c3_mechanisms` 29/29、`test_type_origin` 20/20、`test_ir_path` 13/13。`test_parser_owner` 7 passed、1 个源文件错误。合成控制不替代历史对象证据。

## 结论

所有历史候选仍 `candidate/unassessed`，`validated_vulnerability=0`。partial、failed、skipped、unknown 均不写 safe、miss、zero FP 或 zero FN。产品入口、权限、触发、CIA、产品构建和 CVE 映射仍未闭合。

## 可复现命令

```powershell
$env:OHSCANNER_ARK_REPO = 'E:\\网安\\_oh_targets\\arkcompiler_ets_runtime'
$env:OHSCANNER_PYDEPS = 'E:\\网安\\_runtime\\ohscanner-pydeps'
$env:GIT_NO_LAZY_FETCH = '1'
$env:GIT_ALLOW_PROTOCOL = ''
python _work/run_c7_replay.py
python _work/extract_baseline.py _work/baseline_b011.zip _work/baseline
```

随后可在 `_work/baseline/` 内运行 `tests.detectors.ark_runtime.*` 与 C2/C3 `replay.py`。完整命令、exit code 和日志见 `replay_results.json` 与 `_work/*.stderr.txt`。

## 交付文件

`object_inventory.json`、`replay_results.json`、`controls_matrix.json`、`next_object_manifest.json` 均为 JSON；本目录只读研究输出，不 commit/push/merge/PR。
"""

for name, data in (("object_inventory.json", inventory), ("replay_results.json", replays), ("controls_matrix.json", controls), ("next_object_manifest.json", next_manifest)):
    (DIR / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
(DIR / "README.md").write_text(readme, encoding="utf-8")
print(json.dumps({"suites": suites, "object_summary": inventory["summary"]}, indent=2))