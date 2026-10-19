from dataclasses import asdict
from difflib import unified_diff
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent
FIXTURES = ROOT / "tests/detectors/ark_runtime/fixtures/c10_gap_rules"
model = json.loads((OUT / "production-adapter-replay.json").read_text(encoding="utf-8"))

# Source hashes for the exact implementation and controls added by this line.
source_paths = [
    ROOT / "src/ohscanner/detectors/ark_runtime/model.py",
    ROOT / "src/ohscanner/detectors/ark_runtime/detector.py",
    ROOT / "src/ohscanner/detectors/ark_runtime/size_overflow.py",
    ROOT / "src/ohscanner/detectors/ark_runtime/runtime_exception.py",
    ROOT / "tests/detectors/ark_runtime/test_c10_ark_gap_rules.py",
] + sorted(FIXTURES.glob("*.cpp"))
source_hashes = []
for path in source_paths:
    raw = path.read_bytes()
    source_hashes.append({
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode("ascii") + bytes((0)) + raw).hexdigest(),
    })
(OUT / "source-hashes.json").write_text(json.dumps({
    "baseline_commit": "09ba5aba03c7c7d6787bace349b8fc0a6b0a5457",
    "baseline_tree": "d15b91627c94d9c3043d7d58d47fcf9af7e42454",
    "working_tree_preserved_dirty": True,
    "files": source_hashes,
}, ensure_ascii=False, indent=2), encoding="utf-8")

# Five-control matrix for each mechanism.
def result_for(name):
    text = (FIXTURES / name).read_text(encoding="utf-8")
    from src.parser.ast import parse_source
    from src.ohscanner.contracts import SourceUnit
    from src.ohscanner.detectors.ark_runtime.runtime_exception import analyze_native_inline_exception_propagation
    from src.ohscanner.detectors.ark_runtime.size_overflow import index_bounds_result, length_narrowing_result
    parsed = parse_source(text, "cpp")
    unit = SourceUnit("ecmascript/" + name, "cpp", text, sha256(text.encode()).hexdigest(),
                      parsed.parse_status, ())
    if name.startswith("ia_"):
        r = analyze_native_inline_exception_propagation(unit)
    elif name.startswith("length_"):
        r = length_narrowing_result(unit, "control-matrix")
    else:
        r = index_bounds_result(unit, "control-matrix")
    return unit, r

specs = [
    ("IAO7GO", "ark.runtime.native-inline-pending-exception-propagation", [
        ("positive", "ia_positive.cpp", "candidate"),
        ("fixed", "ia_fixed.cpp", "fixed_control_no_same_root_candidate_not_safety"),
        ("safe", "ia_safe.cpp", "safe_local_control_not_security_verdict"),
        ("unrelated", "ia_unrelated.cpp", "not_analyzed"),
        ("unknown", "ia_unknown.cpp", "explicit_unknown"),
    ]),
    ("I7W51D", "ark.runtime.typedarray-length-signed-to-unsigned-narrowing", [
        ("positive", "length_positive.cpp", "candidate"),
        ("fixed", "length_fixed.cpp", "fixed_control_no_same_root_candidate_rangeerror_is_not_safety"),
        ("safe", "length_safe.cpp", "safe_local_control_not_security_verdict"),
        ("unrelated", "length_unrelated.cpp", "not_analyzed"),
        ("unknown", "length_unknown.cpp", "explicit_unknown"),
    ]),
    ("IB8BCA", "ark.runtime.dataview-index-width-bounds", [
        ("positive", "index_positive.cpp", "candidate"),
        ("fixed", "index_fixed.cpp", "fixed_control_explicit_unknown_not_safety"),
        ("safe", "index_safe.cpp", "safe_local_control_not_security_verdict"),
        ("unrelated", "index_unrelated.cpp", "not_analyzed"),
        ("unknown", "index_unknown.cpp", "explicit_unknown"),
    ]),
]
controls = []
for finding_id, rule_id, rows in specs:
    for kind, filename, expected in rows:
        unit, result = result_for(filename)
        candidate_count = sum(1 for x in result.observations if x.kind == "candidate")
        unknown_count = sum(1 for x in result.observations if x.kind == "unknown")
        if expected == "candidate":
            ok = candidate_count == 1
        elif expected == "not_analyzed":
            ok = result.file_outcome == "not_analyzed" and candidate_count == 0
        elif expected == "explicit_unknown":
            ok = result.file_outcome == "partial" and candidate_count == 0 and bool(result.limitations)
        else:
            ok = candidate_count == 0
        controls.append({
            "finding_id": finding_id,
            "control_id": f"C10-{finding_id}-{kind.upper()}-001",
            "control_kind": kind,
            "fixture": "tests/detectors/ark_runtime/fixtures/c10_gap_rules/" + filename,
            "source_sha256": unit.sha256,
            "rule_id": rule_id,
            "rule_version": "1.0.0",
            "expected_disposition": expected,
            "actual": {
                "candidate_count": candidate_count,
                "unknown_count": unknown_count,
                "file_outcome": result.file_outcome,
                "status": result.status,
                "limitations": list(result.limitations),
            },
            "assertion_status": "pass" if ok else "fail",
            "security_claim": "not_asserted",
        })
(OUT / "control-matrix.json").write_text(json.dumps({
    "controls": controls,
    "all_assertions_pass": all(x["assertion_status"] == "pass" for x in controls),
    "classification_rule": "fixed and safe controls prove only local rule boundaries; RangeError, zero findings and fixed behavior are never product safety",
}, ensure_ascii=False, indent=2), encoding="utf-8")

# Reconstruct the preserved pre-gap dirty baselines for the two untracked modules.
runtime_current = (ROOT / "src/ohscanner/detectors/ark_runtime/runtime_exception.py").read_text(encoding="utf-8")
c10_patch = (ROOT / "research/experiments/ark_runtime/c10_ark_latest_semantics_20261019/minimal.patch").read_text(encoding="utf-8")
marker = "+++ b/src/ohscanner/detectors/ark_runtime/runtime_exception.py\n"
chunk = c10_patch.split(marker, 1)[1]
lines = chunk.splitlines(keepends=True)
pre_runtime_lines = []
started = False
for line in lines:
    if line.startswith("@@"):
        started = True
        continue
    if started and line.startswith("diff --git "):
        break
    if started and line.startswith("+"):
        pre_runtime_lines.append(line[1:])
pre_runtime = "".join(pre_runtime_lines)
size_current = (ROOT / "src/ohscanner/detectors/ark_runtime/size_overflow.py").read_text(encoding="utf-8")
pre_size = size_current.split("\n\n\ndef _bounded_function_regions", 1)[0] + "\n"

def diff_text(path, before, after, new_file=False):
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    if new_file:
        body = list(unified_diff([], after_lines, fromfile="/dev/null", tofile="b/" + path, n=3))
        header = [f"diff --git a/{path} b/{path}\n", "new file mode 100644\n"] + body
    else:
        body = list(unified_diff(before_lines, after_lines, fromfile="a/" + path, tofile="b/" + path, n=3))
        header = [f"diff --git a/{path} b/{path}\n"] + body
    return "".join(header)

parts = []
for path in ("src/ohscanner/detectors/ark_runtime/model.py", "src/ohscanner/detectors/ark_runtime/detector.py"):
    before = subprocess.check_output(["git", "show", "HEAD:" + path], cwd=ROOT).decode("utf-8")
    after = (ROOT / path).read_text(encoding="utf-8")
    parts.append(diff_text(path, before, after))
parts.append(diff_text("src/ohscanner/detectors/ark_runtime/size_overflow.py", pre_size, size_current))
parts.append(diff_text("src/ohscanner/detectors/ark_runtime/runtime_exception.py", pre_runtime, runtime_current))
for path in ["tests/detectors/ark_runtime/test_c10_ark_gap_rules.py"] + [
    "tests/detectors/ark_runtime/fixtures/c10_gap_rules/" + p.name for p in sorted(FIXTURES.glob("*.cpp"))
]:
    parts.append(diff_text(path, "", (ROOT / path).read_text(encoding="utf-8"), new_file=True))
patch = "".join(parts)
(OUT / "minimal.patch").write_text(patch, encoding="utf-8", newline="")
(OUT / "minimal.patch.sha256").write_text(sha256(patch.encode()).hexdigest() + "  minimal.patch\n", encoding="utf-8")

# Final disposition and limitations.
replay = json.loads((OUT / "production-adapter-replay.json").read_text(encoding="utf-8"))
(OUT / "README.md").write_text(f"""# C10-ARK-GAP-RULES

基线：`09ba5aba03c7c7d6787bace349b8fc0a6b0a5457` / tree `d15b91627c94d9c3043d7d58d47fcf9af7e42454`。保留既有 dirty repair、known-cve source identity 修复和 C10 Ark semantics patch；未执行 commit/push/merge/reset/fetch。

## Finding disposition

| Finding | 稳定规则 | 生产适配器固定对象复放 | 最终 disposition |
|---|---|---|---|
| IAO7GO | `ark.runtime.native-inline-pending-exception-propagation` v1.0.0 | parent 1 candidate → fixed 0 | `candidate/unassessed`；selector 已适用，不再静默 0 |
| I7W51D | `ark.runtime.typedarray-length-signed-to-unsigned-narrowing` v1.0.0 | parent 1 candidate → fixed 0 | `candidate/unassessed`；RangeError/固定转换不是安全结论 |
| IB8BCA | `ark.runtime.dataview-index-width-bounds` v1.0.0 | 三个 parent 文件共 3 candidates → fixed 0 | `candidate/unassessed`；fixed 侧仍显式 partial/unknown |

生产复放总数：IAO7GO `{replay['summary']['IAO7GO']['vulnerable_candidate_count']}→{replay['summary']['IAO7GO']['fixed_candidate_count']}`，I7W51D `{replay['summary']['I7W51D']['vulnerable_candidate_count']}→{replay['summary']['I7W51D']['fixed_candidate_count']}`，IB8BCA `{replay['summary']['IB8BCA']['vulnerable_candidate_count']}→{replay['summary']['IB8BCA']['fixed_candidate_count']}`。所有命中仍受完整产品构建、入口/权限、攻击者控制、触发条件、CIA 影响、动态 PoC 和修复产品重验义务约束。

## 验证

| 检查 | 结果 |
|---|---|
| Ark discover | 170 pass，3 skipped，0 fail/error |
| gap-focused | 19 pass，0 skipped，0 fail/error |
| known_cves | 21 pass，0 skipped，0 fail/error |
| compileall src tests | exit 0 |
| git diff --check | exit 0 |

精确 argv、环境摘要、exit code、stdout/stderr 路径与 SHA-256 见 `check-records-win-final2.json`。第一次 compileall 因长路径 pycache 失败的记录保存在 `check-records-win-attempt1.json`，没有覆盖。

## 交付物

- `production-adapter-replay.json`：固定 Git 对象经生产 Detector 的 source-bound 复放。
- `source-replay.json`：规则层固定对象复放和 identity 记录。
- `control-matrix.json`：每机制 positive/fixed/safe/unrelated/unknown 五类控制。
- `minimal.patch` 与 `minimal.patch.sha256`：只包含本线 gap 语义、测试和 fixtures；不覆盖既有 dirty 状态。
- `source-hashes.json`、`artifact-hashes.json`、`limitations.md`、`sustained-goals.md`。
""", encoding="utf-8")

(OUT / "limitations.md").write_text("""# 限制与证据边界

1. 三个规则均为 bounded local syntax/dataflow shape，不证明完整 C++ 类型、宏展开、CFG、别名、跨函数 summary、并发、ownership、真实入口或攻击者控制。
2. 所有命中保持 `candidate/unassessed`。没有产品构建绑定、权限边界、触发条件、具体 CIA 影响、隔离动态 PoC 或修复产品重验，不升级 confirmed/reportable。
3. I7W51D 的 `uint32_t`/RangeError 修复控制只证明同根因静态候选消失，不证明内存安全或产品安全。
4. IB8BCA 的 fixed 输入仍产生显式 `index_width_bounds_arithmetic_not_fully_proven` / unknown；0 findings 不写 safe。
5. safe 控制只是局部规则边界，不是安全 verdict；unrelated 是 not_analyzed；unknown/partial/blocked 不计通过。
6. Ark discover 的 3 个 skip 需要 pinned historical Ark Git stores，未计通过。没有独立可靠标注集，不计算 Precision/Recall，不声称零 FP/FN。
7. Windows Git 子进程 stdout 存在流哈希与 resolved Git blob OID 分离现象；生产适配器以共享事实中的 verified Git OID 加源 SHA-256 绑定，不把流哈希当 blob identity。
""", encoding="utf-8")

(OUT / "sustained-goals.md").write_text("""# G10-AR-1..4 持续执行目标

- **G10-AR-1 固定身份与适用性：已完成。** 固定 IAO7GO/I7W51D/IB8BCA parent/fixed commit、tree-role blob/source hash，`native_inline_lowering.cpp` 必须被 selector 适用。
- **G10-AR-2 规则与五类控制：已完成。** 三个稳定 rule ID/v1.0.0 均有 positive/fixed/safe/unrelated/unknown；RangeError、fixed、0 findings 均不得转 safe。
- **G10-AR-3 语义增强：持续。** 下一片补跨函数 effect summary、精确 CFG dominance、alias/loop、整数区间与 DataView/Atomics 溢出证明；无法证明保持 unknown。
- **G10-AR-4 独立与产品闭环：持续。** 冻结版本后做独立盲 holdout；对满足入口/权限/触发/CIA 门槛的候选执行授权隔离 PoC、修复和重验，不攻击线上服务。

每轮只推进一个最小可验证切片，保留 exact commands、source identity、patch、controls、pass/fail/skip/block、限制和下一最小切片。
""", encoding="utf-8")

# Artifact hashes are generated after the documents above exist.
artifact_paths = sorted(
    p for p in OUT.rglob("*")
    if p.is_file() and p.name != "artifact-hashes.json" and not any(".pycache" in part for part in p.parts)
)
(OUT / "artifact-hashes.json").write_text(json.dumps({
    "files": [{"path": p.relative_to(OUT).as_posix(), "bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}
              for p in artifact_paths]
}, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps({"control_matrix_pass": all(x["assertion_status"] == "pass" for x in controls),
                  "patch_sha256": sha256(patch.encode()).hexdigest(),
                  "artifacts": [p.name for p in artifact_paths]}, ensure_ascii=False, indent=2))
