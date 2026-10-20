# D83：已披露漏洞静态候选质量修复（2026-10-20）

基线 `6cbec8428a5c6c1ca86aa27b62ddc4ff2d06159f`，分支
`codex/d83-known-cve-quality-20261020`。本轮交付规则、回归和真实源码重放；不实现第二层大模型。

## 复用与改动

先逐文件比较并选择性迁入 `codex/d68-pasteboard-observation-bounds-20261023`
固定提交 `3da049887999bd3cacb3d48da9ffa7baefa18ac5` 的 `known_cves.py` 0.19.10、
两个 known-CVE 测试文件、四个 Pasteboard corpus 控制。未合并旧分支的任务或证据报告。
这保留了已测试的插入点定位、同容器/插入前/退出语义/布尔返回值配额控制，以及有界权限观察。
权限检查的身份、语义和支配关系无法证明时保持 `permission_guard=unknown`，不据名称抑制候选。

新发现并修复一个具体漏候选：配额 guard 只按大括号判断顶层，错误地把下面内层 guard
当作所有插入路径都执行的检查：

```cpp
void AddPasteboardChangedObserver(Observer *observer) {
    auto it = observerMap_.find(GetUserId());
    auto observers = it->second;
    if (is_privileged)
        if (observers->size() >= MAX_OBSERVERS_PER_PID) return;
    observers->insert(observer);
}
```

直接配额检查与配额 helper 两条路径现在均检查无大括号条件上下文；
T83 独立反馈的无大括号 else guard 也一并修复，包括 then 分支使用大括号的形态。
同时修正现有上下文观察器遗漏 `body_start == position` 的边界。
版本为 0.19.11；未增加公共 schema、catalog 或敏感流实现变更。

## 开发—测试闭环

- 新回归先在迁入的 0.19.10 上执行：direct/helper × `if`/`while`/`for` 六个反例全部失败（错误返回零候选）。
- 修复后原六个反例及 T83 反馈的四个 else 反例均保留 `CVE-2025-25212`。合法独立顶层 guard，以及一个已结束的 if 或完整 if-else 之后的 guard，仍然安静。
- 正例、修复、安全、无关和 partial/unknown 控制保留。manifest 的当前控制字节哈希和候选数量同步，并增加可发现再次漂移的回归。
- focused suite：35 个测试通过。`git diff --check` 通过。

```powershell
D:\openHarmonyScanner\.venv-c-line\Scripts\python.exe -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus -q
```

测试命令使用的环境实际为 Python 3.13.9。没有把环境目录名解释为 Python 3.10。

## 真实 Pasteboard 源码重放

从完整本地对象库 `D:\openHarmonyScanner\tmp\d68-pasteboard-source` 读取固定 Git 对象，
不 checkout、不构建或运行目标代码。提交 `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`，
tree `e374a0d61c9ec664ddd29fc17002797828c480ee`，snapshot
`b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`。

源码范围 68 个文件：67 C/C++ 和一个 TypeScript 声明；67 个适用文件的 SHA-256 映射与 D68 记录逐项一致。
当前解析 60 complete / 8 partial；本次 JS/TS grammar 可用，D68 环境中不可用，因此不能把这一个声明的解析状态变化当成规则覆盖改善。
detector 仍是 67 partial、run `blocked`，这是覆盖状态；本轮开发成果和源码报告可交付。

| 候选 | 源码位置 | 对 0.18.0 的差异 |
|---|---|---|
| CVE-2025-25212 | `services/core/src/pasteboard_service.cpp:241` | 从函数起点 222 精确到插入点 241；源码未变 |
| CVE-2025-27247 | `services/zidl/src/pasteboard_service_stub.cpp:41` | 候选保留，增加显式 unknown 权限义务和有界观察 |

三版本 0.18.0 / 0.19.10 / 0.19.11 在相同真实源码上均产生这两个候选。
两个文件 SHA-256 分别为 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`
和 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`。
当前重放的权限观察是 `absent`，其语义状态仍是 unknown。

可复现重放（在本 worktree 下，将下列 Python 传入同一解释器）：

```python
from pathlib import Path
from src.ohscanner.execution import run_fixed_commit_scan
out = Path("research/data_sensitive/D83_PASTEBOARD_REPLAY_20261020")
run_fixed_commit_scan(
    Path(r"D:\openHarmonyScanner\tmp\d68-pasteboard-source"),
    "openharmony/miscservices_pasteboard",
    "dd22c7cb5e5f207a6c38c50f45b7369ee8575840", (".",),
    ("ohscanner.known_disclosed_cves",), out.with_suffix(".json"), out.with_suffix(".md"),
)
```

机器报告为 `D83_PASTEBOARD_REPLAY_20261020.json`，配套源码报告为同名 `.md`；
三版本与十个反例的逐项候选差异为 `D83_CANDIDATE_DELTA_20261020.json`。
fixed/safe 控制中 quota 候选保持消失；权限候选从旧版零个恢复为一个 unknown 待复核，不能称其已证明存在漏洞或已证明误报。

## 后续与边界

静态层负责尽可能保留有证据的候选和明确的源码上下文。第二层可进一步判断权限来源、跨函数配额、生命周期与可达性，本轮不实现该层。
配额判断仍是有界词法模型，未证明宏展开、别名重绑定、异常处理、复杂跳转或跨函数生命周期。
产品部署、可利用性和影响仍 unknown；没有报告正式 Precision/Recall，也没有把豁免计为通过。
后续只针对具体反例开展修复，不重复审计这些 unchanged unknown。
