# C++ IPC 权限源码分析第二轮验证

日期：2026-10-09。目录：D:\ICP。主线 main 仍为 dcd9629f50a34545d75abc92c0a16c79723197db，src/ohscanner 尚未落地。

## 本轮进展
新增 cpp_permission.py，使用 Tree-sitter 解析实际 C++ 源码、定位已核验入口函数、提取调用点和直接布尔权限条件；通过显式 source SHA-256 和精确仓库/提交/profile/函数绑定输入。入口资格及权限义务来自研究者模型，不是自动推断的平台安全政策。
支持函数内顺序语句、if/else、return 和按调用者/权限/资源绑定的授权状态；输出仅 syntax 候选及分支行号。任意 if 两边均做语法层过近似，不声称条件可满足性、真实数据流或 guard 支配关系。
未知调用、宏、循环/goto、lambda、赋值、RAII、保存检查结果及部分解析会整体降级 unknown，并撤回不完整候选。

## 验证
Windows Python 3.10.11，60项回归全部通过；6个C++源码fixture复放与先前7个人工图fixture均为design/regression，不是独立holdout。pip check通过。
读取固定MMI源码三个函数并提取39个调用点。这证明能解析和整理源码结构，不证明完整编译上下文或漏洞。三个函数均unknown，未发现/确认真实漏洞。
本地tree-sitter 0.26.0在连续AST测试时出现Windows原生崩溃/节点异常；保留失败日志，切换0.25.2后回归通过。requirements锁定tree-sitter==0.25.2及tree-sitter-cpp==0.23.4；不修改主线依赖。

## 每项输入的真实结果

|来源|函数/样例|解析|评估|调用点|
|---|---|---|---|---|
|synthetic_design_fixture|Handle / fixtures/bypass_branch.cpp|complete|candidate|2|
|synthetic_design_fixture|Handle / fixtures/denial_fallthrough.cpp|complete|candidate|2|
|synthetic_design_fixture|Handle / fixtures/guarded.cpp|complete|no_uncovered_sink_in_supported_syntax|2|
|synthetic_design_fixture|Handle / fixtures/macro_unknown.cpp|complete|unknown|1|
|synthetic_design_fixture|Handle / fixtures/unguarded.cpp|complete|candidate|1|
|synthetic_design_fixture|Handle / fixtures/unreachable.cpp|complete|no_uncovered_sink_in_supported_syntax|1|
|fixed_mmi_source|MultimodalInputConnectStub::StubHandleAllocSocketFd / service/connect_manager/src/multimodal_input_connect_stub.cpp|partial|unknown|16|
|fixed_mmi_source|MultimodalInputConnectStub::StubAddInputEventFilter / service/connect_manager/src/multimodal_input_connect_stub.cpp|partial|unknown|10|
|fixed_mmi_source|MultimodalInputConnectStub::StubAddInputHandler / service/connect_manager/src/multimodal_input_connect_stub.cpp|partial|unknown|13|

## 真实源码限制

### MultimodalInputConnectStub::StubHandleAllocSocketFd
源码SHA-256：0f362a1cc13689c14f3826947f467b3a1966dfac229f0afbb1aa649922ba2d90
评估：unknown；运行验证not_run；validated_vulnerability=0。
直接guard结构观察：[]
限制：Syntactic path over-approximation, not path feasibility/type/IPC reachability proof.; Exact API models supplied by researcher; no inferred platform authorization policy.; Function-local subset only; no macro expansion, aliases, external CFG or cross-language flow.; Incomplete parse, unverified entry or unreviewed sink authorization obligation.

### MultimodalInputConnectStub::StubAddInputEventFilter
源码SHA-256：0f362a1cc13689c14f3826947f467b3a1966dfac229f0afbb1aa649922ba2d90
评估：unknown；运行验证not_run；validated_vulnerability=0。
直接guard结构观察：[{"line": 134, "callee": "PerHelper->CheckPermission", "condition_true_means_granted": false, "subject": "ipc_caller", "permission": "unreviewed_obligation", "resource": "AddInputEventFilter", "origin": "AST and explicit researcher API model"}]
限制：Syntactic path over-approximation, not path feasibility/type/IPC reachability proof.; Exact API models supplied by researcher; no inferred platform authorization policy.; Function-local subset only; no macro expansion, aliases, external CFG or cross-language flow.; Incomplete parse, unverified entry or unreviewed sink authorization obligation.

### MultimodalInputConnectStub::StubAddInputHandler
源码SHA-256：0f362a1cc13689c14f3826947f467b3a1966dfac229f0afbb1aa649922ba2d90
评估：unknown；运行验证not_run；validated_vulnerability=0。
直接guard结构观察：[]
限制：Syntactic path over-approximation, not path feasibility/type/IPC reachability proof.; Exact API models supplied by researcher; no inferred platform authorization policy.; Function-local subset only; no macro expansion, aliases, external CFG or cross-language flow.; Incomplete parse, unverified entry or unreviewed sink authorization obligation.

## 使用
```powershell
cd D:\ICP
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m research.experiments.interface.replay_cpp_sources
```

源码缓存只在本地忽略目录保留；包内没有第三方源码，接收者仍可复放自建源码。缓存缺失时MMI结果明确blocked/unknown。

## 下一步接入要求
负责人冻结Detector v1后，按批准接口桥接；模型所需事实为固定源码、真实入口映射、布尔guard语义、调用者/权限/资源义务与解析覆盖。
必须补足宏/类型/平台身份上下文和真实权限需求，再做受限helper/一跳分析；不能把unknown改成miss或漏洞，也不能通过放宽模型制造告警。
未运行WSL、远端CI、外部工具对照、独立holdout或真实修复对实验；不声称生产检测能力已完成。未push。
