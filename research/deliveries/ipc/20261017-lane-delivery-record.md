# 最小交付记录 — lanes.ipc

> 填充自 `research/coordination/parallel-20261017/DELIVERY_TEMPLATE.md`（模板本身未改动）。

## lane / branch / base full SHA / head full SHA

- lane `lanes.ipc`；branch `work/ipc-20261017`
- base `6a41dc9b1aa030158e09be6241e2b14341f9256d`（integration base，本线**未** rebase）
- head：**本记录所在提交**。本线在本 base 上共 10 个提交，按提交信息依次是
  "per-rule controls for the six families, and an 18-component measurement"（`bb24978`）→
  "census the shapes the six silent rules key on"（`09f49d7`）→
  "why the six silent rules are silent, and 12 more components"（`46d4f64`）→
  "measure the interpreter's own identity attribution, and correct two mechanisms"（`df7bd8e`）→
  "measure why caller-class never emitted"（`400751e`）→
  "measure the coverage ceiling instead of assuming it"（`24c7f6c`）→
  "widen the corpus by mechanism, and measure the loudest rule"（`629f047`）→
  "screen every emitting rule with the same modes, and read every flagged row"（`4214a4f`）→
  "fill the three family directories and cover the engine cases on both sides"（`50e776a`）→
  "measure whether the five engine cases occur in real code, and what the reports keep"（本提交）——
  本提交的确切 SHA 会随 `--amend` 变化，故此处不写死；**未 push、未开 PR、未标 Ready、未 merge**
- worktree `/home/audit/ohscanner/worktrees/parallel-ipc-20261017`

## 选择性迁入来源提交、文件与依赖

**本次没有迁入来源代码。** 检测器一行未改。来源树
`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b` @
`635b3e0449c552f0ccc25118850d245962845568`（`0.8.0` / `oh-ipc-2026.10-v6`）
只作**只读**运行与逐行核对，用于生成交付项 3 的实测数字与逐条触发链的 `file:line`。

**本线反而依赖 worktree 里另一会话尚未提交的 v0.8 import**（`src/ohscanner/detectors/interface/`
的 `families/`、`models.py`、`analysis.py`、`entry_index.py`、`detector.py`，
写入时间 02:57:44，`git status` 为 `M`/`??`）。本线新增的夹具与测试只依赖
`models.py` 的**具名常量表**与 `analysis.py` 的 emit 点；若该 import 被回退或改写，
夹具与测试会随之失败。这是依赖，不是本单元自身的缺陷。

## 问题触发条件、改动后行为

- **触发条件**：11 条目录规则里 3 条（`ipc.auth.caller-class`、`ipc.auth.identity-domain`、
  `ipc.parcel.position-underflow`）**没有任何正例控制**，即从未被证明能够触发；
  3 个家族（AUTH-01 / AUTH-03 / DATA-01）没有 `safe` 控制。
- **改动后**：11/11 规则有正例、6/6 家族有 positive+fixed+safe，且该不变量由
  `tests/test_ipc_family_depth.py` 机器校验（逐规则、逐家族，不是总数）。
- **同时量化了真实代码上的落差**：30 个组件 / 2.44M 行里**仍然只有 5 条规则**命中过；
  AUTH-01 占 92/166 条候选，AUTH-03 仅 2 条，DATA-01 为 0。
  （第一批 18 组件时是 100 条、AUTH-01 54 条。两次批量的 argv 与检测器完全相同。）

## 修改文件、scope check 命令与真实输出

新增（全部只增不改检测逻辑；提交 `400751e` 新增其中四个条目，本提交再增末尾四个）：

```text
research/deliveries/ipc/20261017-v080-dependency-inventory.md
research/deliveries/ipc/20261017-six-family-depth-unit.md
research/deliveries/ipc/20261017-six-family-component-measurement.md
research/deliveries/ipc/20261017-shape-census-silent-rules.md
research/deliveries/ipc/20261017-data01-mechanism.md
research/deliveries/ipc/20261017-shape-corpus-and-auth03-identity.md
research/deliveries/ipc/20261017-interpreter-attribution-auth03.md
research/deliveries/ipc/20261017-caller-class-walk-coverage.md
research/deliveries/ipc/20261017-coverage-ceiling-measured.md
research/deliveries/ipc/20261017-widen-corpus-and-precision.md  (交付项 10)
research/deliveries/ipc/20261017-rule-precision-screen.md      (交付项 11)
research/deliveries/ipc/20261017-lane-delivery-record.md      (本文件)
research/evidence/interface/ipc/component_audit_20261017/     (components.json, index.json, 18×manifest)
research/evidence/interface/ipc/component_audit_shape_20261017/ (components.json, index.json, 12×manifest)
research/evidence/interface/ipc/component_audit_bline_20261017/ (components.json, index.json, 12×manifest)
research/evidence/interface/ipc/hitrace_guard_pair_20261017/  (pair.json)
research/evidence/interface/ipc/auth03_identity_probe_20261017/ (probe.json, interpreter_attribution.json)
research/evidence/interface/ipc/auth01_precision_probe_20261017/ (precision_probe.json/.md, relay_guard_cause.json)
research/evidence/interface/ipc/copy_range_counterfactual_20261017/ (counterfactual.json, patch.diff,
                                                                   patched_analysis.sha256)
research/evidence/interface/ipc/caller_class_walk_20261017/   (caller_class_walk.json)
research/evidence/interface/ipc/rule_precision_screen_20261017/ (rule_precision_screen.json)
research/evidence/interface/ipc/ceiling_20261017/             (ceiling_yield.json, roots/6×json)
research/deliveries/ipc/silent_rule_shape_census.py             (只读，形状取自 IpcPolicy)
research/deliveries/ipc/widen_shape_census.py                   (只读，全语料形状普查，多语料同法可比)
research/deliveries/ipc/auth01_precision_probe.py               (只读，筛查 + pinned-blob 摘录 + relay_guard 六出口实测)
research/deliveries/ipc/rule_precision_screen.py                (只读，同一套模式套到全部 6 条会响的规则 + path 形状普查)
research/deliveries/ipc/copy_range_counterfactual.py            (只读，副本打补丁 + 全语料附带影响比对)
research/deliveries/ipc/copy_range_arg_classes.py               (只读，拷贝长度实参分类)
research/deliveries/ipc/permission_arg_classes.py               (只读，授权谓词实参分类)
research/deliveries/ipc/interpreter_arg_attribution.py          (只读，把探针记录汇成证据 JSON)
research/deliveries/ipc/caller_class_walk.py                    (只读，三种读数汇总)
research/deliveries/ipc/ceiling_yield.py                        (只读，多口径候选增量汇总)
research/deliveries/ipc/probe_site/sitecustomize.py             (只读测量仪，PYTHONPATH 注入，不改检测器)
research/deliveries/ipc/root_probe_site/sitecustomize.py        (只读测量仪，回答"走查跑没跑")
research/deliveries/ipc/ceiling_probe_site/sitecustomize.py     (只读测量仪，只改写入口根集合)
research/methods/interface/IPC_METHOD_CARD.md                  (仅新增两节，并在旧节内标注一处更正)
tests/fixtures/ipc/auth01/                                     (manifest + 1 cpp)
tests/fixtures/ipc/auth03/                                     (manifest + 5 cpp)
tests/fixtures/ipc/data01/                                     (manifest + 3 cpp)
tests/fixtures/ipc/auth02/                                     (manifest + 6 cpp)   ← 交付项 12
tests/fixtures/ipc/auth04/                                     (manifest + 3 cpp)   ← 交付项 12
tests/fixtures/ipc/cap01/                                      (manifest + 7 cpp)   ← 交付项 12
research/deliveries/ipc/20261017-engine-case-coverage-six-families.md          (交付项 12)
research/deliveries/ipc/family_dir_measurement.py              (只读，按深度单元自己的 helper 复现全部 pin)
research/deliveries/ipc/engine_boundary_probe.py               (只读，§4/§5/§6 三条边界的逐差探针)
tests/test_ipc_family_depth.py                                 (12 → 19 项测试)
research/deliveries/ipc/20261017-engine-case-corpus-census.md  (交付项 13)
research/deliveries/ipc/engine_case_corpus_census.py           (只读，形状×语料×已保存报告×作用域计划四节)
```

```console
$ .venv-web/bin/python scripts/check_change_scope.py \
    --base 6a41dc9b1aa030158e09be6241e2b14341f9256d --lane ipc
  "checked_paths": 165 项
  "violations": []
  exit 0
```

（`checked_paths` 76 → 96 → 100 → 104 → 114 → 138 → **141**：第二批新增 12 份 manifest、两份证据 JSON
与两个只读脚本；第三批新增交付项 7、`interpreter_arg_attribution.py`、`probe_site/sitecustomize.py`
与 `auth03_identity_probe_20261017/interpreter_attribution.json`；第四批（`400751e`）新增
交付项 8、`caller_class_walk.py`、`root_probe_site/sitecustomize.py` 与
`caller_class_walk_20261017/caller_class_walk.json`；第五批新增交付项 9、`ceiling_yield.py`、
`ceiling_probe_site/sitecustomize.py`、`ceiling_20261017/ceiling_yield.json`
与 `ceiling_20261017/roots/` 6 份仪器记录；前一批（交付项 10）新增三份只读脚本、
`component_audit_bline_20261017/` 的 12 份 manifest 与两份汇总 JSON、
`auth01_precision_probe_20261017/` 三份、`copy_range_counterfactual_20261017/` 三份；
本批（交付项 11）新增交付项 11 本身、`rule_precision_screen.py`
与 `rule_precision_screen_20261017/rule_precision_screen.json` 各一份；
本批（交付项 12）新增 `auth02/` `auth04/` `cap01/` 三个家族目录共 16 个夹具 + 3 份 manifest、
交付项 12 本身与两份只读仪器；本批（交付项 13）新增交付项 13 本身与
`engine_case_corpus_census.py` 一份 —— **141 → 163 → 165**。）
`--no-renames` 与策略取自 base 提交，本线**没有**为过检查改过策略。
这份 141 项的清单同时含**三个来源**：本线七个提交新增的文件；并发 import 留在
`src/ohscanner/detectors/interface/**` 与 `tests/**` 的既有脏文件（本线从未 stage 过它们，
见"选择性迁入来源提交"一节）；以及本线的夹具/测试。
三者都落在 `lanes.ipc` 的策略范围内，故 `violations` 为空。）

## 公共接口申请

**本线没有直接改共享面。** 未改 `contracts.py`、`runner.py`、`catalog.py`、`analysis.py`、
`models.py`、`src/report/`、`src/case/`、`src/benchmark/`、`src/evidence/`。
夹具走既有的 `tests/fixtures/ipc/<family>/` 家族目录约定，由**他人**已存在的
`tests/test_ipc_family_matrix.py::FamilyFixtureMatrixTests` 自动接管。

**需要集成人另开请求的五项**（全落在并发 import 正在写的 `analysis.py` / `models.py` /
`detector.py`，本线不抢改；每项都有本线的实测量作依据）：

1. **入口建模 + 跨 TU 一跳**（覆盖缺口，交付项 4/5/7，**收益已由交付项 9 量化**）：
   `caller-class` 71 处、AUTH-03 身份形状 17 处可达性为零，根因是入口根只走同文件、
   IDL 生成的分发器不在源码树。**上界是量出来的，不是估的**：按最紧口径
   （只把 `*Service`/`*Stub` 类里的命中方法补成入口根）在 5 个组件上候选 **46 → 57**
   （`caller-class` +5、`guard-coverage` +3、`auth.missing` +3），客户端口径在
   `security_access_token` 上单组件 `0 → 22`。`ability_ability_runtime` 超时未跑、
   客户端口径只覆盖 1 个组件——两处仍是覆盖缺口，不计入上表。
2. **身份派生谓词建模**（交付项 9 新增，**必须与第 1 项同时做，否则第 1 项净降精度**）：
   交付项 9 逐条读源码后确认，`services/` 侧新增的 5 条 `caller-class`
   **全部落在已经做了 system-app 检查的处理器内部**，而被建模成"敏感调用"的那次调用
   没有一条是本处理器对外暴露的操作——4 条是同进程 manager 调用
   （`privacy_manager_service.cpp:462`、`:503`、`:633`、`accesstoken_manager_service.cpp:936`），
   1 条是**跨服务**的客户端 kit 调用（`hcamera_service.cpp:2621`
   的 `PrivacyKit::SetMutePolicy`，camera 服务在那条语句上是发起方不是被检查方）。
   要让 `state.caller_class` 推得出来，需要建模"实参是调用者 token 的 system-app 位测试"：
   `TokenIDAttributes::IsSystemApp`（`frameworks/common/src/tokenid_attributes.cpp:80`）、
   `TokenIdKit::IsSystemAppByFullTokenID`，以及体内只剩它们的同名包装——
   `IsSystemAppCalling` 被各服务类的**本地同名定义遮蔽**
   （`privacy_manager_service.cpp:877` / `accesstoken_manager_service.cpp:2813`，
   两处体逐字相同），相机用**自由函数** `CheckSystemApp`
   （`camera_util.cpp:463`），而这个名字在 `models.py`/`analysis.py` 里**一次都没出现**。
   同一根因的两种形态（遮蔽 / 未命名）在交付项 9 §3.3。
   **请求的形状要说准**：`caller_role_guards` 只在调用无法在本文件内解析时被查
   （`analysis.py:1306` 的 `if helper is None`），文件自己定义了同名函数就永远走不到那张表
   —— 所以"往表里加两个名字"对本语料**是无操作**。要新增的是一条**评审过的身份派生**：
   `(调用者 full token id & M) == M`，`M` 跨两级 constexpr 折叠为第 32 位
   （`tokenid_attributes.cpp:22/:23/:26-29/:36`）⇒ `system_app`；外加让同名包装的返回值透出来。
   交付项 9 §3.3 与 §9.2 给了三层代码依据。
3. **`caller-class` 的 emit 条件**（**规则语义**，不是覆盖问题）：`analysis.py:1037` 只读
   `state.caller_class`、**不读** `state.auth`。同一站点
   `privacy_manager_service.cpp:462` 上 AUTH-02（条件含 `not self.authorized(...)`，
   `analysis.py:1031`）沉默、AUTH-03 发声——两条 emit 条件之差即证明权限事实已入账、
   角色事实未入。是否把"已被权限检查守住的路径"也算"缺少 caller-class 边界"，
   改法由集成人裁定；本线只把两侧证据摆出来（交付项 9 §3.1、§5）。
4. **机制字段**（交付项 4，**部分已由并发 import 解决，请求已收窄**）：原请求是
   "AUTH-02/03/04、CAP-01、DATA-01 的候选无可断言字段、只能读 `message`"。
   核对当前工作树后这一条**大部分不成立**：并发 import 已给每条 finding 加上
   **按族的机制 CWE**（`families/<family>.py` 声明 `FAMILY`/`TITLE`/`CWE`，
   `detector.py` 里 `candidate_cwe=_CWE[o.family]`，另有 `consequence_cwe`），
   六个族一律有，不再只有 AUTH-01 独有。
   **收窄后剩下的请求**：族内**逐候选**的机制仍不可断言——同一族里是哪种守卫缺失、
   哪条路径穿过去，仍只能读 `message`。交付项 9 的汇总因此仍从 `message` 正则取
   `Entry=`，这一解析已在工具 docstring 与证据 JSON 的 `how_to_read` 里**披露**。
   本线证据由 `0.8.0` 产出、早于该字段，故**不回溯改写**报告去补字段。
5. **`copy_calls` 取参下标**：`ReadRawData`（139 次）/`ReadBuffer`（45 次）的真实长度实参
   在第 0 位，规则当前的 `index=2` 够不着 —— 属规则定义改动（交付项 6 §7）。
6. **AUTH-01 的 `relay_guard` 只认分发器形状的守卫**（交付项 10 §6，**本线实测**）：
   这是**候选最多的那条规则**（103/179）里的体系性误报源。`relay_guard`
   （`analysis.py:1159`）本意是"relayed-to function 就是守卫 ⇒ 此调用点不是未守卫边界"，
   但它的六个出口里有三个只接受**内层分发器**的形状，于是把**谓词助手**当成了未守卫的 handler。
   实测 10 条 `guard_symbol` 误报分布在三个不同出口：
   - `:1182` 要求调用**至少携带一个入口实参** ⇒ 零实参守卫（`CheckPermission()`、
     `IsImeInUse()`、`CheckandDoUnFreeze()`）在**读函数体之前**就被判负（4 条）；
   - `:1199` 只在被调函数顶层找 `if_statement` ⇒ 守卫写成
     `return interfaceToken == GetDescriptor();` 时无 `if` 可找（5 条，samgr/dmsfwk）；
   - `:1225` 要求检查之后跟一个 `switch_statement` ⇒ 形状齐全的纯谓词仍被否（1 条，
     `CheckCurrentDescriptor`：`if` 有、mismatch 分支也确实 `return`，只在出口 6 被卡）。
   三项互相独立，**名字表加名字对任何一项都不是修复**（出口 2 发生在读体之前，
   出口 3 是形状而非名字，出口 6 是"谓词 vs 分发器"的建模混淆）。
   本线只给成因与实测分布，**未改检测器**；改法由集成人裁定。

另有一项**数据面**请求与一项**语料面**建议：共享 `tests/fixtures/ipc/manifest.json` 的
`account_role_authorized_fixed` 行（见"下一项"第 4 条）；以及按**文件语言**而非仓库名挑语料
—— `applications_permission_manager` 是 ArkTS，74 个选中文件 0 个被分析，因为
`detector.py:74` 声明的 `supported_languages` 只有 `("c","cpp")`（交付项 6 §8）。

## exact argv、环境版本、通过/失败/skipped 与原因、日志和哈希

```console
$ .venv-web/bin/python -m unittest discover -s tests -q
Ran 568 tests in 24.338s
FAILED (failures=2, skipped=4)

$ .venv-web/bin/python -m unittest tests.test_ipc_family_depth tests.test_ipc_family_matrix -v
Ran 25 tests ... OK
```

两个失败**不是本单元引入**，且与交付项 1 §3.1 的预判逐字一致 —— 并发 import 把来源树的
覆盖侧车断言照抄成 `'blocked'`，本基线 `runner.py:119-131/250-255` 在无 `file_outcomes`
时给出 `'partial'`：

```text
tests/test_ipc_detector.py:61  AssertionError: 'partial' != 'blocked'
tests/test_ipc_detector.py:168 AssertionError: 'partial' != 'blocked'
```

本基线上应保留 `'partial'`，该文件属并发 import，本线未改。

4 项 skip 为既有跳过，与本单元无关。实测运行的 argv 与 18 份报告哈希见
[交付项 3](20261017-six-family-component-measurement.md) 与 `components.json` 的
`report_sha256`；第二批 12 组件的 argv **逐字相同**（只换 `--repo-dir` 与 `--out-dir`），
哈希见 `research/evidence/interface/ipc/component_audit_shape_20261017/components.json`。
本批新增的两个只读脚本（`copy_range_arg_classes.py`、`permission_arg_classes.py`）
不在测试套件内，它们是测量工具、不参与断言；其输出即交付项 5/6 的表格。
`silent_rule_shape_census.py` 的两处改动（`RewindRead` 正则修正 + `--detail`）见交付项 5 §4。

第三批测量（交付项 7 的探针）的 argv 与上面两批**逐字相同**，只多一个
`PYTHONPATH=<探针目录>` 与 `IPC_PROBE_LOG`；**未用 `-I`** 掩盖任何 import 问题
（探针的 `sys.path.insert(os.getcwd())` 是必要偏差，已在仪器 docstring 里写明）。
第三批**整批重跑过一次**以校验可复现性（04:32–04:52），两次数字逐字相同；
取值用的证据 JSON 与仪器哈希：

```text
research/evidence/interface/ipc/auth03_identity_probe_20261017/interpreter_attribution.json
  sha256 fe5e805529a522a0c185c135220cdfda3e31dcf92427ee59eab4d2efbdaeed63
research/deliveries/ipc/probe_site/sitecustomize.py   （该次记录所用的仪器本体）
  sha256 67177e28683de37037e6b0b2bb88db86f2cd8453c80f5fbef452db95b23a5c9e
  ↑ 证据 JSON 的 instrument.sitecustomize_sha256 与它逐字相同（同一份文件既产记录、又被记哈希）
research/evidence/interface/ipc/caller_class_walk_20261017/caller_class_walk.json
  sha256 见仓库（三种读数汇总，调用点 83 / 走查 0 / 根 27）
research/deliveries/ipc/root_probe_site/sitecustomize.py  （第二件仪器，只回答"走查跑没跑"）
  sha256 8e49770f2e1db6dd3d9c3f9bd53e26fb2b0fb4b14f82f4338c05eac78ecaca16
research/deliveries/ipc/ceiling_probe_site/sitecustomize.py  （第三件仪器，只改写入口根集合）
  sha256 54ff14ab39f8dcd48703cb9aa32978408429aac015f7e796bebf329826378a5c
  ↑ 全批次同一份：`ceiling_yield.json` 的 `instrument_sha256` 与它逐字相同
research/evidence/interface/ipc/ceiling_20261017/ceiling_yield.json
  sha256 a0735bb8661126c4a9597f7edd8a679155109a47cb5fa0a007315fb83a8e5d9d
research/deliveries/ipc/ceiling_yield.py  （该次汇总所用的脚本本体）
  sha256 624f52f484d53f33abe672fcae924060e612547fc2a2a36b477d37168220cc13
  ↑ 这两份哈希在交付项 9 定稿后**各改过一次**：`Entry=` 是从 `message` 文本里正则取的，
    原先 docstring 与证据 JSON 的 `how_to_read` 只说"AUTH-02/03/04 没有具名机制字段"，
    没说明这是**所读那批 pinned 报告**的性质——工作树里并发 import 的检测器已经给
    每条 finding 加了**按族的机制 CWE**（`detector.py` 的 `candidate_cwe=_CWE[o.family]`），
    本项读的是 `0.8.0` / `oh-ipc-2026.10-v6` 产出的报告，早于它。改的是措辞、不是数：
    重跑后 `baseline 166`、`services 46 → 57`、`interfaces 0 → 22` 与改前**逐字相同**，
    证据 JSON 的 diff 是 1 行（只有 `how_to_read` 那段）。
```

探针在交付项 8 里扩了 `bucket`/`caller_class_set` 两个字段（哈希随之改变），
**身份侧的 145 / 102 / 31 / 8 / 4 与站点数一个未动**，两次逐字相同；证据 JSON 是按
扩后的仪器重跑重取的，不是拿旧记录去配新哈希。

第三件仪器（`ceiling_probe_site`）在冻结前**改过一次**（docstring 里对 callback stub 的
说法过宽，且 strict 档漏了 `ref_params=()`），改完即冻结、打印 sha256、在
`update_updateservice` 上冒烟，再按冻结版**重跑全批**——重跑逐字复现冻结前的数字
（`security_access_token` 客户端口径前后两次都是 `22`），这同时是可复现性校验。
本单元的**反事实**运行（多口径入口放宽）与上面三批**基线**运行是不同的运行，
两边的报告不做哈希混比：基线 166 条候选那批的 argv 与哈希见交付项 3/交付项 6。

**性能与资源**（比赛文档要求的性能证据；数字取自 30 份 `report.json` 里检测器自报的
`elapsed_seconds` / `peak_rss_kb`，非另行计时）：

| 项 | 值 |
|---|---|
| 组件数 | 30（全部 pinned、`git status --porcelain` 干净） |
| 文件数 / 行数 | 17,546 / 2,435,311 |
| 累计墙钟 | **1,049.2 s** |
| 单组件峰值 RSS 最大值 | **1,914 MB** |
| 候选总数 | 166（全部 `candidate`） |

单组件串行执行、无并发；上表是**本机实测**，不是估算。

## 固定目标 repo/commit/tree/blob/source SHA、scope/profile、detector/model 版本

- detector `ohscanner.interface.ipc` `0.8.0`；model `oh-ipc-2026.10-v6`；
  驱动 `src/ohscanner/detectors/interface/audit.py`，来源树 HEAD `635b3e0`
- 18 个组件逐仓库 `rev-parse HEAD` 现场固定，清单见交付项 3 §1；
  第二批 12 个组件同样现场固定，清单见交付项 6 §1（全部 gitee origin、
  `git status --porcelain` 干净）；两批共 **30 个组件、17,546 文件、2,435,311 行**；
  scope = 驱动默认（production-only，`//production-segment:test|tests|unittest|fuzz|mock|sample|example|demo|benchmark|third_party|3rdparty` 排除），
  **头文件在范围内**
- 候选身份：`source_sha256` + `rule_version` + `interpretation_id` + `observed_detector_versions`
- 目标仓库必须 `git status --porcelain` 干净才跑；脏树记 `dirty` 跳过

## positive/fixed/safe/unrelated 与 holdout 是否独立

- 三件控制齐全（positive + fixed + safe），且按家族各自持有；不存在"借用别家负证据"。
  （**这句话在交付项 12 之前是超前的**：AUTH-02 / AUTH-04 / CAP-01 三个家族当时没有自己的目录，
  只能从共享 manifest 借负证据；交付项 12 补齐这三个目录后，该断言才与本线实际持有的证据一致，
  并由 `RuleControlCoverageTests` 逐家族机器校验。）
- `unrelated`：`caller_class_unreviewed_name_safe.cpp`、`position_underflow_safe.cpp`、
  `relay_unreviewed_call_safe.cpp` 是**不相关形状**控制（不触发目标规则、也不触发别的规则）。
- **不是独立 holdout。** 夹具是为规则手工写的同源设计样例，作者知道规则逻辑；
  30 个真实组件是独立的真实代码，但**没有标签**，因此只能报候选数，不能算 P/R。
  任何"零 FP/FN"的说法都不成立。
- **P/R 的前置条件缺口（明确不做，不是漏做）**：技术文档 §13.1 要求"冻结 holdout 不参与调参"
  且"未知覆盖从分母剥离、单独统计"。本线**可以**冻结样本（30 份报告 + pinned commit 已足够
  给出确定的候选/站点清单，且挑选规则可以是确定性的），但**标签必须由人给**：
  候选是否为真阳性取决于业务语义（例如 `bundle_installer_host.cpp:1838` 是个良性管理检查），
  由本线自评再自算 P/R 正是证据门禁禁止的"把模型自评当真相"。
  故本线**不产出 P/R 数字**，只把缺口和它所需的输入写清楚 —— 需要的是
  **一份人工标注的、冻结的独立样本**（含真阳性与真阴性两侧），这要用户/集成人决定由谁标。
  在拿到它之前，逐规则的"能触发"由正例控制证明（11/11），"在真实语料上命中多少"由 166 条候选陈述，
  两者都不等于精度。

## 候选移动的逐项原因，candidate/confirmed/unknown 的证据边界

本线**没有改动任何规则**，因此**候选集零移动**：18 个组件、1.53M 行上的 100 条候选
全部来自未改动的 `0.8.0` 检测器。全部 100 条保持 `candidate`（`unassessed`），
`confirmed_vulnerabilities` 按构造为 0。**零候选不代表组件安全；候选不等于漏洞。**

第二批 12 个组件（+0.91M 行）把候选从 100 扩到 **166**，逐条原因如下（交付项 6 §3）：

| 规则 | 18 → 30 组件 | 逐项原因 |
|---|---|---|
| `ipc.relay.descriptor-boundary` | 54 → **92**（+38） | ability_runtime +30、samgr +4、dsoftbus +2、data_share +1、pasteboard +1；均为同样的入口缺 descriptor 比较，**规则与阈值未变，是语料新增站点** |
| `ipc.capability.export` | 24 → **43**（+19） | ability_runtime +10、samgr +5、dsoftbus +2、data_share +2 |
| `ipc.auth.missing` | 12 → **21**（+9） | ability_runtime +8、data_share +1 |
| `ipc.auth.guard-coverage` | 8 → 8 | 新语料没有新站点 |
| `ipc.auth.object-owner` | 2 → 2 | 新语料 `owner_calls` 从 2 涨到 57，但该计数**不是**规则的触发条件（交付项 6 §7） |
| 其余 6 条 | 0 → **0** | 见"未验证/下一项"第 1 条的成因表 |

**没有任何一条候选的规则身份或证据字段发生变化** —— 新增的 66 条是新站点上的新候选，
不是旧候选被重新分类。

一处**数字上的移动**必须区分清楚：`window_window_manager` 曾被读作 0 候选，
那是**失败运行的残留报告**（`shard_errors: [ValueError: invalid declared repository name]`，
`files_not_analyzed: 1069`），重跑后为 10 条。这不是候选移动，是**把一个非测量纠回测量**。

## 旧报告、候选 ID、人工复核的兼容性

- 未改任何历史报告、候选 ID 或复核记录；未改 `detector.py` 的 `detector_id` /
  `interpretation_id`，因此新旧候选身份不冲突。
- 前几轮（v0.8 卡片记录的 41 条复核、WWM 14 条、sat/update 5 条）是在**其他 model 版本**
  下得到的，与本表的 100 条**不可直接比较**，本次未做归并，也未重跑那些组件。

## 未验证、阻塞、下一项

1. **形状普查与六条静默规则的成因（已做，交付项 4/5/6）** —— 每一条现在都有可复核的
   机制，且**都不是"规则坏了"**：

   | 规则 | 成因 | 依据 |
   |---|---|---|
   | `position-underflow` | **覆盖**：形状存在（2 处），但站点在另一翻译单元之后，入口根走不到 | 交付项 5（删守卫 A/B + 7 例探针） |
   | `copy-range` | **正确静默**：1860 次拷贝调用，长度无一来自请求 | 交付项 6 §7（逐类实参） |
   | `identity-domain` | **解释器侧覆盖**：`caller_uid` 形状 0 处；30 组件上解释器求值 145 次谓词，`caller_uid` 归因 **0 次** | 交付项 6 §5 + 交付项 7 §2（检测器内部实测） |
   | `request-identity` | 形状 **≥2** 处，但还需同路径敏感效应，且站点在 IDL 生成的分发器之后 | 交付项 6 §6（9 例探针）+ 交付项 7 §5.1（敏感效应前置在做事） |
   | `service-identity` | **覆盖**：17 处普查站点**全部在 scope 内**，但解释器一次都没走到（每个外层函数都是客户端/kit/工具代码）；**不是**"还缺敏感效应" | 交付项 7 §4（含 scope 核对与逐站点外层函数表） |
   | `caller-class` | **覆盖**：30 组件上 83 个调用点，解释器求值 **0** 次；`security_access_token` 的 27 个入口根全在 `interfaces/`，58 个调用点全在 `services/`，无一落在根文件内 | 交付项 4 + 交付项 8（检测器内部实测） |
   | `caller-class`（**补上覆盖之后的要求**） | 成因是覆盖，但**补覆盖单独做会降精度**：新可达的 5 条全部落在已做 system-app 检查的处理器内部，真正缺的是**身份派生谓词建模**（`IsSystemAppCalling` 被本地同名定义遮蔽 / `CheckSystemApp` 从未被命名） | 交付项 9 §3（反事实 + 逐条源码） |

   交付项 4 里写"`position-underflow` 形状 0 次 ⇒ 未被行使"的那一行**已作废**
   （普查正则跨不过嵌套括号），交付项 5 §4 给了旧/新口径对照。
   **交付项 6 §5/§6 关于 `service-identity` 机制的两处结论与 §6 的行号已被交付项 7 更正**：
   机制是**可达性**（与 `caller-class`/`position-underflow` 同类），不是敏感效应前置；
   行号应为 `3461/3465`。更正后 AUTH-03 四条规则里**只有 `request-identity` 属于
   "形状存在但前置不满足"，其余三条都是覆盖问题**。

   **至此六条静默规则全部有检测器内部或探针支撑的证据，没有一条还停在推断上**
   （最后一条 `caller-class` 由交付项 8 用第二件仪器结清）。**三类成因**的分布是：

   - **覆盖 3 条**：`position-underflow`、`caller-class`、`service-identity`
   - **形状不存在 1 条**：`identity-domain`（`caller_uid` 在语料里 0 处，
     文本普查与解释器归因两个独立方法一致）
   - **正确静默 1 条**：`copy-range`
   - **前置不满足 1 条**：`request-identity`

   成因决定下一步改哪：覆盖类要补入口建模/跨 TU 一跳；形状类补建模没用；
   前置类的"修法"（去掉敏感效应前置）会直接降低精度，交付项 7 §5.1 有语料内的反例。

   **下一步**是把 IDL 入口纳入建模、加跨 TU 一跳，**并且同时**把身份派生谓词
   （`TokenIDAttributes::IsSystemApp` 一类）建模——只做前一半会**降精度**，
   交付项 9 §3.3 把两条路（遮蔽 / 未命名）都指出来了。三处都在并发 import 的
   `analysis.py` / `models.py` 里，见下条。
2. **两条覆盖缺口的收益上界（**已量**，交付项 9）** —— 原先这里写"**本次未量**"，
   现在量了。用一件只改写入口根集合、其余一行不改的仪器（`ceiling_probe_site`，
   sha256 `54ff14ab…`）跑**同一个** `0.8.0` 检测器：
   - 最紧口径（`*Service`/`*Stub` + `services/`），5 个含全部调用点的组件：
     候选 **46 → 57**（`caller-class` **+5**、`guard-coverage` +3、`auth.missing` +3），
     补进 321 个根；
   - 客户端口径（`interfaces/`），`security_access_token` 单组件：**0 → 22**
     （`caller-class` +11、`auth.missing` +11）——owner 全是 `*Kit` / `*Client`，
     是客户端与它调用的服务方法**同名**造成的。
   逐条读源码后，服务侧那 5 条 `caller-class` **没有一条**是"处理器没做检查"：
   4 条是同进程 manager 调用，1 条是跨服务 kit 调用。所以这不是召回，是精度损失，
   除非同时做第 2 条请求里的谓词建模。`ability_ability_runtime` 超时未跑、
   客户端口径只覆盖 1 个组件——两处是覆盖缺口，不是"没变化"。
   语料侧已排除：扩到 30 个组件后，
   新增的 66 条候选全部落在原本已响过的三条规则上（交付项 6 §3）。
   **检测器内部口径已给出**（交付项 7）：解释器在这 30 个组件上自己求值了
   **145 次**授权谓词 —— `caller` 102、无法归因 31、同文件同名遮蔽 8、`request` 4，
   `caller_uid` **0**、`self` **0**；只有 9/30 个组件求值到过任何谓词。
   所以 `identity-domain` 的静默是**解释器自己从没做过这件事**，不是文本分类器的口径问题。
   该测量同时充当双向控制：102 次 `caller` 求值是负侧（拿到调用者自身身份的谓词保持沉默），
   4 次 `request` 绑定是正侧（确实记录了 identity issue）。
   **145 次这个数不是候选数** —— `emit()`（`analysis.py:612-631`）无条件 append、
   `detector.py:98-113` 一一映射，故某规则候选为 0 ⇔ 该规则零 emit，此点由报告直接推出，
   未做第二遍插桩重跑。
3. **机制字段（未做）** —— AUTH-01 有具名机制结果（`descriptor_identity` 等），
   AUTH-02/03/04、CAP-01、DATA-01 的候选仍只能靠 `message` 文本区分，没有可断言的字段。
   需要改 `analysis.py` / `models.py`，属并发 import 正在写的文件，本线未抢。
4. **共享 manifest 一行需集成人裁决** —— `tests/fixtures/ipc/manifest.json` 的
   `account_role_authorized_fixed`：并发 import 把它从"必须零候选"改成断言
   `ipc.auth.missing`，却保留 `variant: "fixed"` 与已失效的 `notes`。
   `matrix()` 只按 `expected_rule` 分支、且**全测试集无人读 `variant`**，所以这次改写不会被任何测试发现。
   本线把 `variant` 改为 `positive` 并把 `notes` 补正（不改任何检测行为），
   并在 `test_ipc_family_depth.ManifestContractTests` 里第一次给该字段加上约束。
   **该文件同时含并发 import 新增的 18 行，故本线未提交它**，留给集成人；
   若要保留为真正的负控制，需让它走显式 policy 路径（该行自带 `policy_context` 已指向此方案）。
5. **`ReadRawData`/`ReadBuffer` 取参下标（需集成人裁决）** —— `copy_calls` 的
   `index=2` 对这两个名字够不着它们真正的长度实参（第 0 个）：`ReadRawData` 139 次、
   `ReadBuffer` 45 次取不到。这是**规则定义改动**，落在 `analysis.py`。
6. **未做的动态验证 / PoC** —— 本交付只到静态候选与测量，无 PoC、无动态验证。
7. **反事实证据的两处来源缺陷（已修，交付项 10 §5.1.1）** —— 这两处**都没有产出错的数字**，
   但都让"这个数字由那份补丁造成"这句话不可检验，所以记在这里而不是当作小事：
   - `copy_range_counterfactual.py` 的 `build()` 没建证据目录就写 `patch.diff`，
     直接抛 `FileNotFoundError`。上一会话据此认为 `patch.diff` 已落盘，实际**从未写过**。
   - 跑出 42 组件比对结果的那份副本，与 `--build` 现在产出的副本 `analysis.py`
     sha256 不一致（差异**只在两处注释措辞**，代码逐字相同）。
   处置：`build()` 补建目录并把副本哈希写进 `patched_analysis.sha256`；`--report`
   比对前校验磁盘副本哈希等于记录值，不等即报错退出；归档第一版输出（`cf-out-all-run1/`，
   未删）并用重新生成的副本整份重跑。重跑与第一版**逐组件完全相同（42/42，含 scope 哈希）**，
   故上列数字未变——但这一点现在是量出来的，不是从"差异只在注释"推出来的。
   同时修掉 `report()` 把 `removed`/`added` 写成净差（会打印 `added=-1`）。
8. **交付项 11 的三处成因都落在 `analysis.py`，本线不动** —— 把 AUTH-01 的筛查原样套到
   全部 6 条会响的规则后，179 条里 23 行命中，其中 **12 行的报告自身字段就与自己的
   `message` 相矛盾**。三处成因同一个归属：
   - 8 行把**校验调用本身**当成"未被校验的 handler"（`symbol` 与 `message` 互斥）；
   - 1 行（`raw_parcel_callback_stub.cpp:44`）跳不进**同一文件、被调用者第一层**的守卫；
   - 1 行（`pasteboard_disposable_observer_stub.cpp:48`）的守卫写成宏
     `PASTEBOARD_CHECK_AND_RETURN_RET_LOGE`，于是 `path=()` 为空——**591 条 path 条件里
     0 条宏形条件**，而字面 `if (descriptor != token)` 会被记进 path（同组件有实例）。
   三处都在 `src/ohscanner/detectors/interface/analysis.py`，属共享面，**需集成人另开请求**。
   本项只测量与记录，未改检测器、未撤任何候选。
   另需记住口径：**交付项 10 §6 的 `empty_path` 口径被本项收窄**——11 行里 10 行
   `path=()` 准确、1 行不准确（即上面第三处）。按旧口径"一律准确"会漏掉那 1 行。
   还有一条限制：`ipc.auth.missing` 的 21 条零命中只说明**它没命中这 4 种模式**，
   不等于这 21 条都对。
9. **交付项 12 的一条开放项（未固定行为，属共享面）** —— 同一段一跳程序，对象经**引用出参**
   回来时 credit 抵达并撤销 export 候选，经**返回值**（`virtual RemoteObjectPtr GetObject(...)`）
   回来时 credit 行照记（三处 `file:line` 引用正确）而候选**不撤**；检测器自己的 limitation
   只写了 `Pointer out-parameters are not followed`，未覆盖返回值形态。成因从外部不可判定
   （需读 `analysis.py` / `bind_result`）。**故意不做成夹具**：在预期行为定下来之前把它写进 pin 表
   等于替引擎定行为。详见交付项 12 §5。另两条边界（对象宏命名的类名使入口索引不绑定 dispatch、
   成员定义的角色谓词读 body 而文件作用域定义直接拒名）已固化为夹具并双侧断言。
10. **引擎的 case 级推理不进已保存报告（交付项 13 §4，共享面）** —— 一跳采信/拒绝、
   非唯一拒绝、同名遮蔽这些句子由 `IpcInterfaceDetector.detect(...)` 的
   `run.limitations` 产出，深度单测就是靠它断言两侧的；但在 54 份已保存报告文件里，
   七个 case 标记（`one-hop`/`Cross-TU`/`not unique`/`credited`/`shadow`/
   `Dispatch handler`/`caller-role`）命中 **0**，`report.json` 的 `limitations` 是每组
   10 条固定字符串。报告只带每候选的溯源（`file_analysis_status`/`file_parse_status`/
   `passes`/`source_binding`），不带"为什么被采信/为什么这条一跳没被采信"。
   报告面属 owner/共享面，本线只记录，**需集成人另开请求**再谈是否落盘。
11. **本车道当前修订里搜不到那份生产段排除清单（交付项 13 §7.3）** —— 已保存 42 份报告的
   作用域计划来自 pinned 修订（`635b3e0` 的 `interface/audit.py:122`
   `PRODUCTION_EXCLUDED_SEGMENTS`）；在本 worktree 的当前修订里，`src/` 下搜不到等价清单，
   `families/` 只有族适配。这**不是**缺陷判断（批量 run 用的是 pinned 仓库），
   是要点名的一条开放项：从当前修订驱动的一次运行会在别处推导作用域，需与并行会话确认。
   附带一条实测口径：分段规则下 `rdbmock/`、`kvstoremock/` **不**被排除（要求整段等于
   `mock`），这两个组件的计划里确实点名了那 4 个 const 形式文件（921/921、1446/1446）。

## 本地提交完成；push/merge/Ready 需另有明确授权

- 仅本地提交到 `work/ipc-20261017`；**未 push、未开 PR、未标 Ready、未 merge**。
- 只提交上列"新增"清单中的本线自有路径；**不提交**并发 import 的
  `src/**`、`tests/test_ipc_detector.py`、`tests/test_ipc_entry_index.py`、
  `tests/test_ipc_family_matrix.py`、`tests/test_ipc_integration_safety.py`、
  `tests/fixtures/ipc/*.cpp`（`account_role_*` / `helper_preproc_*` / `onehop_*` /
  `relay_lookahead_*` / `role_predicate_*`）与共享 `tests/fixtures/ipc/manifest.json`
  ——其 dirty 状态被保留。
- **本提交不能单独检出运行 —— 这是实测结论，不是推测。** 在 `d45e602` 的独立
  `git worktree` 检出上跑 `tests.test_ipc_family_depth`：

  ```text
  ImportError: cannot import name 'families' from 'src.ohscanner.detectors.interface'
  ```

  因为本线的家族目录约定（`Family.fixture_dir`）、`families.registry()`、
  `family_of_rule()` 全部来自并发 import 的 **`src/ohscanner/detectors/interface/families/`**，
  而它是**未跟踪**目录、不在本提交内；`tests/test_ipc_family_matrix.py`（家族目录的
  既有入口）同样未跟踪、不在本提交内。**集成顺序必须是 import 先落、本单元后落**，
  或由集成人把两者并入同一批。
- 本线新增的 3 个家族目录与 12 项测试对**基线**（`6a41dc9`）的共享 manifest 是自洽的
  （已逐一核对）：基线的 48 行里 AUTH-01/AUTH-03/DATA-01 缺 `safe`，由本线家族目录补齐；
  基线 48 行的 `variant` 与 `expected_rule` 一致、`family` 与 `family_of_rule()` 一致，
  正例覆盖 8/11 条规则，本线补上其余 3 条后正好 11/11。
  **但这只在 `families/` 包存在时才成立**，所以它不构成"可单独检出"。
