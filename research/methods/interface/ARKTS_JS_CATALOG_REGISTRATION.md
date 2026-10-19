# `ohscanner.oh.arkts_js` Catalog 注册提案（owner 执行）

`src/ohscanner/detectors/catalog.py` 与 `requirements*.txt` 属
`config/collaboration/ownership.json` 的 `shared_owner_only`，本 lane 不修改。
本文件给出 owner 可以直接套用的注册内容与来源链；在 owner 落地之前，该检测器
**不会**被 CLI/Web 的显式选择解析到，语法依赖也不会进 CI。

## 1. 注册进 `catalog.py`

```python
# import block
from .interface.arkts_js import ArkTsJsInterfaceDetector

# _APPROVED
"ohscanner.oh.arkts_js": {
    "factory": ArkTsJsInterfaceDetector,
    "kind": "research_candidate",
    "summary": "B: bounded ArkTS/JS interface candidates; "
               "partial parse is unknown, not safe",
},
```

注册后 `catalog_metadata()` 会多出一项；`build_registry(["ohscanner.oh.arkts_js"])`
即可构造。检测器自身的 `detector_id` 为 `ohscanner.oh.arkts_js`，`version` 为 `0.3.0`，
`supported_languages` 为 `("js", "ts", "arkts")`，`required_facts` 为空，
`ast_scope` 为 `per_file`。

## 2. 依赖

```text
tree-sitter>=0.26.0
tree-sitter-typescript>=0.23.2
tree-sitter-javascript>=0.25.0
```

三者都是可选导入：缺失时 `LANGUAGE_MODULE_STATUS` 为 `missing`，`detect()` 返回
`blocked` 并写明缺哪个语法包，不会把"没跑"报成 0 发现。放进
`requirements.txt` / `requirements-dev.txt` 的选择由 owner 决定，但 CI 若不装，
B-3 的检测在默认环境里始终是 `blocked`。

## 3. 来源与可复核链

| 项 | 值 |
| --- | --- |
| 实现 | `src/ohscanner/detectors/interface/arkts_js.py`，sha256 `8b6c16298d3ef966553c1a290c90af499c0e966bdc8b419caaef03dbf850657e` |
| 规则说明 | 模块 docstring（五条规则、每条的抑制条件与"不做什么"） |
| 控制测试 | `tests/test_ipc_arkts_js.py` 32 条（每条规则正例/抑制例 + 三态 + N-API 12 条） |
| 语料 1 | `research/evidence/interface/ipc/b3_arkts_real_20261017/`（settings `5e8af0a2`，2045 文件，0 候选） |
| 语料 2 | `research/evidence/interface/ipc/b3_arkts_vultraining_20261017/`（vultraining `ceaf1b4f`，16 文件，0 候选） |
| 交付说明 | `research/deliveries/ipc/20261017-bline-parcel-auth-flow.md` §13 / §13.1 |

`b3_arkts_real_20261017/census.py` 直接读 `ArkTsJsInterfaceDetector.version` 与
`detector_id` 写入 `census.json`；改版本号时两处语料都要重新生成，否则证据与实现脱节。

## 4. 注册时需要一并说明的口径

- 该检测器输出 **candidate/unassessed**，不产生 `validated_vulnerability`，
  也不修改任何既有规则集或模型版本号（`oh-ipc-2026.10-v10` 只属于 C/C++ IPC 检测器）。
- `partial` 是 ArkTS `struct`/装饰器的正常结果，不是解析失败；调用方不应把
  `partial` 当作 `blocked` 或 `complete`。
- N-API binding map 只来自同一批次的 `.d.ts`；跨批或扫描树外的声明不可见，
  未映射调用不产生候选，只出现在 limitation 计数里。
