# C10-ARK-GAP-RULES

基线：`09ba5aba03c7c7d6787bace349b8fc0a6b0a5457` / tree `d15b91627c94d9c3043d7d58d47fcf9af7e42454`。保留既有 dirty repair、known-cve source identity 修复和 C10 Ark semantics patch；未执行 commit/push/merge/reset/fetch。

## Finding disposition

| Finding | 稳定规则 | 生产适配器固定对象复放 | 最终 disposition |
|---|---|---|---|
| IAO7GO | `ark.runtime.native-inline-pending-exception-propagation` v1.0.0 | parent 1 candidate → fixed 0 | `candidate/unassessed`；selector 已适用，不再静默 0 |
| I7W51D | `ark.runtime.typedarray-length-signed-to-unsigned-narrowing` v1.0.0 | parent 1 candidate → fixed 0 | `candidate/unassessed`；RangeError/固定转换不是安全结论 |
| IB8BCA | `ark.runtime.dataview-index-width-bounds` v1.0.0 | 三个 parent 文件共 3 candidates → fixed 0 | `candidate/unassessed`；fixed 侧仍显式 partial/unknown |

生产复放总数：IAO7GO `1→0`，I7W51D `1→0`，IB8BCA `3→0`。所有命中仍受完整产品构建、入口/权限、攻击者控制、触发条件、CIA 影响、动态 PoC 和修复产品重验义务约束。

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
