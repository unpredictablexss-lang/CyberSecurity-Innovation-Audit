# Rules

静态安全审计规则库。

按语言或场景拆分：`cpp/`、`java/`、`python/`、`web/`。

后续每条规则建议包含：规则 ID、漏洞类型、CWE、风险等级、匹配条件、误报说明、修复建议和测试样例。

## cpp/ 布局

```text
rules/cpp/
  oh_shared_ptr_uaf.yaml      # OpenHarmony 专用：非原子 shared_ptr reset 并发 UAF
  oh_nothrow_null_deref.yaml  # OpenHarmony 专用：nothrow new 后未判空直接解引用
  vendor/                     # 第三方规则（只读镜像，见 vendor/README.md）
    README.md
    raptor/                   # 0xdea/semgrep-rules，MIT，49 条 c/cpp 规则
```

两条 OH 规则目前都是待人工审查的结构候选：shared_ptr 规则实际匹配所有
`.reset()`，未判断接收者类型、并发访问或锁；nothrow 规则未证明判空分支终止
失败路径或支配解引用。历史修复前后结果仅说明对应样本上的区分效果。
限制与后续开发约束见 `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/143fa63fa479be79fa80ca5f8322c74afecc273c/docs/reviews/architecture_rules_review_2026-10-08.md`。

## 规则来源策略

**不再使用自制的“本地通用规则”**（旧的 `semgrep_rules.yaml`）。原因是其中
`deref-after-arrow`（pattern `$P->$FIELD`）把任意 C++ 成员访问都报出来：在 731 行的
`js_array.cpp` 上产生 144 条诊断 / 0 条有效，属于纯噪音，会虚增 `possible_hit`。

取代方案（2026-10-06 实测）：

| 目标语言 | 规则来源 | 说明 |
|---|---|---|
| C（`.c`、`.h`） | Semgrep 官方 registry | 免费 registry 只有 16 条 `c.lang.*` 公共规则；`p/security-audit` 收录其中 9 条 |
| C++（`.cpp`、`.hpp`） | `vendor/raptor/`（0xdea，MIT） | 免费 registry **没有任何 cpp 规则**，154 条 `cpp.*` 全部是付费 pro 规则 |
| OpenHarmony 专用 | `oh_*.yaml` | 从历史修复反推的增强规则，提供通用规则给不出的语义命中 |

复用脚本：`scripts/semgrep_ruleset_scan.sh`。
