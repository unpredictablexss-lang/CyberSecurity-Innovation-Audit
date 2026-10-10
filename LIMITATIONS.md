# LIMITATIONS：`ohscanner.cpp.shared_ptr_race`

## 独立 holdout

- 当前 holdout 状态是 `designed_not_executed`；没有真正独立、未参与 detector
  规则开发/调参的 vulnerable/fixed pair。
- `tests/detectors/fixtures/cpp_shared_ptr_race/**` 只能作为 synthetic development
  fixtures，不得改称 holdout，也不得生成新 synthetic 样本冒充独立数据。
- 已提供外部 manifest 接口，要求 exact repository/commit/path/source hash/snapshot/
  profile/tool version 和 detector freeze -> unlabeled prediction -> prediction hash
  -> label reveal 流程；在真实外部数据到位前不填写 prediction/label release hash。
- 未来只报告 raw observation/category counts；不计算或宣称正式 Precision/Recall、
  零误报或零漏报。

## 分析能力

- 没有真实产品构建覆盖；不证明真实 OpenHarmony 组件可构建、可运行或可触发。
- 锁语义是词法 scope 近似，不证明 mutex ownership、guard dominance、lock ordering、
  `defer_lock/try_to_lock/unlock` 或跨函数保护关系。
- 没有 CFG、数据流、污点、类型/所有权、模板实例化、lambda capture、跨函数
  escape/call graph 或完整 symbol resolution。
- 没有 dynamic validation、sanitizer 或 PoC 扩展；现有 TSan 复现实验只记录既有
  harness 的环境观察，不由 detector 执行，也不是 exploit 证明。
- 不证明 UAF、concurrent interleaving、attacker control、可达性、权限边界或
  security impact；`CWE-416` 只可能是 race 的后果。

## 状态语义

- `candidate/unassessed` 与 `syntax` evidence 是最低保证，不升级为 confirmed。
- `completed` 只表示 selected/analyzed scope 执行过，不是 safe verdict。
- `partial/failed/blocked/not_run` 是 unknown/coverage insufficient，不是 miss。
- unsupported language 或有证据的 incompatible analysis unit 才能记为
  `not_applicable`，也不是 miss。
- empty findings 只表示当前窄规则在当前 scope 未观察到 shape。

## 交付边界

- 本次只收口纯 M-gate：来源绑定、review verifier、负向回归、契约兼容、CI 配置和 main 同步。
- C-gate 仍未闭合；PoC、动态验证、CWE/CVE、影响版本、修复重验、性能之外的漏洞报告等由后续独立任务完成。
- 不创建 PR、不标 ready、不合并 main；远端 push/CI 由负责人授权后执行。
- 当前结论仍是 `candidate/unassessed`，不得把 TSan harness 观测或历史 fixed pair 写成产品漏洞确认。
