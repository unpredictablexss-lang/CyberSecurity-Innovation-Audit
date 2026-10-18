# B 线公开披露修复对回归（2026-10-19，Detector 0.12.9）

本目录保存两个公开 OpenHarmony 漏洞修复对在 B 线当前工作树上的固定源码回放。它验证的是静态分析候选与公开补丁之间的差分，不是设备利用、产品漏洞动态确认，也不是独立 Precision/Recall 测量。

| 披露 | 仓库与固定端点 | 同范围候选 | 目标变化 | 解析 |
|---|---|---:|---|---|
| CVE-2025-26691 | telephony_call_manager：易受影响 911c6c99872e3a6a421747815bc8c1f6b201db26 → 修复 6018446d576b84d8893f8f7ad5d46353236fb8e0 | 9 → 0 | 九个被审阅操作的权限常量错配均被 AUTH-02 捕获；修复后目标候选消失 | 单文件，两侧 complete |
| CVE-2024-38382 | ability_ability_runtime：易受影响 fd8cd59c2f98c9b5365ee422f58bd82064fe2359 → 修复 f2898e72966a8fcc59ecebc3cdea8d9aab063b1d | 4 → 2 | 目标 AUTH-02 与 DATA-04 消失；剩余两条为共有且无关的 CAP-01 | 同一 7 文件范围，1 complete / 6 partial |

CVE-2025-26691 使用经源码补丁核对的正确父子提交。旧实验记录中的 c751a0dc... → 911c6c99... 虽是相邻提交，但不包含本披露对应的九处权限替换，不能作为该 CVE 的修复对证据；旧结果保留为历史记录，不用于本轮能力结论。

## 实现变化

Detector 0.12.9 加入按完整类限定方法名匹配的审阅权限契约：若实际检查权限与审阅契约不符，则产生 AUTH-02，并避免同一调用链重复报告。规则不是按 CVE 名称触发。另改进敏感返回值的一跳源绑定守卫传播，避免已被守卫覆盖的结果仍产生 DATA-04。配套回归在 tests/test_ipc_detector.py 与 tests/test_ipc_disclosure_consequence.py。

这两个已知修复对不是独立 holdout；新增权限契约还需要配套 safe/negative controls。

## 判定边界

- 两组 CVE 可在公开披露/历史漏洞台账中标记为已披露；这不代表扫描器对当前产品构建作出了 confirmed 判断。
- JSON 中 validated_vulnerability=0 保持原样。没有运行产品构建、设备 PoC 或动态 Harness。
- CVE-2024-38382 的范围有 6/7 个文件为 partial；跨文件覆盖不完整。
- 候选总量不等同于 CVE 根因匹配数，应检查目标规则与逐条 finding。
- 全量单测：714 OK，36 skipped。
