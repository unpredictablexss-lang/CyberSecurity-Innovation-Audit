# C3：泛化控制与独立评估准备

冻结算法：`4ea5f4020884aed5860a88d50f5a926610e7b98a`；Detector/model `0.2.0`；精确模型与预算见 `C3_RUN_MANIFEST.json`。

## 先证伪，再修改

`C3_BASELINE.json` 在 C2 提交 `33242fbd2b58e2f510fa74f1521e247fea08db27`、版本 `0.1.0` 上先运行原专项 41 项，41 通过；新增 24 个开发机制中 12 通过、12 失败。失败编号：G03–G11、G13、G15、G22。它们主要暴露表达式位置漏处理副作用、守卫过期、遮蔽绑定、return 表达式及循环创建身份问题。最终同一矩阵 24/24 通过，记录在 `C3_MECHANISMS.json`。这是开发控制通过数，不能当独立漏洞准确率。

正例包括对象别名、token 多次复制、旧副本与后续重定义分离、源对象内部相等不足以证明目标同型；修复/安全形态包括新目标采样和有效的目标类型相等守卫；无关 receiver/owner 与无法绑定的调用分别保留不适用或 unknown。C01–C12 原案例重新执行 12/12；其中历史两项使用固定 Git 对象，其余使用原 fixture，具体判据见 `C3_LEGACY_CASES.json`。

额外审查先保存六个宿主写入反例，见 `C3_REVIEW_COUNTEREXAMPLES.json`，这些是 C3 开发中的中间算法，不冒称 C2 原始结果。最终回归扩充为 15 种嵌套/间接写入形式，并补充 detached 构造、箭头创建循环、宿主 GateRef 跨块重绑、跨函数预算保留等控制。专项总数 66，含上述子用例的测试方法并非每个子用例各计一项。

既有 `test_local_shadow_is_not_the_outer_object` 改成 species 创建后对 input 重新采样，隔离词法遮蔽语义；旧的创建前采样形态在新增测试中明确期望 unknown。历史测试显式限定 Filter，并断言观察类型为 candidate / matched，避免新增 Set 的匹配掩盖 Filter 回归。不是通过扩大白名单维持历史数字。

## Holdout 包与盲审

`prepare_holdout.py` 在冻结提交之后生成 H01–H16，并逐字节验证当前实现与冻结 Git 对象一致；没有据预测调整算法。源码位于 `holdout/`，哈希在 `C3_HOLDOUT_MANIFEST.json`，原始预测在 `C3_HOLDOUT_PREDICTIONS.json`。16 项没有与 24 个机制样本复用相同源码哈希。

目前准备了风险机制、同源保证、无关和证据不足四类采样意图，每类 4 项；意图不是金标准标签。原始预测为 4 candidate、4 matched、5 unknown、3 无观察。H12 的无关调用意图得到 unknown，保留原始结果，不为类别均衡修改算法。

由同一开发助手编写、共享框架及部分机制，来源独立性有限；独立人工标签仍未获得。现阶段是冻结后未用于调试的待审样本包，不能宣称已完成独立标注的 holdout 评估。Precision/Recall、FP/FN 均未知。

请负责人或另一位队友在不查看预测文件的前提下，核对源码和摘要假设，填写 `C3_HOLDOUT_LABELS.template.json` 的 reviewer、标签、理由及证据。允许标签为 risk_mechanism / reliable_same_type / unrelated / unknown；允许反驳采样意图。先冻结审核标签，再打开原始预测比较；unknown 不能算安全或漏报。若修改算法，旧包转开发集，另收未见数据评估。当前没有向任何队友自动发送消息。

## 复现

```text
python -m unittest discover -s tests/detectors/ark_runtime -t . -v
python research/experiments/ark_runtime/c3_20261017/replay.py --repo-dir <pinned-local-git-store> --output <new-output>
python research/experiments/ark_runtime/c3_20261017/prepare_holdout.py --output <new-empty-output>
```

历史回归需设置 OHSCANNER_ARK_REPO；缺对象时明确 skip。holdout 准备器拒绝覆盖已有 manifest。最终实际命令、环境、结果和日志摘要见 `C3_VALIDATION.json`。
