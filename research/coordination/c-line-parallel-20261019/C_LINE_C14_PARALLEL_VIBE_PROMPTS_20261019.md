# C14 parallel Vibe Coding prompts

## C14-BUILD-PROFILE
### 结构化 Vibe Coding Prompt
> 作为 build-profile Agent，固定宏、include、工具链与生成输入，补 negative mutation 和 positive/fixed/safe/unrelated/unknown 控制；缺项显式 unknown。
### 持续执行目标
G-BP-1 build identity -> G-BP-2 closure -> G-BP-3 mutation -> G-BP-4 known-case replay.

## C14-PRODUCT-CANDIDATE
### 结构化 Vibe Coding Prompt
> 作为产品候选 Agent，只选一个真实候选，闭合入口、权限、触发、CIA、隔离 PoC、修复重验、CWE/CVE 与报告；缺项保持 candidate/unknown。
### 持续执行目标
G-PC-1 select -> G-PC-2 reachability -> G-PC-3 impact -> G-PC-4 PoC -> G-PC-5 fix replay.

## C14-INDEPENDENT-EVAL
### 结构化 Vibe Coding Prompt
> 作为独立评估 Agent，冻结无泄漏 holdout，双人独立标注与裁决；只有可靠 truth 可计算指标，禁止零 FP/FN。
### 持续执行目标
G-IE-1 freeze -> G-IE-2 blind labels -> G-IE-3 adjudication -> G-IE-4 metrics.

## C14-PERFORMANCE-ADMISSION
### 结构化 Vibe Coding Prompt
> 作为性能准入 Agent，复测 2000 files/32MiB/1MiB 下 full/shard/cache 一致性与资源曲线，失败/partial/unknown/skip 分开，不把 NOT ADMITTED 改绿。
### 持续执行目标
G-PA-1 baseline -> G-PA-2 invariance -> G-PA-3 resources -> G-PA-4 admission.

## C14-INTEGRATION
### 结构化 Vibe Coding Prompt
> 作为合流 Agent，固定三方 SHA，只迁入验证通过的非重叠内容；公共契约独立提交，保留 schema v2/v1 边界并更新状态。
### 持续执行目标
G-INT-1 diff -> G-INT-2 migrate -> G-INT-3 verify -> G-INT-4 audited push.
