# G12-PC product closure plan

日期：2026-10-19（Asia/Shanghai）。基线 `ddd8556768d679fcc09f1fcb37d10730f49b2c6c`，tree `7d102eb9d2f0c2149fe978bb350129b7cf2fac71`。本轮未执行 fetch、checkout、commit、push、merge、reset，未修改生产 Detector、contracts、Runner 或 Catalog。

## 任务树状态

| 节点 | 状态 | 正在做什么 | 最小下一步 |
|---|---|---|---|
| G12-PC-1 build/preprocess profile | IN_PROGRESS_BLOCKED | 可复算 manifest 已落地，16 个 Ark 开发案例 | 绑定 official Ark Git store 与真实产品构建/预处理输入 |
| G12-PC-2 independent holdout | PIPELINE_IMPLEMENTED_NOT_RUN | freeze/双盲/裁决机制已自测 | 建立无泄漏独立抽样框和三方人工流程 |
| G12-PC-3 product applicability | BLOCKED | 每案例义务矩阵已建立 | 补入口、权限、攻击者控制、触发和 CIA 影响 |
| G12-PC-4 authorized isolated PoC | NOT_RUN | 已定义准入门槛和记录要求 | 只对满足静态证据门且获授权的候选执行 |
| G12-PC-5 fix/revalidation | NOT_RUN | 已定义 parent/fix/product rebuild 流程 | 固定 patch、同 profile 重建、PoC 和控制回归 |
| G12-PC-6 admission | NOT_ADMITTED | 维护可审计否决结论 | 所有强制项闭环后重审，不自动 Ready |

## Ark 案例处理顺序

1. 先选 source identity 与 parent/fix 关系最完整的 6 个案例做产品适用性调查；不是因为它们最危险，而是证据身份最可复算。
2. 第二批处理已有 detector parent-only candidate、但产品 build/profile 缺失的案例。
3. I7W51D、IB8BCA、历史 variant 等 source identity 或语义覆盖不完整案例继续显式 unknown，不用 0 findings 当 safe。
4. CVE-2025-24304 不把 CVE 与具体 patch 的强推断升级为一对一事实；先闭合产品版本和公告映射。

## 动态验证授权门

只有同时满足以下条件才进入隔离 PoC：

- 固定产品 build manifest、版本/分支/二进制/source hash；
- 真实入口、权限边界、攻击者输入和触发条件；
- 可达敏感操作与具体 CIA 影响假设；
- 明确的隔离环境、资源上限、网络禁用、快照恢复和授权记录；
- vulnerable/fixed 对照、重复次数、stdout/stderr、sanitizer/crash/signals、patch 和 artifact hash。

静态 Python 子进程、单元 fixture、组件 Harness 不是不可信构建或产品 PoC 沙箱。禁止攻击线上服务。

## 当前结论

`NOT_ADMITTED`。缺产品 build、入口/权限、触发、CIA、授权 PoC、修复后产品重验；独立 holdout 也未真实启动。0 findings、partial、failed、not run 均不解释为 safe。