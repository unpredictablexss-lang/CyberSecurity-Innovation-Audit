# Limitations

1. 本轮没有 `OHSCANNER_ARK_OFFICIAL_GIT`，3 个 pinned official Ark historical tests 显式 skip；没有隐式 fetch，也没有把 skip 写成 pass/safe。
2. CVE-2025-24304、IBS5YG 等九项本轮验证的是 source-bound 最小控制和现有 C10 控制，不替代官方 parent/fixed 全源码、产品构建、入口/权限、攻击者控制、触发条件、CIA 影响、PoC 或修复产品重验。
3. identity helper 仅接受同类型单参数、单 return 语句；有副作用、cast 语义、多返回、递归、宏、模板实例化或重载歧义时保持 unknown/partial。
4. loop 仅做有限 invalidation：type-origin 循环重绑定不得证明 equality；callback loop backedge 继续 unknown。没有全程序 alias/points-to、并发或完整 CFG 证明。
5. size/length/index 是局部 token/有限 alias 模型，不证明整数范围、所有转换、路径可行性或内存安全影响。
6. `scripts/check_change_scope.py` 的基线 ownership policy 没有 Ark lane；未修改公共 policy 来“让检查通过”。本轮写范围由任务显式限定，合流负责人需补正式 Ark ownership/disposition。
7. 未运行动态 PoC、未攻击线上服务、未计算 Precision/Recall、未升级任何 candidate 为 confirmed/reportable。
