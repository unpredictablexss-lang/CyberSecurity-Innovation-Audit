# Sustained Goals

持续执行原则：每轮只闭合一个机制并保留最小 patch；机制、profile 或 replay 未闭合时继续该切片，不用告警数量或模型意见替代证据。

- G11-AH-1 alias identity：本轮已闭合局部 alias root/binding 传递；下一轮扩展到跨函数参数/返回的 points-to 有限摘要，仍禁止名称相似性。
- G11-AH-2 cast/sign-width：本轮已闭合透明 cast provenance、cast width 与长度/索引 alias；下一轮只处理可审计的显式数值转换边界，未知范围继续 unknown。
- G11-AH-3 wrapper/helper summaries：本轮已闭合 exact identity helper；下一轮继续 effectful helper 的源码契约摘要，缺 body/signature/macro contract 必须 unknown。
- G11-AH-4 loop backedge invalidation：本轮已闭合 type-origin loop rebind invalidation 与 callback loop unknown；下一轮补最小 CFG backedge state，不用循环展开代替证明。
- G11-AH-5 historical replay/profile closure：当前 blocked by absent pinned official Ark Git store and missing Ark ownership lane。只有固定 Git 对象、profile、产品绑定和统一 scope gate 全部到位后才闭合。

下一轮首选 G11-AH-5 的“只读身份审计/缺口清单”；若 pinned store 仍缺失，则转 G11-AH-3 单机制，保持其他项不退化。
