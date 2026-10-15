# A-EXP-01 preflight blocked/ready 决策报告

生成时间：2026-10-15T07:21:37.416Z（Asia/Shanghai 记录见 run_ledger）。

## 总结

- 结构 preflight：**passed**。
- 执行决策：**blocked**。
- 模型调用：**0**；R0/R1/R2 运行：**0**；实验结果：**0**。
- Precision/Recall：**未计算**；candidate/truth/review/diagnostic ID：**未修改**。

| 组 | 决策 | 原因 |
|---|---|---|
| R0 | preflight ready，execution not authorized | 门禁结构通过；本任务明确禁止运行 R0 |
| R1 | blocked | binding 契约完整，但 exact model record 未绑定且 execution 未授权 |
| R2 | blocked | 除 R1 条件外，adapter 授权记录虽已存在，但 `execution_authorized=false` |

## 六项处理

1. 模型绑定：`model_binding.schema.json` 已定义 provider/model/version/API endpoint/
   data-processing/pricing/approval；模板保留 null 占位并保持 `unbound_execution_blocked`，
   不伪造真实 Provider。
2. R2 授权：`tool_adapter_authorization.json` 已记录 adapter 版本/实现 hash、授权人、
   R2-only 范围、4 项白名单和只读/拒绝边界；执行授权为 false，R2 继续 blocked。
3. 跨 scope 重复：保留两条 review/scope 记录，报告 **45 review items、45 scope occurrences、
   44 unique candidates**；同 scope 重复才判 conflict。
4. canonical hash：`ohscanner.canonical-json-v1` 处理键顺序、Unicode、数字、换行、
   input file 排序、缺失字段与 null；固定 vectors 由 `canonical.js` 验证。
5. 引用：`preflight_validator.js` 只接受当前 item 的 supplied catalog 或已持久化 tool result；
   truth/sealed/other item/forged ID 使 completed run 失败，否则保持 unknown。
6. retry：独立 attempt ID；计 tool call、实际 token/费用、wall、输出/源码字节；
   不计新 repetition；首次失败与最终结果 append-only 保留。

## 仍未满足的执行条件

- 选择并批准真实 model/provider/exact version/API endpoint、data-processing 与 pricing 记录。
- 由有权人员把 model binding 与 R2 adapter authorization 改为执行授权。
- 用户明确授权运行 R0/R1/R2。

在此之前 `node preflight_validator.js --require-ready` 必须 exit 1。
