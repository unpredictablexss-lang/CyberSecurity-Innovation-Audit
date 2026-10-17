# B-3 第二个真实语料：vultraining（2026-10-17）

`census.json` 由 `../b3_arkts_real_20261017/census.py` 生成，未手工编辑。
这是**覆盖清点**，不是漏洞结论。

## 固定输入

| 项 | 值 |
| --- | --- |
| 扫描根 | `/home/audit/openharmony-audit/_research_sync/openharmony-security/vulntest/vultraining` |
| 仓库 | `openharmony-security`（本机检出） |
| commit | `ceaf1b4fbe38e46cd18bfcffd7353516bdc34227` |
| 前端 | `ohscanner.oh.arkts_js` 0.2.0（行为见提交 `d52c82f`） |
| 排除目录/大小上限 | `.git` `node_modules` `oh_modules` `build` `dist` `output` `third_party` `preview`；2 MiB |

## 结果

| 项 | 值 |
| --- | --- |
| 文件数 | 16（`.ets` 14，`.ts` 2） |
| `.ets` complete / partial | 7 / 7 |
| `.ts` complete | 2 |
| unsupported | 0 |
| call site | 239 |
| 导出的 Ability/Extension 类 | 1 |
| WebView bridge 注册 | 0 |
| 路径 sink | 2（同函数路径谓词前 0） |
| eval / `new Function` 站点 | 0 |
| 候选 | **0** |

文本形态计数：文件类 API 2 个文件，`want.parameters` 0 个文件，
`registerJavaScriptProxy`/`javaScriptProxy` 0 个文件，`eval`/`new Function` 0 个文件。

## 说明

- 两个路径 sink 没有被 `want.parameters` 派生值喂入，因此规则不触发；这不是规则被禁用。
- 7 个 `.ets` 为 partial：ArkTS `struct`/装饰器不在 TypeScript 语法内，与第一个语料一致。
- 样本很小（16 文件），只作为第二个独立检出上的前端可用性与 0 命中记录；不用于估计
  误报率，也不构成"安全"结论。

## 哈希

```text
86a6480c55d07992af6af2f721025dc33a3eed7630ffb11f213b92a3c25e259c  census.json
```
