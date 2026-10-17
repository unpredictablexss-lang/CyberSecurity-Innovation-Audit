# B-3 真实语料清点：applications_settings（2026-10-17）

`census.json` 由 `census.py` 生成，未手工编辑。这是**覆盖清点**，不是漏洞结论：
0 条候选说明这四类规则在该应用上没有命中，不说明应用安全。

## 固定输入

| 项 | 值 |
|---|---|
| 目标仓库 | `openharmony/applications_settings` |
| commit | `5e8af0a2a104bc634f8d5e18ed03db202cd1ea02` |
| 前端 | `ohscanner.oh.arkts_js` 0.1.0（提交 `dfb187a`） |
| 语法 | tree-sitter 0.26.0 + tree-sitter-typescript 0.23.2 + tree-sitter-javascript 0.25.0 |
| 排除目录 | `.git` `node_modules` `oh_modules` `build` `dist` `output` `third_party` `preview` |
| 大小上限 | 2 MiB/文件 |

扫描检出放在仓库外（`/home/audit/wtmp/b3_arkts/settings`）；第三方源码不进提交，
`census.json` 只保留聚合计数、规则命中和文本形态计数。

## 结果

| 项 | 值 |
|---|---|
| 文件数 | 2045 |
| `.ets` complete / partial | 1343 / 552 |
| `.ts` complete / partial | 122 / 2 |
| `.js` complete | 26 |
| unsupported | 0 |
| call site | 112221 |
| 导出的 Ability/Extension 类 | 40 |
| WebView bridge 注册 | 0 |
| 路径 sink | 30（同函数路径谓词前 0） |
| eval / `new Function` 站点 | 1 |
| 候选 | **0**（按规则：0） |

文本形态计数（只用于解释覆盖，不是候选）：

| 形态 | 文件数 |
|---|---|
| `registerJavaScriptProxy` / `javaScriptProxy` | 0 |
| `want.parameters` | 16 |
| 文件类 API 调用 | 14 |
| `eval(` / `new Function(` | 1 |

## 为什么是 0

逐点核对过，不是规则沉默：

- 唯一的 eval 形态在 `OpenHarmonyTestRunner.ets:29`：
  `const global: object = new Function('return this')();` —— 字面量函数体，规则按设计
  不产生候选。
- 16 个 `want.parameters` 文件中抽样（如 `BluetoothSwitchAbility.ets`）看到的是
  `bundleManager.getBundleInfoSync(want.parameters?.bundleName, ...)`，
  在 `isParamsValid(want)` 守卫之后，且目标不是 `_PATH_SINKS` 里的文件 API；
  内联参数路径（本次修复新增）同样覆盖不到它，因为 sink 本身不在模型内。
- 40 个导出的 Ability/Extension 类没有一个把 `want.parameters` 送进文件 sink，
  所以 `component_exposure` 的触发条件一个都不满足。
- 整个应用没有 `registerJavaScriptProxy` / `javaScriptProxy`，bridge 规则没有可判对象。

## 没有证明的事

- 0 候选 ≠ 应用无可利用面：规则只覆盖 4 个窄类（Ability 暴露 + 文件 sink、
  bridge 无 origin 谓词、`want.parameters` 到文件 sink、动态 `eval`）。
- 552 个 `.ets` 为 partial：ArkTS `struct`、装饰器不在 TypeScript 语法内，
  组件语义没有被读到；生命周期只按方法名匹配。
- 没有读 `module.json5`，没有跨函数污点，没有调用者可达性；所有潜在命中都是
  candidate，`entry_reachability` / `argument_control` / `not_implicitly_sanitised`
  仍是义务。
- 文本形态计数是正则命中，不是解析结果，二者不可互相替代。

## 复现

```sh
python research/evidence/interface/ipc/b3_arkts_real_20261017/census.py \
    /path/to/applications_settings \
    research/evidence/interface/ipc/b3_arkts_real_20261017/census.json
```

在仓库根目录执行；扫描检出必须在仓库外。

## 哈希

```
ef724883598110e94d83b335cf3622e5c18407e65d33340f5080f38c5a868db9  census.json
e0203db77f58358d55e698e54379e3bcc22ba9a28e64487d7546615f66fddead  census.py
```
