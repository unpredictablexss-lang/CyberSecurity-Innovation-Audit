# B-3 真实语料清点：applications_settings（2026-10-17）

`census.json` 由 `census.py` 生成，未手工编辑。这是**覆盖清点**，不是漏洞结论：
0 条候选说明这五类规则在该应用上没有命中，不说明应用安全。

## 固定输入

| 项 | 值 |
| --- | --- |
| 目标仓库 | `openharmony/applications_settings` |
| commit | `5e8af0a2a104bc634f8d5e18ed03db202cd1ea02` |
| 前端 | `ohscanner.oh.arkts_js` 0.3.0（`detector_version` 直接读类属性；本版新增 `ohscanner.oh.native_bridge`） |
| 前端源码 | `src/ohscanner/detectors/interface/arkts_js.py`，sha256 `8b6c16298d3ef966553c1a290c90af499c0e966bdc8b419caaef03dbf850657e` |
| 语法 | tree-sitter 0.26.0 + tree-sitter-typescript 0.23.2 + tree-sitter-javascript 0.25.0 |
| 排除目录 | `.git` `node_modules` `oh_modules` `build` `dist` `output` `third_party` `preview` |
| 大小上限 | 2 MiB/文件 |

扫描检出放在仓库外（`/home/audit/wtmp/b3_arkts/settings`）；第三方源码不进提交，
`census.json` 只保留聚合计数、规则命中和文本形态计数。

## 结果

| 项 | 值 |
| --- | --- |
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
| N-API `.so` 模块声明 / 函数签名 | 1 / 2（来自 `native_api/src/main/cpp/types/libnative/index.d.ts`） |
| 进入 `lib*.so` 导入的调用点 | 15（映射到声明 2，未映射 13，同函数数值谓词前 0） |
| 候选 | **0**（按规则：0） |

文本形态计数（只用于解释覆盖，不是候选）：

| 形态 | 文件数 |
| --- | --- |
| `registerJavaScriptProxy` / `javaScriptProxy` | 0 |
| `want.parameters` | 16 |
| 文件类 API 调用 | 14 |
| `eval(` / `new Function(` | 1 |
| `from '...lib....so'` / `requireNapi(` | 8（7 处有效导入 + 1 处注释掉的导入；文本计数不区分） |

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
- N-API：15 个调用点中 2 个（`settingsNapi.getKernelInfo(type)`、`settingsNapi.sleep(time)`）
  按 `cpp/types/libnative/index.d.ts` 的路径声明映射成功，但实参是方法自身的参数，
  不是 `want.parameters` 派生值；另外 13 个在 5 个文件里调用 `@ohos.libhgmnapi.z.so`，
  该模块在本扫描内没有 `.d.ts` 声明，按设计计为 unmapped，不按符号名猜测。

## 没有证明的事

- 0 候选 ≠ 应用无可利用面：规则只覆盖 5 个窄类（Ability 暴露 + 文件 sink、
  bridge 无 origin 谓词、`want.parameters` 到文件 sink、动态 `eval`、
  `want.parameters` 到 N-API 数值参数）。
- 552 个 `.ets` 为 partial：ArkTS `struct`、装饰器不在 TypeScript 语法内，
  组件语义没有被读到；生命周期只按方法名匹配。
- 没有读 `module.json5`，没有跨函数污点，没有调用者可达性；所有潜在命中都是
  candidate，`entry_reachability` / `argument_control` / `not_implicitly_sanitised`
  仍是义务。
- 文本形态计数是正则命中，不是解析结果，二者不可互相替代。
- N-API 的 binding map 只来自同一扫描批次内的 `.d.ts`（`census.py` 每 400 文件一批），
  跨批声明不可见；声明本身是类型陈述，不是运行时校验，native 侧是否检查范围/长度
  仍是候选上的 `native_parameter_check` 义务。

## 复现

```sh
python research/evidence/interface/ipc/b3_arkts_real_20261017/census.py \
    /path/to/applications_settings \
    research/evidence/interface/ipc/b3_arkts_real_20261017/census.json \
    openharmony/applications_settings \
    5e8af0a2a104bc634f8d5e18ed03db202cd1ea02
```

在仓库根目录执行；扫描检出必须在仓库外。后两个参数可省略，默认即本目录记录的值。

## 哈希

```text
02b9c563727a5bd72569102bb02a7cb778ee021b2dbec82cd93761f8fe985bf1  census.json
679b2bcdc6067f1c58da03711085a0fdfeadd8f95be00cf5393c79bd3dded7c2  census.py
8b6c16298d3ef966553c1a290c90af499c0e966bdc8b419caaef03dbf850657e  src/ohscanner/detectors/interface/arkts_js.py
```
