# C 线 Ark Runtime 阶段交付（2026-10-20）

## 交付范围与 Git 快照

- 本阶段代码分支：`codex/c-line-ark-stage-20261020`。
- 代码集成提交：`e798fa77fda843ff00f3b0ac7367f4eea02eb5ac`，父提交为本轮最新 `main`：`0f53af62283dbd0f249280805e8286a04b2d43b9`。
- 本轮启动时 `main` 为 `dd8b12b9f0fcf3d8bc96a2d7fbb3d679809d2e35`；实施期间 main 前进两个 B 线文档提交，检查无路径冲突后已将 C 阶段分支重放到最新 main。
- 原 C 分支 `codex/c-line-parallel-plan-20261020`：`cfdbd21eac05f6b515d123a29640f5011733ab03`，启动时工作树干净。实际代码版本为 detector `0.6.3`、static model `0.8.14`。当前 main 基线为 detector `0.6.2`、static model `0.8.13`。
- `config/collaboration/standing_authorization.json` 与项目 `AGENTS.md` 中的持续授权已核对；本交付没有修改原 C 分支或 main。

## 集成清单

- 将 C 线 Ark Runtime detector `0.6.3` / model `0.8.14` 及其已完成的源绑定规则、helper 依赖、正反控制和回归夹具接到独立分支。两条重点规则分别为 `ark.runtime.float32array-negative-double-length` 和 `ark.runtime.typedarray-arraylike-set-offset-wrap`。
- `src/ohscanner/detectors/catalog.py` 保留 `default_enabled: false`；扫描仍必须显式选择 `ohscanner.ark.runtime.type_safety`。未把候选启用为默认扫描项。
- 模型将规则绑定到 `openharmony/arkcompiler_ets_runtime` 的精确 commit、tree、blob 和 SHA-256，并由 adapter 检查 Git 对象来源、路径、parser 事实及依赖。绑定详情见下表和随附 CLI JSON。
- 单独集成了共享 `src/ohscanner/runner.py` 的 applicability selector 支持：Runner 只将 detector 选择的受支持源文件交给它，并校验返回项没有越界、重复或语言不匹配；`tests/test_contract_v2_source_binding.py` 增加来源绑定兼容测试。没有搬入其它已分叉平台代码；本次没有 Parser 改动。

## 最终代码快照上的 CLI 回放

以下结果来自集成代码提交 `e798fa77fda843ff00f3b0ac7367f4eea02eb5ac` 的第一方 `ohscan-run`，不是只运行单元夹具。原始 JSON 与 Markdown 保存在本目录的 `cli/`。

| 回放 | 输入与结果 | 解释 |
|---|---|---|
| Float32Array 正例 | `a65a2853ccae13da167d9aa4720ab8b11ec16656`，包含 CommonStub、TypedHCR 与 creator helper；`completed_with_limitations`，1 条未验证诊断，位于 `common_stubs.cpp:228` | 命中窄的 TDouble 长度下界缺失候选。Detector 内部状态仍是 `blocked/partial`，不是漏洞确认。 |
| `TypedArray.set` 正例 | 同一 source commit，包含 `builtins_typedarray.cpp`、ArrayBuffer sink helper 与声明；`completed_with_limitations`，1 条未验证诊断，位于 `builtins_typedarray.cpp:1227` | 命中普通 array-like `set` 的条件性 offset-wrap/跨视图写入候选。Detector 内部状态仍是 `blocked/partial`。 |
| Float32Array 缺 creator helper | 精确目标与 HCR，省略 `new_object_stub_builder.cpp`；0 诊断 | `negative_double_length_missing_source`，fail closed。 |
| Float32Array 错误 repository | 路径、commit 和 helper 保留，声明为 `wrong/example`；0 诊断 | 精确 repository 绑定失败，coverage 保持 blocked。 |
| 无关输入 | 只输入 `new_object_stub_builder.cpp`；0 诊断 | 非规则目标路径保持 `not_analyzed`，不表示安全。 |
| `TypedArray.set` 缺声明依赖 | 省略 `builtins_typedarray.h`；0 诊断 | `arraylike_set_bounds_missing_target_declaration`，fail closed。 |
| `TypedArray.set` 错误 commit | 输入本地可取得的 `830e85b40240677039719fcbf14f721ad3b19050`；0 诊断 | 精确 commit 绑定失败，coverage 保持 blocked。 |

七项 CLI 结果顶层均为 `completed_with_limitations`；控制项的零诊断不是 safe/miss。正例保留了真实 parser 限制：Float32Array 的 `common_stubs.cpp` 为 `partial`（历史解析记录为 13 个 issue）；TypedArray 声明头为 `partial`。完整输入、helper、来源错配、缺依赖、无关路径与 partial 状态均在 JSON/Markdown 中可查。

### 候选证据与边界

| 候选 | 精确源码绑定（repository / commit / tree） | CLI 观察 | 当前窄结论与缺口 |
|---|---|---|---|
| Float32Array 长度检查缺失 | `openharmony/arkcompiler_ets_runtime` / `a65a2853ccae13da167d9aa4720ab8b11ec16656` / `8781f036a3e7e04d8e0b34970d5f623b42875016`。`ecmascript/compiler/common_stubs.cpp`: blob `6267f2f27a98a298b1190e327abbfa2bd58203f8`, SHA-256 `5a401580e666596fcf2ea89a8dc0321009b53ef5320b20edc59d37781d852212`; `typed_hcr_lowering.cpp`: `1ad4e329a226fc9941db30fa7a10a6562f58f68d`, `acd4ed88bb4ba5d327d5628dc45b7b89685a9c425c5849891cbf2544e8534a0c`; creator `new_object_stub_builder.cpp`: `991ac5ac034a1a027e3200787ec25c55b3f15b69`, `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`。 | 同 commit 实际 CLI 命中 1 条，CommonStub 为 partial；TaggedInt 的非负控制存在，TDouble 路径缺少相同的非负长度检查。 | 保留“Float32Array 长度检查缺失”的源码级窄结论。转换表示、stub 选择、分配结果、后续访问和运行时内存影响未验证；不是已确认越界或产品漏洞。 |
| `TypedArray.set` 条件性跨视图写入 | 同 repository / commit / tree。`ecmascript/builtins/builtins_typedarray.cpp`: blob `0fc27c213e1ea80d93e1e3807eec11baf2634832`, SHA-256 `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c`; ArrayBuffer sink `builtins_arraybuffer.cpp`: `2aa22c58803df690a5a2b326451e02297dc5e2f6`, `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9`; 声明 `builtins_typedarray.h`: `b291181c949c7038b7030a216f5bdc0e7474a1c2`, `651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7`。 | 同 commit 实际 CLI 命中 1 条；目标函数可完整解析，但声明头 partial 使 detector coverage 保持 blocked。规则区分普通 array-like 对象与稳定 JS Array 的 fast path。 | 仅保留条件性的 offset-wrap/跨视图写入候选。加法溢出、窄化、sink 调用和 sibling view 条件来自源码；具体 JS 数值转换、最终字节位置和运行效果未实测。不得宣称已确认 OOB 或产品漏洞。 |

## 修复版本检查

使用公开 GitCode Ark Runtime 历史验证了后续 master `25863269ac05c2f4d6ab84631f2de58b9aa9cf18`（2026-10-20，`!15313`）。它以 a65 为祖先；上述六个目标/依赖文件的 Git blob OID 与 a65 完全相同。因此此可取得的较新版本不是修复版，也不能作为修复对照。当前资料和可访问上游分支中没有找到两条候选对应的真实修复 commit。

仓库单元夹具分别覆盖固定 guard、错误 repository/commit、缺 helper、错 sink、无关路径、safe 与 unknown 形状；这些是 analyzer 控制，不是真实版本回放。Float32Array 和 `TypedArray.set` 的真实修复版本对照仍缺失，fixture 没有替代它。

## 测试与验收

- Ark Runtime 检测器套件：`unittest discover -s tests/detectors/ark_runtime -t .`，**212 项，209 通过、3 跳过、0 失败**。以隔离 WSL Python 3.12.15 环境在重放后的代码快照执行。
- Runner / Catalog / contract v2 / audit-plan 兼容回归：`tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_audit_plan tests.detectors.ark_runtime.test_catalog`，**66 项通过、0 失败**。此集合包含新 selector 来源绑定回归、显式选择/默认关闭和既有无 selector detector 兼容路径。
- `git diff --check`：通过。
- 未把历史 209/3 或历史定向 12 项累加进本轮数字。现有不同代码版本的历史结果不代表本轮测试。

## 运行验证未完成：实际构建环境记录

本轮重新检查了 `D:\openHarmonyScanner\openharmony` 和 `out/rk3568`，没有找到可运行的 `ark_js_vm`、`es2abc` 或已构建 Ark Runtime 库；`out/rk3568` 只有两份旧 build log。源码不是缺失：`.repo` 的 `arkcompiler/ets_runtime` 对象库可解析固定 commit `a65a2853…`，其 tree 为 `8781f036a3e7e04d8e0b34970d5f623b42875016`；六个目标/依赖文件的当前工作树 SHA-256 均与该对象一致。

工具链也实际检查过：WSL2 x86_64、`gn` 2026 (`47b40ef4`)、`ninja` 1.13.2 均可执行。系统 Python 3.14 缺 `pipes`，Python 3.12 的 HB 环境缺 `distutils`；已在 `/tmp/ohscanner-ohos-build-venv` 建立 Python 3.12.15 环境并补齐 `setuptools`、`PyYAML`、`packaging`、`six`、`jinja2`，HB help 与预加载均成功。

实际尝试的现有模块测试目标：

```text
python build/hb/main.py build --product-name rk3568 \
  -T arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset \
  --disable-package-image --disable-post-build
```

HB 输出目录临时设到 `D:\openHarmonyScanner\tmp\ark-runtime-build-stage-20261020`。产品预加载完成，但在 `[LOAD] Checking all build args...` 等待约五分钟；worker 进程停在 WSL NTFS mount 的 `p9_client_rpc`，没有进入 GN 或 Ninja。为避免继续挂起已中断本次构建；原 `out/ohos_config.json` 已恢复。HB 在预加载阶段重写了共享生成目录 `openharmony/out/preloader/rk3568`；临时 build 输出未产生可执行产物。原始失败位置见 `hb-typedarrayset-build.log`。

因此本轮没有运行 Ark VM、官方 `typedarrayset` 测试或任何修复版本对照。最小继续动作是将同一完整源码/产品配置置于 Linux 原生文件系统（或让 HB 的源码索引阶段避免 NTFS/P9 元数据遍历），完成 host `ark_js_vm`/前端构建后再运行现有 `typedarrayset` 测试；真实修复 commit 仍需单独取得。**运行验证未完成**；静态工程交付已完成，研究运行验证没有完成。

## 原始证据

- 本目录 `cli/`：两条正例和五条缺依赖、错身份、无关输入 CLI 回放的原始 JSON/Markdown。
- `hb-typedarrayset-build.log`：本轮 HB 目标构建日志。
- CLI 使用的本地固定 Ark Runtime Git 对象库：`D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`；artifact 没有隐式 fetch，也不改变该对象库。
