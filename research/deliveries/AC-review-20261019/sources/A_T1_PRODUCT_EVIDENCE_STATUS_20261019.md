# A 线 T1 Contacts 产品证据状态（2026-10-19）

## 状态与判定边界

- 本复核基于主线快照 `db77164fdc2af0da02e4d3efc056d84694fd68e8`（2026-10-19，PR #29 合并提交）、本机 A0 sample30 交付及 `T1_product_evidence_review_20261018.md`。截至此快照，没有发现新的 Contacts 产品构建、设备权限/策略或修复重测证据；T1 状态仍为 **partial**。
- 当前 `origin/main` 不含 `research/deliveries/a-line-sample30/20261018/`。复核所用交付位于本机 `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-sample30\20261018\`，其 T1 复核文件在该 checkout 中是未跟踪文件。因此本记录明确引用这份本地证据，不把它描述为已合入主线的交付。
- **源码机制 confirmed**：在固定 Contacts/DataShare 源码对象上，真实函数路径存在未约束路径拼接并进入删除 sink；提取的目标函数在隔离 harness 文件树中稳定删除测试 victim，修复适配器保留 victim。这只确认源码机制和 harness 场景。
- **产品 `validated_vulnerability`：unknown**。当前没有把源码映射到某个实际产品构建，也没有在产品 IPC、目标调用权限、服务 UID/SELinux 与产品文件系统边界上复验。不能将源码/harness `confirmed` 提升为产品漏洞确认，也不能称为扫描器直接命中。
- A0 抽查的 345 条扫描候选 confirmed 为 0；相邻上下文审计的 ADJ-001 是单独的源码机制发现，不属于这 345 条扫描候选。请保留这两组计数和发现来源的区别。

## 固定源码来源与哈希

| 仓库/文件 | 固定 commit / tree | Git blob SHA-1 | 原始文件 SHA-256 |
|---|---|---|---|
| Contacts `dataBusiness/contacts/src/contacts_data_ability.cpp` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` / `2054824c04bb403eeea128a9262edfb3001efa4f` | `c93e950725adc93276916b3c96c5ac7a5bb5b6b7` | `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` |
| Contacts `dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp` | 同上 | `d738c4931bb40ac53519657fb2daa3febfae2bce` | `a913de9c273ef055de9203f83e890067a8594f1028dce6526844228585aa87a4` |
| Contacts `ability/common/utils/src/file_utils.cpp` | 同上 | `7d39485e3b3f253d474d8e49952e16ced7ccd605` | `4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f` |
| Contacts `ability/common/utils/src/uri_utils.cpp` | 同上 | `c051e31adc244c6ce633381e3c750bb041f3c3c1` | `7a6552a4e50ca3ef322dedc01b4a88d0fb548a32de794c93a6d454415499b1b0` |
| Contacts `entry/src/main/module.json` | 同上 | `1183c1acf75a373b0d24519497e639107e2d1978` | `3ba2545592f4fbe95f8ba838264ec017638c546e417599a02feb8aade378c856` |
| DataShare `frameworks/native/provider/src/datashare_stub.cpp` | `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd` / `f731230c116c94d7619f5514c828b33ffac69924` | `cb62502d82c0534a6b9466f7a5d0a9e122d85693` | `cc742b1811c6c6ce2c351e27619a74ec1e5f472502a7a712c50d49fbaeed667a` |
| DataShare `frameworks/native/common/src/datashare_itypes_utils.cpp` | 同上 | `8e6d1fafc8fb5d9b4d2d02357564a6b512d7f755` | `89dcced0d37d46c98bcb7bd2cb6d941f6b1342902287e9667f1afd330d85dc77` |
| DataShare `interfaces/inner_api/common/include/datashare_values_bucket.h` | 同上 | `03f15ab65e6dd106ce066ff3a47097dbf853899c` | `dde5f37c9f9099cad4846b2013c6f97279d79266fabd33bfc0b2bfb9f3f23eab` |
| AccessToken `permission_definitions.json` | snapshot `fe40d5e6c19071c29916903c777f168b2b85e404` / tree `903e2add75bf348d3ece15a4bcc43a4fec0937d0` | `bda95c3549fed44e956f9832c816c50ddafb5952` | `2155f44fdb28a21f7f5423f0f327f06fcce6efae922e868ff59e85c26fedba33` |

Contacts/DataShare 八个源码文件的原始 Git 对象与 A0 manifest 中的 blob、SHA-256 和大小已核对匹配。AccessToken 权限定义来自 OpenHarmony 快照；T1 复核记录当前 master 文件与其字节/hash 相同。checkout 行尾可能改变工作文件 SHA，应以固定 Git blob 原始字节为准。

## 已确认的源码机制

1. `module.json` 将 `ContactsDataAbility` 注册为 `visible: true` 的 DataShare 扩展，URI 为 `datashare://com.ohos.contactsdataability`，声明 `writePermission=ohos.permission.WRITE_CONTACTS`。
2. `ContactsDataAbility::BatchInsert` 在固定源码约第 601–660 行检查 `WRITE_CONTACTS`；HAP 调用路径使用 calling token 交给 `AccessTokenKit::VerifyAccessToken`，权限检查失败即拒绝。
3. DataShare `CmdBatchInsert` 将 URI 与 ValuesBucket 送至 provider；固定 DataShare 反序列化代码接受字符串 key/value。Contacts 再将记录传递至头像处理。
4. `GetPortraitValue` 读取 `PortraitFileName`；`HandleContactPortrait` 将其直接拼接到由 BundleMgr `GetGroupDir(GROUP_ID)` 派生的 `/data/storage/el2/group/<lastPart>/photo/` 路径。该处没有拒绝 `..` 路径段或执行 canonical-path containment 校验。
5. 图像读取/保存失败时，对构造出的 `srcFilePath` 调用 `FileUtils::DeleteFile`；固定实现最终调用 `unlink(filePath.c_str())`。这建立了从受控字符串到路径删除操作的源码链。

源码链不决定真实产品上可删除的文件集合。实际边界仍取决于目标 BundleMgr 路径、服务 UID/GID、DAC、SELinux 标签/策略、软链接状态和产品集成配置。

## 权限事实与未知项

- 固定 `permission_definitions.json` 将 `ohos.permission.WRITE_CONTACTS` 标为 `user_grant`、`system_basic`、`availableType=SYSTEM`、`since=8`。`since=8` 是权限定义的版本字段，不能用作漏洞受影响起始版本。
- 已有证据支持的调用者前提是：能够满足目标产品的系统权限等级/可用类型和签名/授权策略，并已取得用户授权的调用者。不能据此说任意普通第三方应用可调用。
- 未知：目标产品实际安装的 Contacts 包、产品签名和 permission grant 策略、调用者 token/UID/调用结果、服务进程 UID/GID/security domain，以及产品文件 DAC/SELinux 约束。

## PoC 与 Docker 证据边界

- **镜像 digest 尚未闭环**：原 T1 复核声称 PoC image 为 `sha256:1f28ead56a68352c2bbbbd4fb45523a237f271dc3be827b073b9274986a2a829`（见 `T1_product_evidence_review_20261018.md:30`、`report/technical-report.md:129`）。独立审计发现保存的 `evidence/sandbox/image_inspect.json` 实际记录 `ohscanner-validation:local` 的 ID 为 `sha256:e92d5365460142169ddd21d489bc9157d003c61e3382351c8f8516f3e38f96ae`；审计将其识别为通用方法控制镜像，和声称的 PoC digest 不匹配，且未保存完整外层 Docker argv（见 `D1_T1_T2_INDEPENDENT_AUDIT_20261018.md:32`）。因此 **不能把 e92d... 写成固定 PoC image digest**；目前也不能独立证明 1f28... 对应实际执行的容器。需先取得与运行记录绑定的镜像 inspect/digest 和完整 argv，方可声称镜像固定重放。
- PoC 从固定 Contacts 源码提取真实函数片段编译，但用测试 adapter/stub 代替真实 `GetGroupPath`、DataShare/provider IPC 和外围产品配置。逐目录保留的结果如下，状态均为进程退出码，不得跨目录合并成“所有历史运行通过”：

| 结果目录 | 逐项状态 | 可支持的表述 |
|---|---|---|
| `results-ubsan/run_summary.tsv` | attack、fixed、safe、fixed-safe 各 3 次；**12/12 子进程 exit 0**。逐轮原始日志在 `results-ubsan/logs/`。 | 这是 T1 报告引用的稳定功能运行摘要（`T1_product_evidence_review_20261018.md:30`；`report/technical-report.md:139-141`）；只支持抽取函数测试文件树中的行为，且不能据当前 image_inspect 证明其所用 PoC image digest。 |
| `results/run_summary.json` | attack 3 次均 exit 64（usage/参数错误）；safe 2 次 exit 1；fixed 2 次 exit 1；fixed-safe 3 次 exit 0。原始记录和日志路径见该 JSON 的 `log` 字段及 `results/logs/`。 | 混有 usage、失败和通过记录，不是 3/3 attack/fixed/safe 成功。exit 1 的日志含只读 `/data` 清理异常及 ASan `DEADLYSIGNAL`/abort。 |
| `results-final/run_summary.tsv` | attack、safe、fixed、fixed-safe 各 2 次 exit 0、1 次 exit 139；合计 8/12 exit 0、4/12 exit 139。逐轮日志在 `results-final/logs/`。 | 结果不稳定；exit 139 的轮次不能计作通过或 sanitizer 阳性确认。 |

T1 另记录 ASan/UBSan probe exit 139、日志为空（`T1_product_evidence_review_20261018.md:32`）；技术报告也明确此探针不算 sanitizer 成功验证（`report/technical-report.md:16,141`）。该 probe 状态应与 `results-final` 中各模式的 exit 139 分开记录。`patched_target_adapter` 仅是 PoC 修复适配器，不是官方上游补丁。
- 这些结果验证的是机制和测试控制，不是完整 OpenHarmony 产品镜像、真实服务 IPC、产品授权、真实 group path、SELinux 拒绝/放行或产品版本受影响性。

## 产品版本与上游修复状态

已有 source-snapshot 比对（不是产品构建映射）：

| 官方 ref | Contacts commit | 固定快照观察 |
|---|---|---|
| `OpenHarmony-5.0.2-Release` | `f518eaccc5185585f6fd8ed15904edcc23fd911c` | 未找到本次 `PortraitFileName` source-to-sink 实现 |
| `OpenHarmony-5.0.3-Release` | `bcde45a36405b00278bdbaf1b5295b2d6f5f4ff8` | 未找到本次实现 |
| `OpenHarmony-5.1.0-Release` | `39b02924878967be4baab5dfe16741a4d71d39db` | 未找到本次实现 |
| `OpenHarmony-6.0-Release` | `a75adf146dcf0be65ab6f6f1e5026430047773e2` | 未找到本次实现 |
| `OpenHarmony-6.1-Release` | `b11f36cfdb9cc57644a2d9b208b0b4eb63b24206` | 未找到本次实现 |
| `OpenHarmony-6.1-LTS` | `b02aadfc2d801ee30573fcb2d13490298e146fea` | 找到相同拼接/删除逻辑；目标文件 blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`，SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383` |
| `OpenHarmony-7.0-Release` / `OpenHarmony-v7.0-Release` | `77df58072f19e37f4aa996829386e218487de0a2` | 找到相同拼接/删除逻辑；目标文件 blob `ded9abef3e9d644fd5922937dfccacbd2f84dd8c`，SHA-256 `dbf48222b5ea7f08ac6d460062c8077e1d1824d0ac14e9c4860fbfef80995a79` |
| `weekly_20261012` / current Contacts master | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` | 找到；与 A0 固定源码相同 |

固定快照未找到实现不等于已证明产品安全。`OpenHarmony-6.1-LTS` 和 `OpenHarmony-6.1-Release` 是不同代码线，必须分开记录。当前材料没有证明这些 Contacts commits 被哪些具体产品版本/HAP/image 纳入；也没有经审阅并核验的官方修复提交。三个本地源码 clone 为 shallow/grafted，不能据此确定漏洞引入提交、完整历史或所有分支修复情况。完整受影响产品版本与产品修复状态均为 `unknown`。

## 未闭环动作（按依赖排序）

| 优先级/任务 | 依赖 | 可执行步骤 | 可复核产物/完成条件 |
|---|---|---|---|
| P0-1 产品构建与组件映射 | 产品/设备构建维护者提供可复现配置和构建环境 | 固定产品型号、版本、产品配置及完整 manifest；记录所有相关仓库 SHA；构建或取得目标产品镜像/HAP，核验 Contact DataAbility 的包/SA 纳入及组件源码提交映射 | `product_build_manifest.json`（含 manifest/config/日志/artifact hash）、HAP/image hash、组件→包/SA→产品映射表；可从产物追溯到 Contacts commit/blob |
| P0-2 调用者与权限边界 | P0-1 确定目标包/产品；授权隔离设备或镜像 | 使用符合该产品签名/APL/availableType 条件的测试 HAP；分别测试获准 `WRITE_CONTACTS`、未获准和无权限调用；通过真实 Contacts DataShare URI/IPC 记录结果 | 测试 HAP 源码与签名/hash、token/permission grant 记录、caller UID/PID/调用记录、正负对照日志；不得以 manifest 声明代替运行证据 |
| P0-3 服务身份与文件影响边界 | P0-1 的目标 image；与 P0-2 的真实服务入口/授权调用可并行准备 | 固定 BundleMgr 实际 group path；收集服务 UID/GID/security context、DAC mode/owner、file_contexts/SELinux allow 规则和相关审计日志；仅用专用隔离目录中的标记文件比较 photo 目录内、目录外、拒绝访问和软链接控制，不接触真实用户/系统文件 | `service_context.json`、策略/label 摘录及 hash、路径解析记录、PoC 前后文件 hash 与原始日志；据此精确描述受 OS 权限限制的可达文件范围 |
| P1-1 完整历史与修复/版本矩阵（可与 P0-1 并行） | 官方仓库 refs/tags/历史对象可获取 | 对 Contacts 仓库使用完整历史和官方 refs，定位引入提交、修复提交/PR；审阅修复是否阻断 `..`/路径逃逸并覆盖规范化、软链接语义；为每个 release/LTS ref 绑定 commit/tree/blob/hash | full-depth refs/tags 清单、引入/修复 commit 与官方来源、patch diff/hash、source-level presence/fix matrix；逐项标明 source observation 与产品映射的区别 |
| P1-2 修复版产品对照复测 | P0-1 至 P0-3 完成；P1-1 确认官方修复且已纳入匹配产品构建 | 对同配置易受影响版与修复版运行获准调用者、未授权调用者、安全输入和路径逃逸输入对照；确认修复版拒绝 traversal，同时合法头像流程正常 | 两版本构建 manifest/hash、测试输入/hash、调用/审计日志、victim 目标 hash 前后状态、重复结果；复核记录明确真实产品观察和限制 |

在 P0 产品证据到齐前，结论保持：源码机制 confirmed；具体产品版本、真实调用可达性、产品影响边界及产品级 `validated_vulnerability` 为 unknown。任何 harness 适配器修复都不能替代官方修复和修复产品复测。

## 证据索引

本机 A0 交付：`research/deliveries/a-line-sample30/20261018/`，重点文件：

- `T1_product_evidence_review_20261018.md`：调用链、权限限制、Docker 边界、版本快照及产品证据缺口。
- `poc/ohscanner-contacts-path-traversal/source_manifest.json`：固定源码 commit/tree/blob/SHA-256。
- `poc/ohscanner-contacts-path-traversal/results-ubsan/run_summary.tsv`、`results-ubsan/logs/`：12/12 子进程 exit 0 的摘要和逐轮日志；镜像实际运行绑定仍待补齐。
- `poc/ohscanner-contacts-path-traversal/results/run_summary.json`、`results/logs/` 与 `results-final/run_summary.tsv`、`results-final/logs/`：其它历史轮次的 exit 64/1/139 原始状态和逐轮日志，不能概括成全部成功。
- `evidence/sandbox/image_inspect.json`：记录 `ohscanner-validation:local` 与 e92d... image ID；它不是原 T1 声称的 PoC digest 1f28...。镜像差异和缺失完整 Docker argv 见 `D1_T1_T2_INDEPENDENT_AUDIT_20261018.md:32`。
- 独立审计原件位于 `D:\openHarmonyScanner\worktrees\a-path-source-sink-1c21ac6\research\deliveries\cpp\D1_T1_T2_INDEPENDENT_AUDIT_20261018.md:10,13,32`；该审计判 T1 block/产品 partial-unknown，并说明 e92 镜像记录与 PoC digest 不匹配。
- 2026-10-19 并行任务树位于 `research/deliveries/cpp/a-line-continuation-plan-20261019.md:23-47`；T1 仍标进行中，其完成门仍要求真实入口/权限/路径影响/产品构建与版本/补丁来源分别有证据。
- 对应复核文字：本机 A0 `T1_product_evidence_review_20261018.md:30,32`、`report/technical-report.md:16,129,139-141`，以及上述独立审计和任务树。
- `evidence/adjacent_findings.json`、`evidence/reconciliation.json`：ADJ-001 与扫描候选计数的分离。
- `report/technical-report.md`：源码机制描述及报告范围。
