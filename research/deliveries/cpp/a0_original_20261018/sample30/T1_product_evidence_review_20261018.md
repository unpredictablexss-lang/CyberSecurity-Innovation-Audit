# T1 Contacts 产品证据复核（2026-10-18）

## 当前判定

状态：**partial**。固定源码上的调用链、权限检查和路径操作已独立复核；源文件的 Git blob、SHA-256 和字节数与 A0 交付一致。现有 Docker 结果证明抽取真实函数后的机制复现，不是完整 OpenHarmony 产品构建。当前源代码 master 仍包含相关路径；尚无完整 HAP/产品镜像、目标 SELinux 域和产品级运行记录，因此受影响安装版本、产品上的可删除文件边界、修复状态与修复后产品行为仍为 `unknown`。

## 固定来源与复核结果

| 仓库 | commit / tree | 远端 master | 核验 |
|---|---|---|---|
| `applications/standard/contacts_data` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` / `2054824c04bb403eeea128a9262edfb3001efa4f` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` | 与 A0 绑定对象一致；5 个 Contacts 文件从 `commit:path` 读取后 SHA-256、blob 和字节数均匹配。 |
| `foundation/distributeddatamgr/data_share` | `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd` / `f731230c116c94d7619f5514c828b33ffac69924` | `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd` | 与 A0 绑定对象一致；3 个传输/反序列化源文件 SHA-256、blob 和字节数均匹配。 |
| `base/security/access_token` | OpenHarmony 快照 `fe40d5e6c19071c29916903c777f168b2b85e404` / `903e2add75bf348d3ece15a4bcc43a4fec0937d0` | 当前远端 master `f811ac9fcebe948bff04e03a2af68929e6309976` | 快照 commit 的 `permission_definitions.json` blob `bda95c3549fed44e956f9832c816c50ddafb5952`，SHA-256 `2155f44fdb28a21f7f5423f0f327f06fcce6efae922e868ff59e85c26fedba33`；与当前 master 文件字节一致。 |

验证命令的核心读取方式为 `git show <commit>:<path>`；8 个 A0 Contacts/DataShare 源文件均得到 `PASS`。此外，权限定义从 OpenHarmony manifest 锁定的 `fe40d5e6...` 拉取并核验，和当前远端 master 的该文件 SHA/blob 完全相同。Windows checkout 的工作文件 SHA 因行尾转换与 Git blob 字节不同；A0 manifest SHA 对应 Git 对象原始字节，不应拿 CRLF checkout 的 `Get-FileHash` 直接判为漂移。

## 调用链与边界

1. Contacts 模块 `entry/src/main/module.json` 把 `ContactsDataAbility` 注册为 `visible: true` 的 DataShare 扩展，URI 为 `datashare://com.ohos.contactsdataability`，声明 `writePermission=ohos.permission.WRITE_CONTACTS`。
2. `ContactsDataAbility::BatchInsert` 在 `contacts_data_ability.cpp:601-660` 调用 `TelephonyPermission::CheckPermission(WRITE_CONTACTS)`；失败即拒绝。该检查对 HAP 调用者以 calling token 调用 `AccessTokenKit::VerifyAccessToken`。
3. 同一 permission manifest 在 `permission_definitions.json` 将 WRITE_CONTACTS 定义为 `user_grant`、`system_basic`、`availableType=SYSTEM`（`since=8`）。因此攻击前提不是任意普通第三方应用，而是能满足该系统权限等级/类型的调用者并已取得用户授权。具体产品签名与授权策略仍须在目标产品验证。
4. DataShare `CmdBatchInsert` 将 URI 和 ValuesBucket 送至 provider；对应反序列化实现接受字符串 key/value。Contacts provider 的 `BatchInsert` 转发至上层能力，之后逐项进入 `ProcessSingleInsert` 与 `HandleContactPortrait`。
5. `GetPortraitValue` 读取 `PortraitFileName`。`HandleContactPortrait` 构造 `srcFilePath = groupPath + portraitFileName`，没有在该点拒绝 `..` 段或对结果做 canonical-path containment 校验。`groupPath` 由 BundleMgr `GetGroupDir(GROUP_ID)` 得到应用组目录，并构造成 `/data/storage/el2/group/<lastPart>/photo/`。
6. 图片读取/保存失败时，对 `srcFilePath` 和输出 `filePath` 调用 `FileUtils::DeleteFile`；该函数直接 `unlink(filePath.c_str())`。这构成路径穿越到删除操作的静态 source-to-sink 链。

上述静态链支持“权限达标的调用者可影响服务处理的路径”结论，但不能单靠静态代码确定产品中可访问文件集合。遍历是否越出 photo 目录、能触及哪些文件，最终还受 BundleMgr 返回路径、进程 UID、DAC/SELinux 标签、软链接状态和产品配置约束。

## 现有动态证据的准确范围

A0 PoC Docker 镜像 digest 为 `sha256:1f28ead56a68352c2bbbbd4fb45523a237f271dc3be827b073b9274986a2a829`。现存 `results-ubsan/run_summary.tsv` 与逐轮日志显示 attack、fixed、safe、fixed-safe 各 3/3 退出码为 0；例如 attack 将测试目录中的 victim 从存在变为不存在，fixed 保留 victim。该 harness 抽取并编译精确 Contacts 函数片段，但对 `GetGroupPath`、DataShare/provider 和外围产品配置使用测试适配器/桩。它验证代码片段对测试文件树的行为，不验证产品 IPC 服务、安装权限、真实 group path 或 SELinux。

ASan/UBSan probe 的已记录状态为 `exit 139`，日志为空；仍为失败/环境限制，不作为 sanitizer 证据。

## 上游修复和版本范围

- 本轮分别向三个项目仓库查询了远端 HEAD；远端与上表本地 HEAD 一致。当前 `applications_contacts_data` master 的精确源码仍含 `srcFilePath = groupPath + portraitFileName` 和失败时 `unlink`，故**该当前源 tip 尚未包含对此代码路径的修复**。
- 本轮读取并固定了官方 GitCode release/weekly refs 的 Contacts 仓库提交，逐个在整棵 source tree 搜索 `PortraitFileName`、`portraitFileName` 与 `DeleteFile(srcFilePath)`。结果仅说明这些精确代码快照是否含此实现，不代表安装包构建映射或整个版本系列的安全结论：

| OpenHarmony ref | Contacts commit | 该 source snapshot 的观察 |
|---|---|---|
| `OpenHarmony-5.0.2-Release` | `f518eaccc5185585f6fd8ed15904edcc23fd911c` | 未找到 `PortraitFileName` / 本次 source-sink 实现。 |
| `OpenHarmony-5.0.3-Release` | `bcde45a36405b00278bdbaf1b5295b2d6f5f4ff8` | 未找到。 |
| `OpenHarmony-5.1.0-Release` | `39b02924878967be4baab5dfe16741a4d71d39db` | 未找到。 |
| `OpenHarmony-6.0-Release` | `a75adf146dcf0be65ab6f6f1e5026430047773e2` | 未找到。 |
| `OpenHarmony-6.1-Release` | `b11f36cfdb9cc57644a2d9b208b0b4eb63b24206` | 未找到。 |
| `OpenHarmony-6.1-LTS` | `b02aadfc2d801ee30573fcb2d13490298e146fea` | **找到**；`contacts_data_ability.cpp` blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`; 有相同 groupPath 拼接与失败/成功时 `DeleteFile(srcFilePath)`。 |
| `OpenHarmony-7.0-Release` / `OpenHarmony-v7.0-Release` | `77df58072f19e37f4aa996829386e218487de0a2` | **找到**；文件 blob `ded9abef3e9d644fd5922937dfccacbd2f84dd8c`, SHA-256 `dbf48222b5ea7f08ac6d460062c8077e1d1824d0ac14e9c4860fbfef80995a79`; 同一路径拼接和删除逻辑。 |
| `weekly_20261012` / 当前 `master` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` | **找到**；与 A0 固定源码 blob/hash 相同。 |

这支持“Contacts 6.1-LTS、7.0 Release 和当前 master 的对应源码快照包含该危险实现”。5.0.2/5.0.3/5.1/6.0 Release/6.1 Release 的这些提交中没有这条字段处理链；不能据此声称整条产品发布线已证明安全。`OpenHarmony-6.1-LTS` 与 `OpenHarmony-6.1-Release` 的代码不同，必须保留区分。完整受影响产品版本、构建/组件纳入关系与更新补丁状态仍是 `unknown`。
- 三个本地 clone 均为 shallow/grafted；Contacts 可见历史仅包含被固定的 merge tip。无法据此重建引入提交、历史修复分支、所有发布分支或漏洞首次出现版本。`since=8` 是权限定义的最低版本字段，不是该漏洞的受影响起始版本。
- 对已比对的 6.1-LTS、7.0 Release 和 master，源码仍包含危险拼接/删除逻辑；没有找到或验证对应上游修复提交。不能将 PoC 中 `patched_target_adapter` 作为官方补丁。精确产品版本/镜像是否包含这些 refs、产品级修复状态继续标为 `unknown`。

## 未完成项与解阻动作

| 缺口 | 状态 | 最小解阻动作 |
|---|---|---|
| 真实产品入口与 IPC/权限集成 | 静态存在，运行未验 | 获取可复现产品构建与安装产物；用符合该 APL/availableType 并显式获准 WRITE_CONTACTS 的测试调用者做本地隔离验证。 |
| 目标设备/镜像上的文件影响边界 | `unknown` | 固定真实 group path、服务 UID、DAC/SELinux policy，检查路径解析/软链接并限定只对临时标记文件做 PoC。 |
| 上游修复与完整受影响版本 | `unknown` | 获取非 shallow 的官方 refs/tags/patches，按源码对象定位修复前后提交并核对各发布线。 |
| 修复后产品复验 | `unknown` | 对官方修复 commit 构建同配置产品镜像，攻击版、修复版、safe 与 fixed-safe 配对测试。 |
| 产品影响等级/报告可发布范围 | `partial` | 在权限和产品策略确认后，再判断现实攻击者前提、CIA 边界及报告表述；不从 harness 结果外推。 |

**T1 下一步：**取得非 shallow 历史和目标产品构建/策略材料。材料到位前保留 A0 的机制复现与源码问题结论；受影响源码分支暂列 6.1-LTS、7.0 Release、master，产品版本映射仍 unknown；不声称任意文件影响或官方修复完成。
