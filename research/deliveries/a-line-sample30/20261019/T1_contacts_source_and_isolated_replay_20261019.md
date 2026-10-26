# T1 Contacts 路径穿越：来源历史与隔离复验增量（2026-10-19）

## 判定

**T1 维持 `partial`。** 本轮把 A0 的 8 个 Contacts/DataShare 源对象、Contacts release 标签和当前 Contacts 主线历史重新绑定到 Git commit/tree/blob/SHA；并在可用的本地隔离容器中重放了 A0 已编译的机制测试二进制。静态调用链与 WRITE_CONTACTS 权限边界有源码证据；实际 HAP/产品入口、受影响产品版本、UID/SELinux 文件范围和官方修复后产品行为仍为 `unknown`。不更改 A0 原报告、历史 verdict 或 scanner detector。

## 工作树与输入

- 当前任务工作树：`D:\openHarmonyScanner\worktrees\a-contacts-t1-20261019`
- 分支：`codex/a-contacts-t1-20261019`
- 完整基线：`db77164fdc2af0da02e4d3efc056d84694fd68e8`，与 `origin/main` 相同。
- 旧 A0 输入只读：`D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-sample30\20261018\`
- 任务树：`research/deliveries/a-line-development-plan-20261019.md`；T1 为 P0/进行中/partial。
- 历史 T1：`T1_product_evidence_review_20261018.md`；本文件是增量记录，不覆盖历史。

旧 A0 交付的 artifact SHA-256 manifest 逐项复算 **97/97 PASS**；源码抽取 manifest 的 11 个函数片段逐项复算 **11/11 PASS**。再从 GitCode 固定的 Contacts 与 DataShare commit 取原始 Git blob，8 个 A0 Contacts/DataShare 文件的 blob OID、SHA-256 与字节数均 **8/8 PASS**。`WRITE_CONTACTS` 定义文件在旧 AccessToken pin `fe40d5e6c19071c29916903c777f168b2b85e404` 与当前 AccessToken master `f811ac9fcebe948bff04e03a2af68929e6309976` 的 blob、SHA-256 和字节数相同；它将权限定义为 `user_grant`、`system_basic`、`SYSTEM`，`since=8` 是权限元数据，不是漏洞起始版本。详情见 `evidence/a0_integrity_recheck.json` 与 `evidence/source_objects_audit.json`。

## 入口、权限、输入与 sink

已固定的调用链是：

1. Contacts `entry/src/main/module.json` 注册 `ContactsDataAbility` DataShare 扩展，URI `datashare://com.ohos.contactsdataability`、`visible: true`、`writePermission: ohos.permission.WRITE_CONTACTS`。
2. DataShare `DataShareStub::CmdBatchInsert` 反序列化 URI 与 `ValuesBucket` 并派发 `BatchInsert`；DataShare string value 反序列化为字符串，没有路径分隔符/点段过滤。
3. Contacts `ContactsDataShareStubImpl::BatchInsert` 转发给扩展。`ContactsDataAbility::BatchInsert` 在 `contacts_data_ability.cpp:601-660` 再检查 `WRITE_CONTACTS`。
4. `TelephonyPermission::CheckPermission` 读取 IPC calling token：HAP token 通过 `AccessTokenKit::VerifyAccessToken`；此源文件对 native token 直接返回 granted。权限定义要求系统级类型并由用户授权。因此证据不支持“任意普通第三方应用可调用”；具体产品签名、token 类型、授权策略仍未知。
5. `ProcessSingleInsert` → `HandleContactPortrait` 读取 `PortraitFileName`。代码以 `groupPath + portraitFileName` 构造 `srcFilePath`，没有对此字段做 canonical containment、basename 或 allowlist 检查。`GetGroupPath` 从 BundleMgr `GetGroupDir(GROUP_ID)` 取得目录并选最后一段，添加 `/photo/`；这不是产品运行时路径证据。
6. 非法/不可解码图片使 `SavePortraitFileAndBlob` 返回错误，错误分支仍对 `srcFilePath` 调用 `FileUtils::DeleteFile`；该 helper 是直接 `unlink(filePath.c_str())`。成功路径也会删除临时输入文件。触发机制是把路径越界与失败输入组合起来。

攻击输入只有在符合权限的直接 DataShare `BatchInsert` 调用者可设置该 `ValuesBucket` 字段时才成立。Contacts 高层头像 API 的现有代码通常从 contact/raw-contact ID 生成正常文件名；这并不单独证明普通高层 API 可任意设置该字段。可控性来自通用 DataShare bucket/反序列化及 provider 接口，是源代码支持的调用推断，尚未用真实授权 HAP 对产品服务实测。

`unlink` 只能删除服务进程依据实际路径解析、DAC 和 SELinux 策略可访问的对象。当前证据不确定产品中的可删除文件集合、软链接/父目录约束或进程身份；PoC 测试目录不能支持“删除设备任意文件”的表述。静态 sink 支持的潜在后果为可访问文件的完整性/可用性损失；没有机密性影响证据。

## 精确来源版本与上游历史

本轮分别核验了官方 Contacts release **标签**（不是只把 release 分支头当作版本），并在 full Contacts master history 中检索路径构造/删除语义：

| 官方 Contacts tag | tag commit | 精确源码观察 | `contacts_data_ability.cpp` SHA-256 |
|---|---|---|---|
| `OpenHarmony-v5.0.2-Release` | `f518eaccc5185585f6fd8ed15904edcc23fd911c` | 未找到 `PortraitFileName`、`portraitFileName`、`DeleteFile(srcFilePath)` 标记 | `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` |
| `OpenHarmony-v5.0.3-Release` | `f518eaccc5185585f6fd8ed15904edcc23fd911c` | 未找到这些标记 | `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` |
| `OpenHarmony-v5.1.0-Release` | `39b02924878967be4baab5dfe16741a4d71d39db` | 未找到这些标记 | `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` |
| `OpenHarmony-v6.0-Release` | `e7ab7da19173979c071f07bbb250d58d7e98b270` | 未找到这些标记 | `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` |
| `OpenHarmony-v6.1-Release` | `1b18ffcdfa3a76a0fe97b1f820bc593d4cd6fe60` | 未找到这些标记 | `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` |
| `OpenHarmony-v6.1-LTS` | `b02aadfc2d801ee30573fcb2d13490298e146fea` | **找到**同一字段/拼接/失败删除链 | `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383` |
| `OpenHarmony-v7.0-Release` | `77df58072f19e37f4aa996829386e218487de0a2` | **找到**同一字段/拼接/删除链 | `dbf48222b5ea7f08ac6d460062c8077e1d1824d0ac14e9c4860fbfef80995a79` |
| Contacts `master` / `weekly_20261012` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` | **找到**；与 A0 Contacts source object 同 blob | `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` |

此表只表示这些精确 source tag/branch snapshot 中的代码状态，不表示安装产品版本范围，也不把未命中标签升级成整个产品系列已证明安全。6.1 Release 与 6.1-LTS 必须分开。

Contacts master 历史中首次出现这组精确 `PortraitFileName`/拼接/删除标记的提交为 `e30029d888d45ee1355743a2947bcbb60056c375`（2026-02-12，tree `557afe89411dea99bd5e71dd026a545c3844645c`，父提交 `a7fb1ce32b382a841d165e0b098502dcb724b2d1`）。父树检索不到这些精确标记；`HandleContactPortrait` 函数片段 SHA-256 在该提交与当前 master 一致（`ff59434934e7d1a4d3cd77b7a3e14fa7f538fe40a668707762495a0b38c8bd06`）。检索到的后续相关历史改动为合入重复提交和 fuzztest 编译修复，没有修复这段函数；当前 master、6.1-LTS、7.0 Release 标签仍含危险逻辑。**没有找到/验证官方修复提交或修复版本。** 该引入/来源历史不是产品首个受影响版本：产品构建清单与 source tag 的映射仍缺失。

来源快照、标签 OID/commit/tree/blob/SHA、branch refs 与历史搜索结果分别保存在 `evidence/upstream_contacts/snapshot_audit.json`、`release_tag_refs.txt`、`release_tag_audit.json`、`history_audit.json`、`source_objects_audit.json`。检查使用 GitCode 官方 OpenHarmony Contacts、DataShare、AccessToken 仓库；本轮下载的 shallow/历史 Git 对象在交付前会移除，避免把第三方源码仓库带入本工作树交付。

## 隔离重放与旧记录对账

A0 旧 `results-ubsan` 文件夹的 run summary 有 attack/fixed/safe/fixed-safe 各 3 次、共 **12/12 进程 exit 0 且 12/12 adapter `pass=true`**；attack 三次 `victim_after=false`，patched adapter `fixed` 三次 `victim_after=true`，safe/fixed-safe 三次保留 victim 且生成正常输出。这是从 Contacts 函数抽取后连接测试桩/测试文件树的机制复现。旧 `results` 目录有 CLI exit 64 与 `/data` 只读失败；`results-final` 有 4/12 exit 139；这些失败目录没有被合并成通过数据。A0 ASan/UBSan attack probe 仍为 exit 139，日志为空，不算 sanitizer 成功。

原技术报告声称 PoC Docker image ID 为 `sha256:1f28ead56a68352c2bbbbd4fb45523a237f271dc3be827b073b9274986a2a829`。当前 Ubuntu WSL Docker daemon 为 29.1.3；本机 `docker image inspect` 对这个 ID 返回 `No such image`。目前可核验的 `ohscanner-validation:local` 是 `sha256:e92d5365460142169ddd21d489bc9157d003c61e3382351c8f8516f3e38f96ae`，且 RepoDigests 为空；它是 A0 方法控制/验证镜像，**不能当作原 PoC 镜像**。该镜像没有 `g++`，完整脚本编译尝试失败，原始失败记录保留在 `evidence/replay_e92_20261019/logs/compile.log`。

为增加环境可重复性，本轮把 A0 已编译、SHA 与 A0 artifact log 一致的 `target_ubsan` 与 `patched_ubsan` 二进制以只读挂载方式，在 e92 镜像中作了独立补充运行：容器 `network=none`、根文件系统只读、`uid/gid=65534`、drop ALL capabilities、no-new-privileges、CPU 1、内存/交换 512 MiB、pids 64、nofile 64；`/tmp` 和 `/data` 是仅容器内的 noexec/nosuid/nodev tmpfs，输入只读，只有日期化输出目录可写。attack/fixed/safe/fixed-safe 各 3 次均 exit 0 且 adapter assertion 3/3；逐轮 JSON、输入二进制 hash、运行命令和容器参数见 `evidence/replay_e92_binary_clean_20261019/replay_manifest.json`。这是**预编译机制二进制**在另一个已核验镜像上的补充重放，不是原 PoC 镜像复现、重新编译、真实 IPC、权限检查或产品 PoC。它不能替代原镜像 digest 验证。

测试适配器将 `TelephonyPermission::CheckPermission` 固定为 true、伪造 Contacts `GetGroupDir`/DataShare provider/数据库/图像 API，并在容器 `/data` tmpfs 构造 victim；patched binary 是测试用路径拒绝变体，不是上游官方补丁。因此本实验只重放机制的 source/fixed/safe 行为，不证明现实产品权限、安装入口、受影响文件边界或修复后产品状态。

## 未完成项与最小解阻动作

| 缺口 | 当前状态 | 最小解阻动作 |
|---|---|---|
| 历史原 PoC 镜像 `1f28…` | 当前 Docker daemon 不存在；先前结构化镜像 inspect 未绑定该 ID | 从原运行 WSL Docker store 导出 `docker image inspect/save` 记录，或恢复精确镜像归档并核对 config digest；若无法恢复，原镜像身份保持 unknown，仅保留已记录旧日志与 e92 补充运行 |
| 实际 HAP/产品构建和版本映射 | unknown | 提供可复建的签名/版本化产品构建清单、HAP/镜像、Contacts/DataShare/AccessToken 组件 revision 和安装包散列 |
| 现实授权入口与输入控制 | 静态入口/权限门已证明；产品运行未验 | 在本地隔离产品上用满足 `system_basic`/`SYSTEM` 且已获 user grant 的测试 HAP，对真实 DataShare URI 发送单条临时 bucket；记录 token 类型、calling token、权限结果和 IPC 路径 |
| 文件可访问范围、UID/DAC/SELinux | unknown | 在该产品构建固定服务 UID、SELinux domain/policy、BundleMgr group path；只对隔离镜像中自建临时文件验证路径解析与删除边界 |
| 官方 fix commit 与修复版本 | 当前被查 tag/master 均仍有实现；未发现修复 | 取得官方修复提交/公告与 release branch mapping；在同配置产品构建中复跑攻击/fixed/safe/fixed-safe，核对二进制、HAP、策略与日志 |
| ASan/UBSan | probe exit 139、日志为空 | 保留失败限制；要复验须先在相同隔离环境排除运行时/内核限制后重新生成完整日志，不能引用它作安全或 sanitizer 结论 |

**收口规则：** 等上述产品材料到位后继续同一 T1，不把 A0 或本轮机制重放升格为产品漏洞结论。完成入口、权限、实际 file-scope、产品版本/修复与配对产品复验后，再按证据审产品影响与状态；在此之前 T1 维持 `partial`，产品安装范围和修复状态为 `unknown`。\n\n## 交付清单校验（2026-10-19）\n\nvidence/deliverable_manifest.json 为单一标准 JSON 对象，覆盖本日期目录内除清单自身外的 49 个文件。逐项复算路径存在性、字节数及 SHA-256：49/49 匹配，路径唯一；清单可由标准 JSON 解析器读取。\n