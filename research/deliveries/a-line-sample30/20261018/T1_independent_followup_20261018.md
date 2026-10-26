# T1 Contacts PortraitFileName 独立复核补充（2026-10-18）

## 摘要

本补充记录在独立工作树中对 `ohscanner-contacts-path-traversal-001` 的再核验。工作树基于集成基线 `1c21ac60890fca0ce6be5d50d82e4757dd5e4623` / tree `4c833e2452413a7e9a404199439fe0a797b74ae9`，没有在原本已有大量脏文件的 A 线工作树中写入。本轮只新增本日期化交付；A0 原始报告、源清单、PoC 和失败日志保持原样。

**判定：产品证据仍为 `partial`；产品级 `confirmed/reportable` 未建立。** 绑定源码显示可见 DataShare `BatchInsert` 的值进入头像处理，`PortraitFileName`、`contactId` 和 `rawContactId` 直接作为字符串读取并参与路径构造；路径没有 canonicalization 或目录包含约束，文件 API 有删除与创建/写入行为。HAP 调用者受 `WRITE_CONTACTS` 门槛限制，只有符合权限可用级别/类型且权限已授予的调用者可过该检查；普通第三方应用不是已证明的攻击者。静态链和原机制 PoC 支持越界删除机制，但目标产品中的入口可达性、实际服务身份、可删除路径集合及产品版本映射仍未知。

本轮确认原始 PoC manifest 中 Contacts/DataShare 八个对象的 commit、tree、path、blob、字节数及 SHA-256 全部匹配；补充权限实现和定义对象也通过。旧记录报告的 PoC 镜像 digest `sha256:1f28ead56a68352c2bbbbd4fb45523a237f271dc3be827b073b9274986a2a829` 当前不在 Ubuntu Docker Engine 的本地镜像库；交付目录现存的 `image_inspect.json` 对应通用镜像 `sha256:e92d5365460142169ddd21d489bc9157d003c61e3382351c8f8516f3e38f96ae`。由于没有 PoC 专用的镜像 inspect 和完整外层 `docker run` argv，本轮不能把旧运行日志重新绑定到 1f28 digest，也不使用 e92 替代。因此 vulnerable/fixed/safe/fixed-safe 的新一轮重放为 **blocked**。旧日志中的 ASan/UBSan probe exit 139 继续按失败/限制处理。

工作树保护记录：原 A 线工作树首次观察为 658 个 status 项，收尾时为 663 个；本轮没有在该树执行写入操作，五项增量原因无法从本轮操作确定。新增 T1 文件只存在于下述独立 worktree；A0 `evidence/hashes.json` 所列 97 项仍全部匹配。此状态计数差异作为未解释的工作树变化保留，不推断为本轮造成或安全。

## 来源对象与证据表

源文件哈希均按 `git show <commit>:<path>` 的 Git 对象原始字节重算；Windows checkout 行尾不用于 source SHA-256。Contacts commit/tree：`341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` / `2054824c04bb403eeea128a9262edfb3001efa4f`。DataShare commit/tree：`560c5cdadf08b4beeb691e93d70ff32cc2dca8bd` / `f731230c116c94d7619f5514c828b33ffac69924`。

原 PoC `source_manifest.json` 的八个源对象逐项复核结果：

| Repository | Commit / tree | Path | Blob | Source SHA-256 | Bytes | Result |
|---|---|---|---|---|---:|---|
| Contacts | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` / `2054824c04bb403eeea128a9262edfb3001efa4f` | `dataBusiness/contacts/src/contacts_data_ability.cpp` | `c93e950725adc93276916b3c96c5ac7a5bb5b6b7` | `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` | 85,339 | PASS |
| Contacts | same | `dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp` | `d738c4931bb40ac53519657fb2daa3febfae2bce` | `a913de9c273ef055de9203f83e890067a8594f1028dce6526844228585aa87a4` | 29,986 | PASS |
| Contacts | same | `ability/common/utils/src/file_utils.cpp` | `7d39485e3b3f253d474d8e49952e16ced7ccd605` | `4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f` | 6,843 | PASS |
| Contacts | same | `ability/common/utils/src/uri_utils.cpp` | `c051e31adc244c6ce633381e3c750bb041f3c3c1` | `7a6552a4e50ca3ef322dedc01b4a88d0fb548a32de794c93a6d454415499b1b0` | 2,733 | PASS |
| Contacts | same | `entry/src/main/module.json` | `1183c1acf75a373b0d24519497e639107e2d1978` | `3ba2545592f4fbe95f8ba838264ec017638c546e417599a02feb8aade378c856` | 7,730 | PASS |
| DataShare | `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd` / `f731230c116c94d7619f5514c828b33ffac69924` | `frameworks/native/provider/src/datashare_stub.cpp` | `cb62502d82c0534a6b9466f7a5d0a9e122d85693` | `cc742b1811c6c6ce2c351e27619a74ec1e5f472502a7a712c50d49fbaeed667a` | 26,370 | PASS |
| DataShare | same | `frameworks/native/common/src/datashare_itypes_utils.cpp` | `8e6d1fafc8fb5d9b4d2d02357564a6b512d7f755` | `89dcced0d37d46c98bcb7bd2cb6d941f6b1342902287e9667f1afd330d85dc77` | 69,041 | PASS |
| DataShare | same | `interfaces/inner_api/common/include/datashare_values_bucket.h` | `03f15ab65e6dd106ce066ff3a47097dbf853899c` | `dde5f37c9f9099cad4846b2013c6f97279d79266fabd33bfc0b2bfb9f3f23eab` | 2,475 | PASS |

Supplemental permission objects also pass: Contacts `ability/common/utils/src/telephony_permission.cpp` at the Contacts commit above, blob `d46fa4fbb7c41aad03c3e5e75154537c1ed5d9fe`, SHA-256 `fd5f730ca7ddd460339b973595981873511850344ee5d63737b9dd5f068d73bd`, 4,634 bytes; AccessToken `services/accesstokenmanager/permission_definitions.json` at `fe40d5e6c19071c29916903c777f168b2b85e404` / tree `903e2add75bf348d3ece15a4bcc43a4fec0937d0`, blob `bda95c3549fed44e956f9832c816c50ddafb5952`, SHA-256 `2155f44fdb28a21f7f5423f0f327f06fcce6efae922e868ff59e85c26fedba33`, 455,517 bytes.

| Claim | Source object（repo@commit:path；blob） | Artifact / hash | 结论 | 限制 |
|---|---|---|---|---|
| 公开入口声明 DataShare 扩展和写权限 | Contacts `341cc3…`:`entry/src/main/module.json`；blob `1183c1acf75a373b0d24519497e639107e2d1978` | manifest SHA-256 `3ba2545592f4fbe95f8ba838264ec017638c546e417599a02feb8aade378c856`；7,730 bytes | `ContactsDataAbility` 可见，URI `datashare://com.ohos.contactsdataability`，writePermission 为 `ohos.permission.WRITE_CONTACTS`（源码行 42–51）。 | 模块声明不证明任何具体产品实际打包、安装或开放该扩展。 |
| IPC BatchInsert 将 URI/ValuesBucket 送往 provider | DataShare `560c5c…`:`frameworks/native/provider/src/datashare_stub.cpp`；blob `cb62502d82c0534a6b9466f7a5d0a9e122d85693` | source manifest SHA-256 `cc742b1811c6c6ce2c351e27619a74ec1e5f472502a7a712c50d49fbaeed667a` | `DataShareStub::CmdBatchInsert` 反序列化调用参数并进入 provider（源码行 486–510）。 | 没有在真实系统 IPC 服务上运行。 |
| ValuesBucket 字符串未经路径语义过滤 | DataShare `560c5c…`:`frameworks/native/common/src/datashare_itypes_utils.cpp`；blob `8e6d1fafc8fb5d9b4d2d02357564a6b512d7f755`；以及 `interfaces/inner_api/common/include/datashare_values_bucket.h`；blob `03f15ab65e6dd106ce066ff3a47097dbf853899c` | SHA-256 分别 `89dcced0d37d46c98bcb7bd2cb6d941f6b1342902287e9667f1afd330d85dc77`、`dde5f37c9f9099cad4846b2013c6f97279d79266fabd33bfc0b2bfb9f3f23eab` | `UnmarshalValuesBucketToBuffer` 接受字符串 key/value；未见拒绝斜杠、反斜杠或点段的逻辑（源码行 1156–1208）。 | 只证明该反序列化层没有此类校验。 |
| Provider 转发后进入 Contacts 能力 | Contacts `341cc3…`:`dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp`；blob `d738c4931bb40ac53519657fb2daa3febfae2bce` | SHA-256 `a913de9c273ef055de9203f83e890067a8594f1028dce6526844228585aa87a4`；29,986 bytes | `ContactsDataShareStubImpl::BatchInsert` 通过 owner 调用 `extension->BatchInsert(uri, values)`（源码行 260–280）。 | 产品的 DataShare service/owner 初始化仍未运行验证。 |
| `WRITE_CONTACTS` 权限门和 token 语义 | Contacts `341cc3…`:`dataBusiness/contacts/src/contacts_data_ability.cpp`；blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`；`ability/common/utils/src/telephony_permission.cpp`；blob `d46fa4fbb7c41aad03c3e5e75154537c1ed5d9fe` | SHA-256 分别 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`、`fd5f730ca7ddd460339b973595981873511850344ee5d63737b9dd5f068d73bd` | `BatchInsert` 首先检查 `WRITE_CONTACTS`，失败返回权限错误（601–607）；HAP token 通过 `AccessTokenKit::VerifyAccessToken` 检查，native token 分支直接授予（权限实现约 53–75 行）。 | Native token 是更高信任域；HAP 的实际签名、用户授权和产品策略尚未核验。 |
| 权限只能按声明的系统级范围授予 | AccessToken `fe40d5e6c19071c29916903c777f168b2b85e404` / tree `903e2add75bf348d3ece15a4bcc43a4fec0937d0`:`services/accesstokenmanager/permission_definitions.json`；blob `bda95c3549fed44e956f9832c816c50ddafb5952` | SHA-256 `2155f44fdb28a21f7f5423f0f327f06fcce6efae922e868ff59e85c26fedba33`；455,517 bytes | `WRITE_CONTACTS` 定义为 `grantMode=user_grant`、`availableLevel=system_basic`、`availableType=SYSTEM`（源码行 6731–6735）。 | 该定义不等于具体产品为某包授予权限的运行时证据。 |
| 可触发分支、攻击输入和路径传播 | Contacts `341cc3…`:`dataBusiness/contacts/src/contacts_data_ability.cpp`（同上 blob/hash） | PoC `source_manifest.json` SHA-256 `b9234fc08f8b3bef54565443c1e9ac601cdfa40a22c5cd9aa1e243bc3e299d2c` | 普通非 `isFromBatch=true` 的 contact-data BatchInsert 分支逐项进入 `ProcessSingleInsert`，先执行 `HandleContactPortrait`（734–744）；`GetPortraitValue` 直接读取 `PortraitFileName`、`contactId`、`rawContactId`（855 起）；头像路径处理只要求字段有效且非空，再拼 `groupPath + portraitFileName` 和 `groupPath + contactId + "_" + rawContactId`（770–800）。 | `isFromBatch=true` 的迁移分支条件不同；产品端的具体 URI/ValuesBucket 构造未实机验证。 |
| Group path 有前缀检查，但输入路径未做 containment | Contacts `341cc3…`:`ability/common/utils/src/file_utils.cpp`；blob `7d39485e3b3f253d474d8e49952e16ced7ccd605` | SHA-256 `4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f`；6,843 bytes | `GetGroupPath` 从 BundleMgr 的 group dir 取最后一段并构造 `/data/storage/el2/group/<lastPart>/photo/`（155–174）；`HandleContactPortrait` 随后直接拼接调用者字符串；未见 canonical path 或目录包含验证。 | group dir 的产品实际值和路径权限未知；单纯源代码不能确定攻击者可达文件集合。 |
| 失败和成功分支都会删除源路径；输出路径可创建/写入 | Contacts `341cc3…`:`dataBusiness/contacts/src/contacts_data_ability.cpp`、`ability/common/utils/src/file_utils.cpp`（上表对象） | 同上源码对象 | Save 失败调用 `DeleteFile(srcFilePath)`（792），成功也调用（797）；`SavePortraitFileAndBlob` 用 `open(filePath, O_CREAT|O_WRONLY, …)` 创建/写入目标（802–832）；`DeleteFile` 直接 `unlink(filePath.c_str())`（208–215）。 | 删除影响范围受进程 DAC/SELinux、目录权限、挂载和真实路径解析约束。对 `filePath` 的越界完整性影响未做产品动态证明。 |
| PoC 输入和历史结果只证明 harness 机制 | 原 PoC：`target_adapter.cpp`、`patched_target_adapter.cpp`、`run_ubsan.sh`、`results-ubsan/` | `run_ubsan.sh` SHA-256 `5568fc10d96b4bed9307b973f9d9f19f25d24633437872a47bc613f47d68925a`；summary SHA-256 `6a213959aa9b063ed94af724ca644632e792e7a32759bbc8c90571a9cf0ac696` | 历史 12 次运行记录 attack/fixed/safe/fixed-safe 各 3/3 exit 0。attack 输入 `../../../base/files/victim.txt`，测试树中的 victim 存在→删除；fixed adapter 拒绝斜杠、反斜杠和点段后 victim 保留；safe 用 `allowed.png` 并观察到 source 删除及输出生成。 | fixed 是本地 harness 适配器的字段过滤，不是官方上游修复。PixelMap、provider、数据库插入和 group path 使用桩；safe 只证明桩流程，不证明真实图片解码或联系人写入。 |
| PoC 镜像身份和日志关联 | `evidence/environment.json`、`evidence/sandbox/image_inspect.json`、`evidence/sandbox/docker_version.json` | environment SHA-256 `65b76dceb446fdd5b082524a3fe13837652bde8f72c38195c144693a1babdd34`；inspect SHA-256 `c772d6ce7090b97b19ef52654ed096f8eff0d860bb89631550de049546f01338`；Docker version SHA-256 `548b1db15e597eeada10ee97c061da483a8546a41be883f4356f8d73b9531249` | PoC 环境 JSON 声明 digest 1f28；现存 inspect JSON 描述通用镜像 e92；当前 WSL Engine 也只有 `ohscanner-validation:local`/e92，inspect 1f28 返回 `No such image`。97 项 `evidence/hashes.json` 与本地文件复核 97/97 匹配。 | 通用 inspect 不必然是 PoC inspect；没有 PoC 专用 inspect/完整 Docker argv，故旧日志与 1f28 的关联无法独立复核。 |

PoC 代码/运行记录的重点 SHA-256：`target_adapter.cpp` `c5c2c2495b2d15c0cfbc0158b250c974cb87096cda092513891888b2c4108447`；`patched_target_adapter.cpp` `1ca464c205d16deddd2fb4cf26b686701ddf14b2f37a0760d605e9aeb1a07255`；`results-ubsan/logs/compile.log` `aa0890e60ad6cfdbad5992656d9156aa4cda5f654bf70829696f6305b89e2a74`；`results-ubsan/logs/artifact_hashes.txt` `c52d31e720759d536ce24437dc6001f4ca1d565e1e01197901a57097ffeadd07`；`evidence/hashes.json` `06ae700e4754e5255761f4fa5577e2a311e7f3fbedc2e78f6bab6a77ff5a9f63`。本地 hash manifest 的 97 个条目均逐项通过核对。

## 版本 / 补丁矩阵

下面是 Contacts source repository 的精确源码快照观察，不等同于 OpenHarmony 产品镜像、设备固件或具体厂商产品的构建映射。

| OpenHarmony ref（A0 绑定） | Contacts commit / tree | contacts_data_ability.cpp blob / SHA-256 | 本轮判断 |
|---|---|---|---|
| `OpenHarmony-5.0.2-Release` | `f518eaccc5185585f6fd8ed15904edcc23fd911c` / `942fbd077860086c5b8d9eb66b036e8d04f0f4cb` | `d37d03ce1691b33355554d993e1b8e3fe6a035e9` / `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` | 对象存在；指定字段 source→path→delete 链未出现。不能据此宣称整条产品线安全。 |
| `OpenHarmony-5.0.3-Release` | `bcde45a36405b00278bdbaf1b5295b2d6f5f4ff8` / A0 旧记录未在本轮对象库重验 | — | **blocked**：指定 commit 本地缺失。A0 旧记录称未见该链；本轮不复用为独立验证。 |
| `OpenHarmony-5.1.0-Release` | `39b02924878967be4baab5dfe16741a4d71d39db` / `5e21206ccc5943c52008a11a092ba7f0cddfb342` | `d37d03ce1691b33355554d993e1b8e3fe6a035e9` / `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` | 对象存在；指定链未出现。 |
| `OpenHarmony-6.0-Release` | `a75adf146dcf0be65ab6f6f1e5026430047773e2` / A0 旧记录未在本轮对象库重验 | — | **blocked**：指定 commit 本地缺失。A0 旧记录称未见该链；本轮不作独立判断。 |
| `OpenHarmony-6.1-Release` | `b11f36cfdb9cc57644a2d9b208b0b4eb63b24206` / `da1c7a4626463bd22326f51dddd6292986c4dd0a` | `d37d03ce1691b33355554d993e1b8e3fe6a035e9` / `6107f4630c36e1ddc00dfb17092438713ccb05e6a22f56b5e6fa07ff5b7b01b1` | 对象存在；指定链未出现。与 6.1-LTS 分开。 |
| `OpenHarmony-6.1-LTS` | `b02aadfc2d801ee30573fcb2d13490298e146fea` / `ef183625ccbc842f47b076eb75e68b665d7c21c6` | `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6` / `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383` | 对象存在；字段、路径拼接、删除链存在。 |
| `OpenHarmony-7.0-Release` | `77df58072f19e37f4aa996829386e218487de0a2` / `33eeb415a27bf42c111e22aaddfdcc313625b80d` | `ded9abef3e9d644fd5922937dfccacbd2f84dd8c` / `dbf48222b5ea7f08ac6d460062c8077e1d1824d0ac14e9c4860fbfef80995a79` | 对象存在；危险链存在。 |
| `weekly_20261012` / 当前绑定 `master` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` / `2054824c04bb403eeea128a9262edfb3001efa4f` | `c93e950725adc93276916b3c96c5ac7a5bb5b6b7` / `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` | 对象存在；危险链存在。 |

本地 Contacts object database 非 shallow，包含 660 个 refs 可达 commits；A0 列出的漏洞快照与本地可取对象的内容一致。历史搜索使用 `git log --all -G'PortraitFileName|DeleteFile\(srcFilePath' -- dataBusiness/contacts/src/contacts_data_ability.cpp` 和 `git log --all -S'PortraitFileName' -- dataBusiness/contacts/src/contacts_data_ability.cpp`；没有定位到可验证的官方修复 commit。没有官方 fixed commit、补丁链接或其适用版本边界可供绑定；不根据 release 名称或日期推定修复范围。5.0.3 与 6.0 的缺失对象使这些行保持 blocked。产品 HAP、bundle 签名、构建清单、SELinux policy、完整固件和 OTA 修复状态均 unknown。

## 复现命令与结果

原始文档索引命令为 `poc/ohscanner-contacts-path-traversal/run_ubsan.sh`。脚本内部构建命令（运行时工作路径为 `/sandbox`）：

```sh
g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer /sandbox/work/target_adapter.cpp -o /sandbox/out/target_ubsan
g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 /sandbox/work/patched_target_adapter.cpp -o /sandbox/out/patched_ubsan
g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer /sandbox/work/target_adapter.cpp -o /sandbox/out/target_asan_ubsan
g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 /sandbox/work/patched_target_adapter.cpp -o /sandbox/out/patched_asan_ubsan
```

旧 compile log 记录 g++ Debian 12.2.0，上述编译均 exit 0。`results-ubsan/run_summary.tsv` 记录 12 项 attack/fixed/safe/fixed-safe，每项 exit 0；每类三次记录均一致。测试树观测为：attack 的返回值 `-1`、victim `present→absent`；fixed 的返回值 `-1`、victim 保持 present；safe/fixed-safe 返回值 `0`、victim 保持 present、allowed source `present→absent`、photo output `absent→present`。attack 三份日志 SHA-256 为 `af7a9a8236a7d2f0cd719515c235d85ca2b5f5b320bb74045d2e4b0bd164b4dc`，fixed 为 `5032c4f4a4a21e1fd5216146cdf3890991c07c27e1ec313304ca60829cabfff`，safe 为 `985977423342d0e1f4ec83d087c3212e96c1765fc4b9c86c203f8ba7bb9f56ba`，fixed-safe 为 `0dbf427fa9e73a6fc7b607dd80eb6e8b73bafdcdfbaeb6d67a05508eea165ec9`。`results-ubsan/logs/asan_ubsan_probe_status.txt` 记录 exit 139；probe log 是空文件 SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`，结果仍为探针失败/限制。

旧运行记录声明容器参数为 `--network none`、只读根、`--cap-drop ALL`、`--security-opt no-new-privileges`、1 CPU、512 MiB、64 PIDs、64 FD，`/tmp` 与 `/data` 为 tmpfs，无宿主进程回退；PoC 在 `/data` 临时树内创建 victim 和 allowed image 输入。本轮没有新运行：在 WSL 执行 `docker image inspect sha256:1f28ead56a68352c2bbbbd4fb45523a237f271dc3be827b073b9274986a2a829` 返回 `No such image`；可用的 `ohscanner-validation:local` 是不同 digest e92。根据对象身份约束，**不使用不同 digest 代跑**。因此新一轮 vulnerable/fixed/safe/fixed-safe 的结果均为 blocked，原结果和失败样本保留。

PoC 目录没有保存足以重放外层容器的完整 Docker argv；`run_ubsan.sh` 是容器内构建/执行脚本。要达到按文档重复，需要重新提供 digest 完全匹配的镜像归档，并保存完整容器启动 argv、挂载和运行时 inspect。当前 fixed 控制是本地 basename/分隔符/点段拒绝适配器，不应标成上游修复复验。

## 已证明、推断与未知

- **源码已证明：**可见 DataShare 扩展；外部 ValuesBucket 可传字符串；HAP 写入路径要求 `WRITE_CONTACTS`；native token 检查分支直接允许；非迁移的 contact-data BatchInsert 对有效非空头像字段进入文件处理；source 路径无标准化/包含校验；成功/失败都会尝试删除 source；输出路径从 `contactId` 和 `rawContactId` 拼接并打开写入。
- **机制结果记录：**本地 adapter 中的 `../../../base/files/victim.txt` 使临时 victim 删除；adapter guard 保留 victim；安全 basename 控制生成 photo output 并移除 allowed source。历史文档有 3/3 每种的 exit 0 与输出日志，但当前无法独立复核这些日志实际运行于声明的 1f28 image。
- **有条件的影响推断：**若产品构建保留该源码、入口对权限合格调用者开放，且 Contacts 服务进程对穿越后的目标具有父目录写/搜索权限，路径解析可能越出 `photo` 目录并 unlink 对应文件，造成文件完整性/可用性损失。实际受影响集合由 BundleMgr group path、UID、DAC、SELinux、挂载和路径中间组件决定。`contactId` / `rawContactId` 还控制输出文件路径，源码存在跨目录写入风险，但本轮没有产品写入覆盖证据。
- **未证明：**普通第三方应用可获取该权限；任何产品版本实际包含受影响对象；跨 Contacts 私有目录、系统文件或任意主机文件可删；机密信息可被攻击者读出/外传；真实图片/联系人产品流程在官方修复后仍工作；存在或适用某个官方 fix commit。

## 剩余 unknown / 最小后续事项

| Unknown / blocker | 最小后续事项 |
|---|---|
| 精确 PoC 镜像缺失、旧日志未能与镜像 inspect 完整绑定 | 提供 `sha256:1f28…` 的离线镜像归档及校验记录，或由原构建环境导出 PoC 专用 inspect、完整 docker argv、输入/输出挂载和全部原始日志。保持网络关闭与只读 root。 |
| 官方修复对象和版本适用范围未知 | 从官方上游获取可验证的 fixed commit/patch 和相关 release manifest；核对 patch 的路径约束行为、修复前后 blob/tree，并映射到产品构建。不能用当前 adapter guard 替代。 |
| 产品入口、权限和服务策略未知 | 获取可再现的产品构建/HAP、签名与权限授予证据、DataShare 配置、进程 UID/DAC、SELinux 域策略；只在仿真产品或专用临时分区内对标记文件验证。 |
| 5.0.3 / 6.0 指定 source commit 对象缺失 | 仅获取这两个明确 OID 的官方对象并核对；不换相邻版本。 |
| 产品完整性写入影响和安全图片流程未测 | 在匹配的 vulnerable / 官方 fixed 构建上，分别使用越界删除输入、越界输出输入、合法图片/联系人控制；记录文件树前后状态与应用数据库状态。 |

本补充不将 A0 机制级 `confirmed` 标签外推为产品级确认；针对本 T1 产品证据门，状态保持 `partial` / `unknown`，不升级为 `confirmed/reportable`。A0 原始交付保持历史原样。
