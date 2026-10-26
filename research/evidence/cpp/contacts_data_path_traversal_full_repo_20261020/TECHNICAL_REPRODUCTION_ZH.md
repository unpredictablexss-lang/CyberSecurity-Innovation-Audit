# Contacts DataShare 路径穿越：完整仓库复核与产品链复现方案

日期：2026-10-20  
Finding：`ohscanner-contacts-path-traversal-001`  
状态：**完整仓库源码复核及组件级动态复现完成；完整 OpenHarmony 产品运行尚未执行。**

## 1. 执行摘要

从 OpenHarmony 官方 GitCode 拉取了完整的 Contacts 与 DataShare 仓库，并 checkout 到历史报告绑定的提交。重新从完整 Contacts 仓库提取了 11 个实际函数，与历史 PoC 中的提取片段逐一比较，全部字节一致。随后用这些重新提取的源码函数重跑了删除汇点攻击、修复和合法输入控制：每项 3/3 通过。独立二次复核还确认同一函数存在第二个路径汇点：攻击者控制的 `contactId`/`rawContactId` 可使头像缩略图写到 photo 目录外，组件探针 3/3 复现，修复变体 3/3 拒绝。

这证实报告绑定的上游源码包含两个未做目录边界约束的文件路径汇点：`PortraitFileName` 路径在头像解码失败后进入 `unlink`；由 `contactId`/`rawContactId` 拼出的目标路径可进入 `open(O_CREAT|O_WRONLY)` 写入缩略图。组件 harness 对 IPC、数据库、Bundle Manager 和权限系统使用桩，因此仍不是产品级端到端复现。当前环境没有连接的 OpenHarmony 设备、`hdc` 或 QEMU；完整镜像构建、真实权限、服务 UID 和 SELinux 验证未执行。第 5 节给出隔离设备/虚拟机上的复现步骤。

## 2. 上游源码与来源固定

官方根清单 `openharmony/.repo/manifests/default.xml` 将 OpenHarmony GitCode 设为默认远端；`ohos/ohos.xml` 中的项目名为 `applications_contacts_data` 和 `distributeddatamgr_data_share`。

| 仓库 | 官方地址 | 固定提交 | Git tree | 完整历史提交数 |
|---|---|---|---|---:|
| Contacts | `https://gitcode.com/openharmony/applications_contacts_data.git` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` | `2054824c04bb403eeea128a9262edfb3001efa4f` | 682 |
| DataShare | `https://gitcode.com/openharmony/distributeddatamgr_data_share.git` | `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd` | `f731230c116c94d7619f5514c828b33ffac69924` | 3,527 |

完整克隆位于 `tmp/openharmony-full-repos-20261020/{contacts_data,data_share}`。使用 `git clone --no-single-branch` 拉取完整历史，再 checkout 上表提交；克隆工作树干净。Windows Git 的 `core.autocrlf=true` 会把工作文件转换成 CRLF，因此来源校验以 Git blob 和原始 LF 字节为准。Contacts 关键源文件的 Git blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7` 解出的 SHA-256 与历史来源清单一致：`contacts_data_ability.cpp` 为 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`；`file_utils.cpp` 为 `4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f`。

完整源码上重新运行了历史提取器。三份受校验输入文件的 hash 校验通过，11 个提取函数均与历史 PoC 片段相同；详见本目录 `extraction_manifest.json`。

## 3. 漏洞机制和真实入口

目标服务在 `entry/src/main/module.json` 中声明为可见 DataShare ability：`datashare://com.ohos.contactsdataability`，写权限为 `ohos.permission.WRITE_CONTACTS`。

调用链如下：

1. DataShare 的 `DataShareStub::CmdBatchInsert`（`data_share/frameworks/native/provider/src/datashare_stub.cpp:486`）解包 URI 和 `ValuesBucket`，随后调用 provider 的 `BatchInsert`。
2. `UnmarshalValuesBucketToBuffer`（`data_share/frameworks/native/common/src/datashare_itypes_utils.cpp:1156`）接收字符串键值；这里没有移除路径分隔符或 `..`。
3. Contacts 的 `ContactsDataShareStubImpl::BatchInsert`（`contacts_data/dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp:260`）取得 ability 并转发到 `ContactsDataAbility::BatchInsert`。
4. `ContactsDataAbility::BatchInsert`（`contacts_data/dataBusiness/contacts/src/contacts_data_ability.cpp:601`）要求 `WRITE_CONTACTS`，之后 one-by-one 分支在 `ProcessSingleInsert` 中调用 `HandleContactPortrait`（行 735、770）。
5. `GetPortraitValue` 读取 `PortraitFileName`、`contactId` 和 `rawContactId`（行 855 起），只要求它们存在且非空；没有路径白名单。
6. `FileUtils::GetGroupPath` 基于 Bundle Manager 的 group directory 生成 `/data/storage/el2/group/<group-id>/photo/`（`file_utils.cpp:155-194`）。`HandleContactPortrait` 直接拼接 `groupPath + portraitFileName`（`contacts_data_ability.cpp:786`）。
7. 非图片数据导致 `SavePortraitFileAndBlob` 失败；失败分支仍调用 `DeleteFile(srcFilePath)`（行 790-793）。`FileUtils::DeleteFile` 最终直接 `unlink(filePath.c_str())`（`file_utils.cpp:208-211`）。没有 canonical path 或目录边界检查。成功解码时，函数还将 `groupPath + contactId + "_" + rawContactId` 作为缩略图目标路径打开写入；这两个 ID 字段同样只校验非空。组件探针确认 traversal 可将 PNG 头缩略图写到 photo 目录之外，带路径边界校验的修复变体拒绝该输入。

`contacts_api.cpp:1344-1373` 的正常头像流程会生成类似 `<contactId>_<rawContactId>.jpg` 的文件名。风险点是可获得写权限的调用者直接向 DataShare `BatchInsert` 提交自定义字段，并绕过该正常文件名生成流程。此结论不意味着没有 `WRITE_CONTACTS` 的普通应用可直接利用。

## 4. 触发输入及影响边界

使用隔离测试实例中动态取得的 group photo 根目录 `G`。删除汇点输入：

```text
PortraitFileName = ../../../base/files/ohscanner_canary_<run-id>.txt
contactId = 1
rawContactId = 1
```

对于 `G=/data/storage/el2/group/<group-id>/photo/`，规范化后目标是：

```text
/data/storage/el2/base/files/ohscanner_canary_<run-id>.txt
```

删除汇点影响范围为 **Contacts 服务进程有权限 unlink 的文件**。写入汇点使用服务可读取、可解码的头像源，并令 `contactId` 含 traversal；组件探针使用 `contactId="../../../base/files/written"`、`rawContactId="1"`，目标为 `/data/storage/el2/base/files/written_1`，写入 PNG 头缩略图。它能创建或部分覆盖服务 UID 可写的文件，内容不是任意字节，`open` 未设置截断标志。产品运行时的账户布局、数据库对 ID 的约束、目录权限、服务进程身份及 SELinux 规则决定真实镜像上的可达范围。测试只在隔离设备/虚拟机用唯一、无敏感信息的 canary；不得以系统配置文件或用户数据为目标。

## 5. 产品链人工复现步骤

### 前置条件

- 使用可回滚的 OpenHarmony 测试镜像、一次性用户/账户和非生产设备；完整固定 Contacts/DataShare 源码版本及产品配置。
- 调用方必须是该测试镜像允许获得 `ohos.permission.WRITE_CONTACTS` 的测试应用/系统签名应用。先验证实际权限；不要绕过访问控制或在未经授权的设备上测试。
- 设备侧可检查 Contacts 服务日志和文件系统；记录镜像哈希、设备型号、构建配置、补丁状态、SDK 与工具版本。
- 先确认 Contacts 的 `GetGroupPath()` 返回路径及其规范化结果。不要假设硬编码 group id 或固定安装路径。

### Canary 与前置校验

1. 为本轮生成唯一标识，例如 `ohscanner_canary_<UTC时间>.txt`。
2. 在隔离实例中将纯文本 canary 创建到经设备侧确认的目标目录 `/data/storage/el2/base/files/`。记录 owner、mode、inode、SHA-256 和 `realpath` 结果；确保 Contacts 服务能够访问该文件及其父目录。
3. 按 group path 计算 `G/../../../base/files/<canary>`，用设备侧路径规范化工具确认它与 canary 的绝对路径完全相同。先运行只读检查，确认不存在软链接或路径拼接误差。
4. 记录 canary hash；每次攻击仅使用一个新 canary。测试结束只删除这个唯一 canary（若漏洞已删除，则确认缺失），不清理目录中的其他文件。

### 通过真实 DataShare API 发起 BatchInsert

使用具有上述权限的测试应用调用 DataShare Helper。API 签名和 `batchInsert` Promise 在 DataShare 仓库 `frameworks/ets/ani/ets/@ohos.data.dataShare.ets` 中。可将以下片段接入测试页的按钮处理函数；`this.context` 按测试应用的 ArkTS 页面上下文替换：

```ts
import dataShare from '@ohos.data.dataShare'
import { ValuesBucket } from '@ohos.data.ValuesBucket'

const uri = 'datashare://com.ohos.contactsdataability/contacts/contact_data'
const helper = await dataShare.createDataShareHelper(this.context, uri)
const row: ValuesBucket = {
  PortraitFileName: '../../../base/files/ohscanner_canary_<run-id>.txt',
  contactId: '1',
  rawContactId: '1'
}
const result = await helper.batchInsert(uri, [row])
await helper.close()
```

将 `<run-id>` 替换成实际 canary 名称。不要用值“猜测”系统目录；先按上一节确认规范化路径。若 helper 创建失败，先记录权限/服务启动错误；若返回权限错误且 canary 保留，说明调用未到达漏洞分支，不能判成漏洞未复现。

### 观测与对照

- **攻击组**：有效授权后提交上述非图片 canary 路径。记录 API 返回码、调用方 bundle/UID、Contacts/DataShare 日志、canary 前后 hash/存在状态。漏洞分支预期先出现头像解码失败，随后 canary 消失；返回错误码本身不是成功判据。
- **无权限对照**：使用不具备 `WRITE_CONTACTS` 的调用方提交相同请求；预期权限拒绝且 canary 保留。
- **安全输入对照**：在测试实例中通过正常 Contacts API 写入合法图片并确认结果正常；不要把正常流程的客户端生成文件名改成 traversal。
- **修复对照**：在独立固定分支加入 basename/canonical path 边界校验，构建同一镜像后重放攻击；预期拒绝请求并保留 canary，同时合法头像仍可工作。
- **写入汇点**：仅在另一份一次性镜像快照上测试。先通过正常头像流程准备一张 Contacts 服务可读的测试图片，再用获授权的真实 API 提交含 traversal 的 `contactId`/`rawContactId`。按实际 `G` 规范化目标，例如组件探针对应 `G/../../../base/files/written_1`；在目标目录放置独立 canary 并记录 hash，提交后检查目标是否新建/改变及 PNG 头。若 API/数据库拒绝 traversal ID，记录为“未到达写入汇点”，不能判漏洞不存在。不得以系统配置文件或用户数据作为覆盖目标。
- 每轮最好恢复干净快照或重启服务。失败的 `ProcessSingleInsert` 路径在事务开始之后返回；产品事务清理和服务状态也应作为观测项。

## 6. 已完成的组件级动态验证

以完整 Contacts 克隆重新提取的源码函数构建临时适配器，在 Docker 网络隔离容器中使用 Clang 14 编译运行。容器为 `--network none`、只读根文件系统、`--cap-drop ALL`、`no-new-privileges`、资源限制和临时 `/data`。运行镜像 ID：`sha256:9adf310e14b3067c1b8a59b372bfab23f8fccd6383acfc55f43e1ee3c58efcf3`。

| 用例 | 次数 | 观察结果 | 状态 |
|---|---:|---|---|
| attack | 3/3 | 错误返回；沙箱内 canary 被删除 | 通过 |
| fixed attack | 3/3 | 错误返回；canary 保留 | 通过 |
| safe | 3/3 | 合法图片源被转换为头像输出 | 通过 |
| fixed-safe | 3/3 | 修复变体仍接受合法图片 | 通过 |
| attack-write | 3/3 | traversal 目标在 photo 目录外新建 PNG 头缩略图 | 通过 |
| fixed-write | 3/3 | 修复变体拒绝路径，目标未创建/改变 | 通过 |
| ASan/UBSan probe | 12/12 | 关闭 WSL 高熵 ASLR 后干净退出，无 sanitizer 报告 | 通过 |

本轮使用完整仓库中重新提取的 11 个函数，但仍以适配器提供框架替身；`TelephonyPermission::CheckPermission` 固定返回 true，数据库、Bundle Manager 和 IPC Parcel 也由替身实现。因此它证明了真实函数逻辑对输入和文件系统的结果，不证明真实权限授予、IPC 可达性、数据库对 traversal ID 的接受或量产镜像策略。

运行摘要、编译日志、逐次输出和二进制/源码哈希在本目录 `component_run_summary.tsv` 与 `component_logs/`。适配器和历史 PoC 入口见 `research/deliveries/a-line-sample30/20261018/poc/ohscanner-contacts-path-traversal/`。

## 7. 尚未验证事项与报告口径

- 未在 OpenHarmony 完整产品镜像上编译、安装和运行 Contacts HAP/Native service。
- 未执行真实 DataShare IPC 反序列化、真实访问令牌检查、Bundle Manager group path 查询、服务 UID 文件访问或 SELinux 策略验证。
- 未确定产品设备/发布分支的受影响范围；目前没有找到与本 finding 相匹配的 CVE 或上游安全公告。
- 当前环境没有连接的 OpenHarmony 设备、`hdc` 或 QEMU；因此本报告给出产品链人工复现规程，但没有把缺少设备说成“漏洞未复现”或“产品已确认”。

建议结论：**官方固定版本源码含有两个路径穿越文件汇点：头像处理失败时删除越界路径，成功处理时将 PNG 缩略图写入越界路径；组件级 PoC 在完整仓库源码上复现成功。完整产品链、实际权限主体、数据库对 traversal ID 的接受情况、设备影响和修复后产品镜像验证待目标测试设备执行。**

### 产品组件构建尝试记录（2026-10-20）

尝试使用完整 OpenHarmony 源码树的 HB 目标 `//applications/standard/contacts_data:contactsdataability`，产品配置为 `rk3568`，并把输出设在独立目录 `openharmony/out/contacts-path-traversal-rk3568-20261020`。没有覆盖现有 `out/rk3568`。HB 默认 Python 为 3.14，首次启动因上游脚本导入已移除的标准库 `pipes` 失败；在临时 `PYTHONPATH` 中提供只实现 `pipes.quote` 的兼容模块后，HB 进入预加载和参数检查。

随后 HB 在 subsystem 扫描阶段约 2 分 37 秒没有进入 GN/Ninja 或编译步骤。扫描进程递归遍历位于 Windows 挂载盘 `/mnt/d` 的源码树；为避免继续占用共享工作区 I/O，本次只中断了该 HB 命令。**这不是源码编译失败，也没有产生可安装的组件或产品镜像。** `out/ohos_config.json` 已恢复原内容，隔离输出目录未形成可用构建产物。完整仓库源码提取和组件级动态 PoC 的结果不受此构建尝试影响。

复现完整产品链仍按本节设备规程进行；若后续先走虚拟产品路线，应在独立 Linux 源码副本/构建盘中使用 OpenHarmony 支持的 Python 与构建环境，选定包含 Contacts/DataShare 的 `x86_64_virt` 产品，完成镜像启动、安装获授权测试应用、通过真实 DataShare IPC 提交唯一 canary 并采集服务日志与文件状态，再对修复镜像做同样对照。当前没有将上述步骤记为已完成。

## 8. 二次复核补充（2026-10-20 晚）

独立重提取（未复用历史提取器）与重编译复核。完整、可一键重跑的证据包见 `component_repro_20261020/REPORT_ZH.md`（脚本 `component_repro_20261020/reproduce/reproduce.sh`，包含来源校验、11 函数重提取、12 个组件用例、6 个写入探针与 sanitizer 分析）；早期 `recheck_20261020/` 为同一轮工作的临时目录，内容已被该证据包覆盖。

- 3 个源文件按 LF 归一化后 hash 与 `extraction_manifest.json` 一致；11 个函数的片段 hash、行号和 `.inc` 内容全部一致；组件 12/12 通过，二进制 hash 与第 6 节一致。
- 第 6 节 “ASan/UBSan probe 退出码 139” 已定位为 WSL2 高熵 ASLR 与 ASan 影子内存冲突的环境伪影：空 `main` 的 ASan 程序 20 次运行 8 次 139，`setarch -R` 关闭 ASLR 后 0/20；目标四模式 12/12 干净、无 sanitizer 报告。该项应记为 “ASan/UBSan clean（关闭 ASLR）”。
- **新增汇点**：`filePath = groupPath + contactId + "_" + rawContactId` 同样未做 basename/规范化，3/3 在 photo 目录外创建带 PNG 头的文件；带边界校验的修复变体 3/3 拒绝。影响由“任意删除”扩展为“任意创建/部分覆盖（内容为可控图片）”。
- 权限先决：`ohos.permission.WRITE_CONTACTS` 为 `system_basic`/`user_grant` 的受限开放权限（需 ACL 审批），真实利用者为系统/预置/获批应用，不是任意三方应用。
- 产品级仍未执行：官方只发布板卡镜像，无 QEMU 镜像；唯一可行路径是源码构建 `x86_64_virt` 标准系统镜像（`vendor/ohemu`，含 contacts 与 contactsdataability，KVM + `hdc tconn 127.0.0.1:5555`），成本约 1–2 天。

## 9. 公开披露与 0day 口径（截至 2026-10-20）

检索 OpenHarmony 官方 2026 年 10 月安全公告及公告索引，公告列出的系统仓库问题是 `drivers_peripheral`、`device_soc_rockchip`、`drivers_hdf_core` 等，三方库条目包括 curl、ffmpeg、nghttp2、skia、lzma；该公告没有列出 `applications_contacts_data` 或 `distributeddatamgr_data_share`。基于官方公开公告和精确关键词检索，**当前没有找到本 finding 的公开 CVE/公告记录**。

这不足以确认“0day”：公开公告未命中不能证明维护者私下未知，也不能证明某个已发布产品镜像实际受影响。当前准确分类为**未发现公开披露的源码级安全问题候选**；待产品镜像复现、确定受影响版本并与上游披露状态核实后，再判断是否属于 0day。OpenHarmony 说明采用修复后发布安全公告的负责任披露流程，参考[官方 2026 年 10 月安全公告](https://lists.openatom.io/hyperkitty/list/security%40openharmony.io/thread/SQFOVEUMA3FP26J3G27EKUD2VLDY5YYM/)和[安全漏洞治理流程](https://gitcode.com/openharmony/security/blob/master/en/security-process/README.md)。
