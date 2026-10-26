# Contacts DataShare 路径穿越：组件级完整复现包

Finding：`ohscanner-contacts-path-traversal-001`
日期：2026-10-20
状态：**组件级（代码级）复现已完成并可一键重跑；产品级（真实镜像/设备）未执行。**
证据等级：代码缺陷 = 已确认；服务端可达性 = 静态确认；产品影响范围 = 未验证。

---

## 0. 一页结论

固定提交的 OpenHarmony Contacts 源码中，`ContactsDataAbility::HandleContactPortrait()` 把客户端可控的
`PortraitFileName`、`contactId`、`rawContactId` 直接拼进文件路径，随后：

1. `unlink()` 删除任意服务可写路径（**删除原语**）；
2. `open(O_CREAT|O_WRONLY)` 在任意服务可写路径创建/覆盖文件（**写入原语**，本次新增确认）。

两个原语都不做 basename、`..` 或规范化检查。组件级 harness 用上游真实函数跑通攻击 3/3、修复 3/3、
合法输入 3/3、修复后合法输入 3/3，并在 ASan/UBSan 下干净通过（关闭 ASLR 后）。

---

## 1. 目标与范围

| 做过的 | 没做的 |
|---|---|
| 固定上游提交，重提取 11 个函数并与历史片段逐字节比对 | 真实 DataShare IPC（`DataShareStub::CmdBatchInsert` 的 Parcel 路径） |
| 用真实函数构建 harness，动态跑攻击/修复/合法对照 | 真实 `AccessToken`/ACL 权限校验 |
| 复现删除原语与新增的写入原语 | 真实 BundleManager group path 查询、Contacts 数据库事务 |
| ASan/UBSan 与 ASLR 伪影分析 | Contacts 服务进程 UID、SELinux、产品镜像行为 |

因此本包能回答"**这段上游代码是否有可触发的路径穿越、触发后对文件系统做了什么**"，
不能回答"**某台真实设备上最终能删到哪些文件**"。

---

## 2. 来源固定（provenance）

克隆方式：`git clone --no-single-branch` 完整历史后 checkout 固定提交。

| 仓库 | 地址 | 提交 | tree |
|---|---|---|---|
| Contacts | `https://gitcode.com/openharmony/applications_contacts_data.git` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`（2026-10-08） | `2054824c04bb403eeea128a9262edfb3001efa4f` |
| DataShare | `https://gitcode.com/openharmony/distributeddatamgr_data_share.git` | `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`（2026-10-10） | `f731230c116c94d7619f5514c828b33ffac69924` |

复现时 contacts `origin/master` 顶端即 `341cc3b`（本次克隆当天确认），因此该缺陷**仍在当前 master 上**。

被校验的三个源文件（Windows `core.autocrlf=true`，以 LF 归一化后的字节为准）：

| 文件 | Git blob | LF SHA-256 | 字节 |
|---|---|---|---|
| `dataBusiness/contacts/src/contacts_data_ability.cpp` | `c93e950725adc93276916b3c96c5ac7a5bb5b6b7` | `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6` | 85,339 |
| `dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp` | `d738c4931bb40ac53519657fb2daa3febfae2bce` | `a913de9c273ef055de9203f83e890067a8594f1028dce6526844228585aa87a4` | 29,986 |
| `ability/common/utils/src/file_utils.cpp` | `7d39485e3b3f253d474d8e49952e16ced7ccd605` | `4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f` | 6,843 |

`reproduce/verify_extraction.py` 会重新做花括号配平提取（不复用历史提取器），校验 11 个函数的
片段 SHA-256、起止行号，并与 harness 实际编译的 `.inc` 逐字节比对。结果见
`provenance/verify_extraction.json`（`all_ok: true`）。

---

## 3. 完整调用链（上游源码逐跳）

1. **IPC 入口** — `datashare_stub.cpp:486`
   `DataShareStub::CmdBatchInsert` 解包 URI 与 `vector<DataShareValuesBucket>`，再调 provider 的 `BatchInsert`。
2. **反序列化** — `datashare_itypes_utils.cpp:1156`
   `UnmarshalValuesBucketToBuffer` 逐项读取 key（`std::string`）与 value，**原样放入 bucket，无任何字符过滤**。
3. **Contacts 扩展入口** — `contacts_datashare_stub_impl.cpp:260`
   `ContactsDataShareStubImpl::BatchInsert` 取 ability 后转发。
4. **权限检查 + 分发** — `contacts_data_ability.cpp:601`
   `BatchInsert` 先检查 `WRITE_CONTACTS`，随后走 `batchInsertHandleOneByOne`。
5. **逐条处理** — `contacts_data_ability.cpp:734`
   `ProcessSingleInsert` 的第一件事就是 `HandleContactPortrait(rawContactValues)`。
6. **漏洞函数** — `contacts_data_ability.cpp:770`
   取 `PortraitFileName` / `contactId` / `rawContactId`，只要求"存在且非空"，然后：
   ```cpp
   std::string srcFilePath = groupPath + portraitFileName;                  // 读 + 删除
   std::string filePath    = groupPath + contactId + "_" + rawContactId;    // 创建/覆盖
   ```
7. **失败/成功都删除** — 行 790-797：
   解码失败走 `DeleteFile(srcFilePath)`；成功路径同样 `DeleteFile(srcFilePath)`。
8. **最终 sink** — `file_utils.cpp:208`：`FileUtils::DeleteFile` → `unlink(filePath.c_str())`；
   `save_portrait_file_and_blob` 里 `open(filePath, O_CREAT|O_WRONLY, 0660)`。

`groupPath` 由 `FileUtils::GetGroupPath()`（`file_utils.cpp:155`）生成：
`/data/storage/el2/group/<group-id>/photo/`，只校验前缀，不做 `realpath`/边界检查。
因此 `../../../base/files/x` 会规范化到 `/data/storage/el2/base/files/x`。

---

## 4. 两个 sink 与攻击输入

设 `G = /data/storage/el2/group/<group-id>/photo/`。

**删除原语**（原报告已覆盖）

```text
PortraitFileName = ../../../base/files/canary.txt
contactId        = 1
rawContactId     = 1
```

`srcFilePath = G + ../../../base/files/canary.txt` → 非图片 → `GetPixelMapFromFile` 失败
→ 失败分支 `unlink(srcFilePath)`。即使源文件是合法图片，成功分支也会 `unlink`。

**写入原语**（本次新增）

```text
PortraitFileName = allowed.png          # 服务可读的合法图片
contactId        = ../../../base/files/written
rawContactId     = 1
```

`filePath = G + ../../../base/files/written_1` → `open(O_CREAT|O_WRONLY)` 成功写入缩略图。
写入内容为攻击者提供的图片（非任意字节），且 `O_WRONLY` 不带 `O_TRUNC`，对已存在文件是**部分覆盖**。

---

## 5. 复现环境（精确版本）

| 项 | 值 |
|---|---|
| 宿主 | Windows + WSL2，内核 `6.6.87.2-microsoft-standard-WSL2` |
| 构建/运行容器 | `ubuntu:22.04` |
| 镜像 | `ohscanner-validation:c1-ruby-20261019`，ID `sha256:9adf310e14b3067c1b8a59b372bfab23f8fccd6383acfc55f43e1ee3c58efcf3` |
| 编译器 | `Ubuntu clang version 14.0.0-1ubuntu1.1`（x86_64-pc-linux-gnu） |
| Docker | 29.1.3 |
| 容器约束 | `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --cpus=2 --memory=1g --pids-limit=128`，`/data` 为 64MB tmpfs |
| Python | 3.10（仅用于提取校验） |

镜像可由 `harness/Dockerfile` 重建（`docker build -t ohscanner-validation:c1-ruby-20261019 harness/`）。

---

## 6. 一键复现

```bash
CONTACTS_REPO=/path/to/contacts_data \
OUT=/tmp/repro \
bash reproduce/reproduce.sh
```

脚本顺序执行并逐段打印：

1. 校验 `HEAD`/`tree` 是否等于 pin；
2. 重新提取 11 个函数，校验 hash/行号，并写出到 `$OUT/generated`；
3. 与包内 `harness/generated/*.inc` 做 `diff -r`；
4. 容器内编译 4 个二进制并跑 12 个用例；
5. 编译写入探针并跑 6 个用例；
6. （可选 `ASAN_ASLR=1`）复现 ASLR 伪影。

只想做来源校验：`VERIFY_ONLY=1`。

---

## 7. 结果

### 7.1 组件用例（`results/component/`，3 次重复）

| 用例 | 输入 | 返回码 | 观测 | 判定 |
|---|---|---|---|---|
| attack | `PortraitFileName=../../../base/files/victim.txt` | `-1` | victim 被删除，无 photo 输出 | 3/3 pass |
| fixed | 同上，`HandleContactPortrait` 加 basename/`..` 校验 | `-1` | victim 保留，无 photo 输出 | 3/3 pass |
| safe | `PortraitFileName=allowed.png` | `0` | 源图被消费，photo 输出生成 | 3/3 pass |
| fixed-safe | 同 safe，走修复实现 | `0` | 源图被消费，photo 输出生成 | 3/3 pass |

原始输出（`results/component/logs/attack_r*.log`）：

```json
{"mode":"attack","return_code":-1,"victim_before":true,"victim_after":false,"source_after":true,"photo_output_after":false,"pass":true}
```

**返回码不是判据**：漏洞分支本来就返回 `OPERATION_ERROR`，但删除已经发生。

二进制 SHA-256（`results/component/logs/artifact_hashes.txt`，与历史产物一致，可重复构建）：

```
845f1f06…  target_ubsan        4538b4c1…  patched_ubsan
0b417f5b…  target_asan_ubsan   7ed0920d…  patched_asan_ubsan
c5c2c249…  target_adapter.cpp  1ca464c2…  patched_target_adapter.cpp
b211316b…  target_adapter_common.hpp
```

> 注：二进制含调试路径，跨机器重编不保证同 hash；**源文件 hash 才是稳定身份**。

### 7.2 写入探针（`results/write_probe/`，3+3）

```json
{"mode":"attack-write","return_code":0,"written_outside_photo":true,"written_png_header":true,"src_after":false,"pass":true}
{"mode":"fixed-write","return_code":-1,"written_outside_photo":false,"written_png_header":false,"src_after":true,"pass":true}
```

攻击组 3/3 在 photo 目录外创建了带 PNG 头的文件；修复组 3/3 拒绝且不落盘。

### 7.3 Sanitizer（`results/asan/`）

- 历史报告里的 "ASan 退出码 139" 是**环境伪影**：空 `main` 的 ASan 程序同容器 20 次运行挂 8 次；
- `setarch x86_64 -R`（关 ASLR）+ `seccomp=unconfined` 后 20/20 正常；
- 目标四模式各 3 次，ASan+UBSan 下 **12/12 退出码 0，无任何报告**。

结论：该缺陷不是内存安全问题，是纯粹的路径处理缺陷；sanitizer 结果从"未计入"升级为"clean"。

---

## 8. Harness 设计与被替身的部分

**真实代码（逐字节来自上游）**：11 个 `.inc`，覆盖 `ContactsDataShareStubImpl::BatchInsert`、
`ContactsDataAbility::BatchInsert/batchInsertHandleOneByOne/ProcessSingleInsert/HandleContactPortrait/
SavePortraitFileAndBlob/GetPortraitValue/GetStringValueFromDataShareValue`、
`FileUtils::GetGroupPath/DeleteFile`，以及 `DataShare` 侧伪 stub。

**替身（`harness/target_adapter_common.hpp`）**：

| 替身 | 行为 | 影响 |
|---|---|---|
| `TelephonyPermission::CheckPermission` | 恒 `true` | 不验证权限门 |
| `IPCSkeleton::GetCallingUid` | 恒 `20010000` | 不验证调用者身份 |
| `GetBundleNameByUid` | 恒返回 contacts bundle | 不影响逻辑 |
| `FileUtils::GetGroupDir` | 恒返回 `/data/storage/el2/group/com.ohos.contactsdataability` | 固定 group 路径 |
| `PixelMapUtil::*` | 只识别 PNG magic，写 8 字节 | 不依赖真实图像栈 |
| `ContactsDataBase` / `ProfileDatabase` | 空实现 | 不验证数据库副作用 |
| `RdbUtils::ToValuesBucket` | 返回空 bucket | 插入阶段必失败（不影响删除/写入发生） |
| `Uri` / `ValuesBucket` | 最小实现 | 不经过真实 Parcel |

因此 harness 的边界是：**从 provider 的 `BatchInsert` 入口开始，到文件系统为止**；
IPC 入口、权限、BundleManager、数据库都未覆盖。

---

## 9. 影响模型（能说与不能说）

**条件**：调用方必须持有 `ohos.permission.WRITE_CONTACTS`。该权限为 `system_basic` + `user_grant`，
且属于"受限开放权限"（需 ACL 审批），普通三方应用仅靠用户授权拿不到。参见
[OpenHarmony 受限权限文档](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/AccessToken/restricted-permissions.md)。

**可确认**：
- 持权调用者可以把"联系人数据写权限"升级为 **Contacts 服务进程可写路径内的任意文件删除/覆盖**；
- 典型目标：`/data/storage/el2/base/files/`、`databases/`、`preferences/`、`cache/`，以及同 group 的共享目录。

**不可确认（需真实设备）**：
- 服务 UID、SELinux 域、实际 group 布局决定最终可达范围；
- 是否能覆盖联系人数据库导致持久化破坏（取决于文件锁与事务时机，未验证）；
- 是否可跨 bundle（大概率不能，受 UID/DAC/SELinux 限制）。

**不成立的表述**：任意系统文件删除、RCE、无权限应用可直接利用。

定级建议：Medium。若产品侧确认可覆盖 Contacts 的 RDB 文件导致数据不可用，可上调到 6.x；
在没有产品验证前不建议给具体 CVSS 分数。

---

## 10. 披露状态

- 上游：截至 2026-10-20，`origin/master` 顶端即 pin 提交，**无修复**；
- 公开：未检索到该点的公开报告或 CVE 归属（检索非穷尽）；
- 因此按"未公开披露 + 无补丁"的口径处于 **0day 状态**，但应按"权限内、沙箱级"定性与披露，
  正式对外前建议走 OpenHarmony 安全披露流程。

---

## 11. 修复建议

在 `HandleContactPortrait` 拼接前做**路径围栏**，而不是只过滤字符：

1. 三个字段只允许 basename：拒绝 `/`、`\`、`.`、`..`，或直接 `std::filesystem::path(p).filename() == p`；
2. 拼接后 `realpath()`（目标不存在时对父目录 realpath）并校验 `path.compare(0, groupPath.size(), groupPath) == 0`；
3. 对 `srcFilePath` 额外确认是可读普通文件且非符号链接（`O_NOFOLLOW`）；
4. 删除/写入统一走带边界校验的 `FileUtils` 封装。

附带观察（未动态验证）：`batchInsertHandleOneByOne` 在 `ProcessSingleInsert` 失败时直接 `return`，
既未 `RollBack` 也未提交，事务会悬挂到连接释放。建议一并修复。

---

## 12. 证据文件索引

```
reproduce/reproduce.sh              一键复现（provenance → 提取 → 12 用例 → 6 探针）
reproduce/verify_extraction.py      独立提取与 hash 校验
harness/*.cpp, *.hpp, *.inc         真实函数 + 替身 + 两个探针
harness/Dockerfile                  可重建的编译镜像
results/component/                  12 用例日志、run_summary、二进制 hash
results/write_probe/                6 个写入用例日志
results/asan/                       ASLR 伪影与目标 sanitizer 结果
provenance/verify_extraction.json   提取校验明细
provenance/source_pins.md           提交/tree/blob/hash 记录
provenance/product_context.md       产品侧上下文（预置应用、子系统、权限级别）
SHA256SUMS.txt                      本包全部文件的校验和
```

校验整包：`sha256sum -c SHA256SUMS.txt`。
