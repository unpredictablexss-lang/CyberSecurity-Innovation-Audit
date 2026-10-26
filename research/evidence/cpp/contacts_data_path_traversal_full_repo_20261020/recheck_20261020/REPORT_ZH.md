# Contacts DataShare 路径穿越链：二次独立复核与产品级复现可行性

日期：2026-10-20（晚）
对应 finding：`ohscanner-contacts-path-traversal-001`
父文档：`../TECHNICAL_REPRODUCTION_ZH.md`
结论一句话：**组件级链路已独立复现并额外确认了一个“任意路径写入”汇点；产品级端到端在本机当前不可直接执行，需要先构建 `x86_64_virt` 标准系统镜像（约 1–2 天）。**

## 1. 本次复核结论

| 项目 | 结果 | 证据 |
|---|---|---|
| 上游源码来源（pin 提交、3 个文件、11 个函数） | 通过，逐字节一致 | `extraction/verify_extraction.json` |
| 组件级攻击/修复/合法对照 | 12/12 通过，二进制 hash 与历史一致 | `component/run_summary.tsv`、`component/logs/` |
| 历史报告遗留的 “ASan 退出码 139” | 已定位为**运行环境的 ASLR 伪影**，非目标缺陷；关闭 ASLR 后 12/12 干净 | `asan/` |
| 额外汇点 `contactId`/`rawContactId` | **新增确认：任意路径文件写入**（不只删除），3/3 通过 | `write_probe/` |
| 真实 DataShare IPC / 权限 / BundleMgr / 数据库 / SELinux | 仍未验证 | 见第 4 节 |

## 2. 来源与提取复核（不依赖历史提取器）

在 WSL Ubuntu 中对完整克隆重新做了括号匹配提取，未复用历史脚本：

- `contacts_data` 固定提交 `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`（即 clone 的 `master` 顶端，2026-10-08）；
- 3 个源文件按 CRLF→LF 归一化后 SHA-256 与 `extraction_manifest.json` 完全一致（85339 / 29986 / 6843 字节）；
- 11 个函数的片段哈希、起止行号、以及 harness 实际编译的 `.inc` 文件内容全部一致（`ALL_OK=True`）。

复现命令（摘要）：对每个 `needle` 从首个 `{` 做花括号配平提取，与 manifest 的 `snippet_sha256`、`line_start/line_end`、`generated/*.inc` 三方比对。

## 3. 组件级动态复核

使用历史同一镜像 `ohscanner-validation:c1-ruby-20261019`（ID `9adf310e14b3`），但**重新编译**而非复用二进制：

```
docker run --rm --entrypoint /bin/sh --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --cpus=2 --memory=1g --pids-limit=128 \
  -v work:/sandbox/work:ro -v out:/sandbox/out --tmpfs /tmp --tmpfs /data \
  ohscanner-validation:c1-ruby-20261019 /sandbox/work/run_ubsan_clang.sh
```

结果：attack / fixed / safe / fixed-safe 各 3 次，全部 `pass:true`；四个二进制的 SHA-256 与历史 `artifact_hashes.txt` 逐字节相同，说明历史产物可重复构建。

### 3.1 关于 ASan 退出码 139

历史记录写“ASan/UBSan probe 退出码 139，不计为 sanitizer 通过”。复核显示这是**环境问题**：

- 一个 `int main(){return 0;}` 的 ASan 空程序，在同一容器中 20 次运行有 8 次 139（`asan/trivial_asan_20runs.txt` 第 2 行）；
- 同一二进制用 `setarch x86_64 -R`（关闭 ASLR，需 `--security-opt seccomp=unconfined`）后 20 次全部 0；
- 目标四个模式在关闭 ASLR 后跑 ASan+UBSan 各 3 次，12/12 退出码 0，无任何 sanitizer 报告（`asan/target_asan_12runs.txt`）。

即：WSL2 内核的高熵 ASLR 与 ASan 影子内存布局冲突导致随机段错误，与 Contacts 代码无关。该项应从“未计入”升级为“clean（关闭 ASLR 后）”。

## 4. 新增：`contactId`/`rawContactId` 的写入汇点

原报告只覆盖了 `PortraitFileName` 的删除原语。同一函数还有第二个拼接点：

```cpp
std::string srcFilePath = groupPath + portraitFileName;   // 路径 A：读 + 删除
std::string filePath    = groupPath + contactId + "_" + rawContactId;  // 路径 B：O_CREAT|O_WRONLY 写入
```

`contactId` 与 `rawContactId` 同样只校验“存在且非空”（`GetPortraitValue`），未做 basename/规范化。当 `srcFilePath` 指向一张可解码图片时，`SavePortraitFileAndBlob` 成功后会把缩略图写入经穿越解析的 `filePath`。

探测结果（`write_probe/`，3/3）：

```json
{"mode":"attack-write","return_code":0,"written_outside_photo":true,"written_png_header":true,"src_after":false,"pass":true}
```

即 `contactId="../../../base/files/written"` 使文件被创建在 `/data/storage/el2/base/files/written_1`（photo 目录之外），带 PNG 头；带边界校验的修复变体 3/3 拒绝且不落盘。

影响差异：
- 原删除原语：`unlink` 任意服务可写路径；
- 新增写入原语：`open(O_CREAT|O_WRONLY)` 创建/部分覆盖任意服务可写路径，内容为攻击者提供的图片缩略图（非任意字节，且不截断）。对数据库、偏好文件等属于完整性破坏。
- 前置条件：需要一个服务可读、可解码的图片作为源；攻击者可先用正常头像接口写入一张，或指向镜像内既有图片。

两者都受同一权限门限制（见 5.1）。

## 5. 产品级端到端：为什么本机现在做不到

### 5.1 攻击者模型（先决条件，容易被忽略）

`ohos.permission.WRITE_CONTACTS` 在官方权限表中属于**受限开放权限**，级别 `system_basic`、授权方式 `user_grant`，需 ACL 审批，普通三方应用仅靠用户点“允许”拿不到。因此真实利用者是：系统/预置应用、通过 ACL 获批的合作方应用，或已被攻陷的持权应用。这不是“任意应用可打”的洞，但它是**从“联系人数据写权限”升级为“Contacts 进程沙箱内任意文件写/删”**的边界跨越，影响应表述为 Contacts 服务 UID 可写范围内的数据破坏，而非系统任意文件删除。

### 5.2 环境现实

- 官方 `repo.huaweicloud.com/openharmony/os/*` 只发布板卡镜像（dayu200/dayu600 rk3568、hispark），**没有任何 QEMU/模拟器镜像**；CI 产物需要权限（403）。
- 无 OpenHarmony 设备、无 `hdc`、无 DevEco 模拟器（DevEco 的镜像是 HarmonyOS 系、需申请）。
- 唯一可行路线是源码构建标准系统 QEMU 产品 `x86_64_virt`（`vendor/ohemu/qemu_x86_64_linux_full`，`type: standard`，继承 `rich.json`，含 ability_runtime / bundle_framework / data_share / relational_store / hdc / `contacts_data`；`install_list.json` 预置 contacts 与 contactsdataability）。启动脚本 `qemu_run.sh` 用 `qemu-system-x86_64 -machine q35,accel=kvm`，`hostfwd tcp::5555-:5555`，之后 `hdc tconn 127.0.0.1:5555` + `bm install`。
- 本机条件：WSL2 Ubuntu 24.04（不在官方支持矩阵 18.04–22.04）、WSL 内存 15 GB（官方建议 32 GB）、`/dev/kvm` 可用（nested=Y）、WSL 磁盘剩余约 866 GB。
- 成本：首次全量构建 190–250 GB 产物，32 核约 4–10 小时（16 GB 内存需降 `-j` 并加 swap），加上依赖修复与镜像调试，现实周期约 1–2 天。

### 5.3 若执行，最小步骤

1. 把 WSL 内存提到 24 GB、swap 64 GB（`.wslconfig`），或改在原生 Ubuntu 22.04 / 32 GB 机器上做；
2. 在 `ubuntu:22.04` 环境中 `repo init -u https://gitcode.com/openharmony/manifest.git -b master` + `repo sync -c -j8`；
3. `./build.sh --product-name x86_64_virt --ccache --disable-package-image --ninja-args=-j16`；
4. `vendor/ohemu/qemu_x86_64_linux_full/qemu_run.sh` 启动，`hdc tconn 127.0.0.1:5555`；
5. 安装/构造一个持 `WRITE_CONTACTS` 的测试 HAP（需要系统签名或 ACL 配置），在隔离实例内放置唯一 canary，调用 `dataShare.batchInsert`，观测 unlink/写入；
6. 对照组：无权限调用方、修复镜像。

## 6. 未验证事项

- 真实 DataShare IPC 反序列化（`DataShareStub::CmdBatchInsert` → `UnmarshalValuesBucketVec`）、真实 ACL/令牌校验、BundleMgr group path 查询、Contacts 服务 UID 与 SELinux 策略；
- 产品镜像上 `GetGroupPath()` 的实际返回与可写范围；
- 修复补丁在真实镜像上的回归（组件级已过）。

## 7. 证据索引

- `extraction/verify_extraction.json` — 重提取校验明细
- `component/` — 重编译二进制、12 次运行日志、compile.log、artifact_hashes.txt
- `asan/` — trivial ASan 20 次对照、目标 12 次 ASan/UBSan 结果
- `write_probe/` — 写入原语源码、6 次运行日志、二进制哈希
