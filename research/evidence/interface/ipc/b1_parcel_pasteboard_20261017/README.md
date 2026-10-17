# Parcel 族真实修复对：pasteboard `ReadRawData` 非 ashmem fd（2026-10-17）

这是 DATA-02 族的第一组**公开修复真实对**：同一函数在修复前后的两个固定提交上，
用同样的伪造请求与无害对照各跑一次。`result.json` 由 `assemble.py` 从 harness
输出与固定源码摘要生成，未手工编辑。`validated_vulnerability` 为 0。

## 固定输入

| 项 | 值 |
| --- | --- |
| 仓库 | `openharmony/distributeddatamgr_pasteboard` |
| 函数 | `OHOS::MiscServices::MessageParcelWarp::ReadRawData` |
| vulnerable | `3287e85450f16d3f41801040abe35701131ad6f4` |
| fixed | `ddee7c00d97d54423c6168fac994d3ef6204f385` |
| 修复 | mmap 前增加 `AshmemGetSize(fd) >= 0 && size <= actualSize` 校验 |
| 修复提交说明 | `ReadRawData补充AshmemGetSize校验防止非ashmem fd注入` |
| c_utils | `3bdc11e00e7bf6e577cee300ad51045ca9958efd`（`Parcel`/`Ashmem` 实现） |

修复前，`ReadRawData` 只校验 `size` 与包内 `ReadInt64()` 一致（`bufferSize == size`），
随后直接对**包里带来的任意 fd** 做 `mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0)`。
它从不确认该 fd 是 ashmem，也不确认其实际容量。修复加入的正是这两点。

## 什么被原样编译，什么是本 harness 补的

原样编译（每次构建按 `result.json` 的 sha256 校验，版本不符即中止）：

- `framework/tlv/message_parcel_warp.cpp`（vulnerable / fixed 各一份）
- `framework/tlv/message_parcel_warp.h`、`utils/native/include/pasteboard_hilog.h`、
  `framework/framework/include/api/visibility.h`
- c_utils `base/src/{parcel,refbase,string_ex,unicode_ex,ashmem}.cpp` —— 真实的 `Parcel`
  与真实的 `AshmemGetSize`（`ioctl(fd, ASHMEM_GET_SIZE)`）

本 harness 提供：

| 文件 | 原因 |
| --- | --- |
| `harness.cpp` | 构造伪造请求、调用 `ReadRawData`、打印观测值 |
| `shim/message_parcel.h` | 只补描述符传输（`WriteFileDescriptor`/`ReadFileDescriptor`），其余方法走真实 `Parcel`；ipc_core 的实现在独立编译时需要 binder 驱动 |
| `shim/parameters.h` | `OHOS::system::GetIntParameter` 返回默认值（128 MiB，远高于所有用例） |
| `shim/hilog/log.h` | 日志降为 no-op；`PASTEBOARD_CHECK_*` 的 `if`/`return` 形状不受影响 |
| `shim/securec.h` | `memcpy_s`/`strcpy_s`，与项目既有的 c_utils 独立编译配方一致 |
| `shim/linux/ashmem.h` | 宿主内核无 ashmem 驱动，头文件未安装；ioctl 号取自上游 UAPI 头，只为让真实 `ashmem.cpp` 编译 |

`-DCROSS_PLATFORM` 与仓库自身的跨平台分支一致：它去掉的只是 `fdsan_*` 调用。

## 复现

```sh
# 宿主机（WSL）本地；两个仓库的提交必须已在本地对象库中
PASTEBOARD_REPO=/path/to/pasteboard CUTILS_REPO=/path/to/commonlibrary_c_utils \
    sh build.sh
sh run.sh
python3 assemble.py "$OUT" detector_vulnerable.json detector_fixed.json result.json
```

构建与运行产物全部落在仓库外的 `OUT`（默认 `/home/audit/wtmp/parcel_harness/build`），
第三方源码不进提交。运行不联网，不接触任何线上服务。

## 结果

| 场景 | vulnerable | fixed |
| --- | --- | --- |
| A 非 ashmem fd，声明大小 = 文件大小（64 KiB） | `non_null`，首/末字节均为 `0x41` | `null` |
| B 非 ashmem fd，声明大小（64 KiB）> 文件大小（4 KiB） | `non_null`；调用方读到 EOF 之外 → **SIGBUS(7)** | `null`，未尝试读取 |
| C 小载荷（≤ 32 KiB，不走 fd） | `non_null`，字节一致 | `non_null`，字节一致 |
| D 声明大小与包内 `ReadInt64` 不一致 | `null` | `null` |

A 是核心差分：修复前，发送方在包里放一个普通文件 fd，接收方就把该文件内容
当作剪贴板原始数据交回；修复后同一请求返回 `null`。B 说明同一路径还能让调用方
在越界页上收到 SIGBUS。C 与 D 是无害对照与既有校验，两个修订必须一致。

## 静态检测器的现状（负结果，保留）

同一对提交用 `research/deliveries/ipc/bline_direct_measure.py` 全树扫描：

| 修订 | all-files | complete-ast |
| --- | --- | --- |
| vulnerable `3287e854` | `blocked`；1 条 `ipc.relay.descriptor-boundary`；DATA 族 0 | `completed`；0 |
| fixed `ddee7c00` | `blocked`；1 条 `ipc.relay.descriptor-boundary`；DATA 族 0 | `completed`；0 |

两个修订输出相同，DATA-01..04 都没有命中。原因有两层，都用探针确认过：

1. **规则形状**：现有 DATA-02 以 parcel 派生长度驱动**目标缓冲区**
   （copy/index/`ReadRawData(dst,size)`）为判据，没有把"包里带来的 fd 作为 mmap
   的 backing、长度未与该 fd 实际容量比较"建模为 sink。
2. **调用解析**：调用点是 stub 里的 `messageData.ReadRawData(data, rawDataSize)`，
   接收者是局部对象。`analysis.Interpreter.resolve` 明确不解析带 `.`/`->` 且接收者
   不是 `this` 的名字（`analysis.py:711-713`），所以 `ReadRawData` 的函数体从未被
   解释。探针显示该调用点被计为 `dest_sites=1 / dest_request=1`，但函数体里的
   `ReadFileDescriptor`/`mmap` 一次也没有被求值。即使补上 fd sink 模型，现状下也
   不会产生候选。

这是当前规则集的**假阴性**，记录在此，不用候选数掩盖。它不否定 A/B 的差分观测，
也不说明其他组件安全。要补这条能力，需要先扩大"局部对象成员调用"的解析面，属于
独立的设计变更，不在本轮擅改。

## 没有证明的事

- harness 直接调用 `ReadRawData`。真实 TLV 分发层如何把包交到这一步、哪个进程
  能向该包写入描述符、调用者身份与权限，都未建立；`reachability` 保持 `partial`。
- 宿主内核无 `/dev/ashmem`，因此没有跑"真实 ashmem 但声明大小超过其容量"的用例
  （上游回归测试 `ReadRawDataTest005` 的形状）。A/B 使用的是普通文件 fd：
  `AshmemGetSize` 在设备上对非 ashmem fd 同样返回 -1，这条路径与设备一致。
- 未验证 pasteboard 的调用方是否会接受攻击者提供的 fd；未构造完整 IPC 事务。
- `validated_vulnerability` 保持 0：这是缺陷路径的隔离差分，不是端到端可利用性结论。

## 哈希

```text
dbb4410946a54765e060d66a3fa0cb0dd81ffb87a9c06048a642812b8226be73  result.json
a486ff1a47245712cfc5e025d0cb91db9ca92508c5b2661906b9fa69b227ef89  vulnerable message_parcel_warp.cpp
f07acbadf9481ee61ea35024555182b4a06e1d21b24e5899586f3a183c7b958b  fixed message_parcel_warp.cpp
```
