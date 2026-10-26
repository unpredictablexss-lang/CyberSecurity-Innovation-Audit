# D30：libpng CVE-2026-46675 组件级 ASan 复现与修复对照

日期：2026-10-19
扫描器：`ohscanner.known_disclosed_cves` 0.9.0
结论：在 G 盘 OpenHarmony 镜像实际携带的 libpng 1.6.55 源码归档上，组件级 heap-use-after-free 已由 ASan 复现；应用上游修复后同一输入不再触发。OpenHarmony 产品状态仍为 unknown。

## 固定来源

- G 镜像仓库：`third_party_libpng`，HEAD `e57b1079564a02a50321ec528aa6e41884979d32`。仓库其他文件目前有 dirty 状态；本次仅读取。
- 构建归档：`libpng-1.6.55.tar.gz`，Git blob `975cee2aca0eda6bfa3e9b7a1336c956fcf1b094`，SHA-256 `71a2c5b1218f60c4c6d2f1954c7eb20132156cae90bdb90b566c24db002782a6`。工作树归档字节与 HEAD 中的 blob 一致。
- 上游修复：libpng 提交 `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`。PoC 在归档的独立临时解压副本中运行；修复对照是在另一份副本应用此精确 `pngrutil.c` 修复提交。**这不是完整 libpng 1.6.59 发布树构建**，而是同一 1.6.55 组件对修复提交的可复现对照。
- 固定来源与本次每轮结果见 `D30_LIBPNG_CVE_2026_46675_REPLAY.json`。

## PoC 与结果

`read_png_end.c` 使用顺序读取 API，对输入先调用 `png_read_info()`，不读取图像行，随后直接调用 `png_read_end()`。重放脚本生成 CRC 正确的 1×1 PNG，先放置带无效 zlib 窗口头的 zTXt，再放置 512 KiB tEXt 使 libpng 释放并替换共享 chunk buffer，随后调用上述顺序。

三轮 ASan 重放结果一致：

- 受影响归档：3/3 在 `png_read_end` 路径报告 heap-use-after-free，读发生在 `png_zlib_inflate`；ASan 栈显示缓冲区由 `png_handle_zTXt` 分配，经较大的 `png_handle_tEXt` 重新分配时释放。
- 修复提交对照：3/3 不再出现 ASan UAF；同一畸形输入按预期因 PNG/zlib 错误退出。
- 安全顺序控制：在同一受影响版本先读图像行再调 `png_read_end`，3/3 未触发 UAF。
- 无重新分配控制：短 tEXt 输入在受影响版本中 3/3 未触发 UAF。

环境为 x86_64、GCC 11.4、AddressSanitizer、系统 zlib 1.2.11；只在本地临时目录构建和运行，未触及 G 盘工作树、设备、网络服务或真实用户数据。PoC 输入 SHA-256 为 `b46c2e24a0866c307cfe0a42360a78819e21282f8c0dd228445cf86373bcc68b`；控制输入 SHA-256 为 `a1a9361f86489e4c39863433145444deb8216d6a1466cd07aa2eb36fdd94a576`。

复现命令（要求 GCC、CMake、GNU patch、zlib 开发头文件）：

```bash
.venv-web/bin/python research/data_sensitive/d30_libpng_cve_2026_46675_replay.py
  --source-tar /mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/third_party_libpng/libpng-1.6.55.tar.gz
```

脚本校验归档 SHA-256，只解压固定归档到临时目录，分别构建受影响与修复对照版本，生成 PoC 和控制 PNG，重复运行三轮，产出机器可读 JSON。它不联网，也不修改传入归档。

## 扫描器与修复建议

D 的已披露 CVE 规则把 libpng 1.6.0–1.6.58 标为 source-level candidate。当前 0.9.0 直接扫描从该归档提取的 `png.h` 得到 `CVE-2026-46675` candidate 于 `png.h:277`，source SHA-256 为 `00e93d3c87cde182df182a3e6090e704b4208d48f9473a6af4c651b8a0be05f1`，parse_status=`not_run`、DetectorRun=`blocked`；真实 G 镜像 Runner/API→Worker→报告→源码查看此前已由 D22 对同一归档路径验证。这条版本候选是组件版本筛查，不证明产品采用了该组件或调用了受影响顺序。

优先升级到 libpng 1.6.59 或更高版本。无法升级时，采用维护者修复提交 `aa77ef3` 中清空 zlib 输入/输出指针及计数的逻辑。应用侧避免在尚未读取图像行时直接调用 `png_read_end()`；确需处理尾部 ancillary chunks 时，先开始读取图像，再处理尾部并正确处理格式错误。

## 结论边界

上游公告确认受影响版本和触发前置条件；本次 ASan 证明指定 1.6.55 归档在该调用顺序下发生组件 UAF，修复提交消除本次复现。尚未确认 OpenHarmony 最终产品构建是否采用这份归档、产品调用点是否满足罕见顺序，也未测试设备/产品版本。结论标签为：**组件根因 confirmed；OpenHarmony 产品适用性、入口和影响 unknown；`validated_vulnerability=0`**。

参考：[libpng 维护者安全公告](https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j)、[上游修复提交](https://github.com/pnggroup/libpng/commit/aa77ef38c17ab2fc1b41bec09fb973c6a386641d)。
