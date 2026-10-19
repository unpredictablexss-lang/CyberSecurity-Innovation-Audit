# D31：libtiff CVE-2025-9900 PoC 与修复对照

日期：2026-10-19
组件判定：**CVE-2025-9900 的 libtiff 4.7.0 组件路径 confirmed**；OpenHarmony 产品构建、调用入口与影响 unknown。扫描器输出仍是 candidate，`validated_vulnerability=0`。

## 固定源码与扫描结果

- 只读对象：G 盘 `third_party_libtiff` 的 commit `d4a0516c477dfbaf1153ae295893ab75aadd63d4`，Git tree `33beab3b3b50fe6678b1a74ed48ac3b69084c6ec`。仓库工作树另有 dirty 文件；脚本从 `git archive` 导出固定 commit，不采纳这些改动。
- `libtiff/tif_getimage.c` 的 Git blob 为 `5121e85b9eb2bc734b557892c0968f629d370b82`，SHA-256 为 `4b664c80e2e208c2a9cd33042419f69e590ff088c1a3befe99581d1b1df5471a`，版本为 4.7.0。
- 当前 `ohscanner.known_disclosed_cves` 0.9.0 两次固定源码回放一致，在 `tif_getimage.c:621` 报 CVE-2025-9900 candidate，source SHA 与固定 blob 一致。此输入的 parse coverage 为 partial、DetectorRun 为 blocked；命中不能说明同一产品入口可达或安全影响已确定。
- 本次只读源码 Runner 回放，不冒称本轮走过面板 API。D 的规则已在扫描页面作为显式、默认关闭的研究选项集成；其他面板 API→Worker→报告→源码查看回归见 D22/D30 记录。

## 组件 PoC 和修复对照

`cve_2025_9900_read_small_raster.c` 通过 libtiff API 生成合法的 16×16、8-bit 调色板 TIFF，再调用 `TIFFReadRGBAImageOriented()`，要求将图像写入仅 16×1 的目标 raster。旧代码按 `(rheight - img.height) * rwidth` 计算目标偏移；较小的调用方高度令目标指针下溢。ASan 报告 `put8bitcmaptile` 中的 **WRITE memory access**，调用栈经 `TIFFRGBAImageGet()` 返回该 API。安全控制用同一图像和 16×16 目标 raster。

脚本在同一个固定源码快照的两个临时副本分别构建 ASan 版本；修复副本应用上游 libtiff MR !732 的代码改动。三轮结果均为：受影响版本 3/3 ASan 越界写；修复对照 0/3 ASan 报告；旧版本安全尺寸控制 0/3 ASan 报告。每次都重新生成输入，机器可读源身份、候选和输出记录在 `D31_LIBTIFF_CVE_2025_9900_REPLAY.json`。

上游 !732 将宽高适配移入 `TIFFRGBAImageGet()`，并让包装函数传入原始 `raster, rwidth, rheight`；这是 PoC 修复对照。建议升级到 libtiff 4.7.1 或更高版本，或针对准确基线审查并回移 [上游 MR !732](https://gitlab.com/libtiff/libtiff/-/merge_requests/732)；不要只手工删掉偏移表达式而不应用配套尺寸处理。

## 复现和结论边界

环境为 WSL2 x86_64、GCC 11.4、CMake、AddressSanitizer；禁用了不相关的可选 codec、工具和测试。脚本不访问网络、不写回 G 盘仓库：

```bash
.venv-web/bin/python research/data_sensitive/d31_libtiff_cve_2025_9900_replay.py \
  --repo /mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/third_party_libtiff
```

Red Hat CVE 公告将该缺陷描述为由特制 TIFF 图像触发的 write-what-where 风险；上游 MR 标题和改动描述为 raster 行数不足时的 buffer-underflow crash。[Red Hat CVE-2025-9900](https://access.redhat.com/security/cve/cve-2025-9900)、[libtiff MR !732](https://gitlab.com/libtiff/libtiff/-/merge_requests/732)、[libtiff 4.7.1 release notes](https://libtiff.gitlab.io/libtiff/releases/v4.7.1.html)。本次组件 PoC 证明越界写访问和崩溃，不证明攻击者能控制任意目标地址，也不证明代码执行。

没有确认该镜像文件进入具体 OpenHarmony 产品构建，没有追到产品里可由攻击者控制的 `rwidth/rheight` 调用点，也没有在产品/设备上复测。故只有**组件缺陷 confirmed**；产品漏洞、产品影响与利用性均为 **unknown**，不得把 scanner candidate 或 ASan Harness 结果升级成 OpenHarmony confirmed。
