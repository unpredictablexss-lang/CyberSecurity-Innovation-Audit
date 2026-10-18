# 已披露组件漏洞首批扫描器（2026-10-19）

## 目标与证据边界

针对 `OHScanner_G盘源码漏洞审查记录_20261018.md` 中有本地组件代码线索的公开 CVE，新增默认启用的第一方检测器 `ohscanner.known_disclosed_cves`，规则版本 `0.1.0`。诊断绑定扫描源 SHA、规则版本和 CWE，并保留组件身份、产品构建、攻击路径、影响四项缺证义务。任何命中都是候选，不把公告、组件 Harness 或规则回放当成 OpenHarmony 产品漏洞确认。

## 当前支持的首批 CVE

| CVE | 检测线索 | 控制与回放 |
|---|---|---|
| CVE-2025-9900 libtiff | `TIFFRGBAImageGet(&img, raster + (rheight - img.height) * rwidth, ...)` 这类先按未校验尺寸偏移目标指针的路径 | vulnerable/fixed 合成控制通过；从固定 blob `third_party_libtiff@d4a0516c477dfbaf1153ae295893ab75aadd63d4:libtiff/tif_getimage.c` 命中 1 条 |
| CVE-2026-92391 libcurl | 所有权子 MIME 的 `freefunc` 清理回调重入 `curl_mime_free`，释放循环再调 part cleaner；可见深度上限则不报 | recursive/fixed-depth 合成控制通过；从固定 blob `third_party_curl@1386bb128bb060b284309397b97adcaaec21c003:lib/mime.c` 命中 1 条 |
| CVE-2026-67216 cJSON | `cJSON_Compare` 对对象递归比较，双向重复线性 key lookup | positive/nonrecursive/parse-only 合成控制通过；从固定 blob `third_party_cJSON@0c2c9dff82cc85539c8362132d7a5f6bf7d1e748:cJSON.c` 命中 1 条 |
| CVE-2026-46675 libpng | vendored C source version macro `PNG_LIBPNG_VER_STRING` 落入 1.6.0–1.6.58；或单函数中 `png_read_info` 后直接 `png_read_end` 且未读图像行 | 1.6.55/1.6.59 版本控制与 unsafe/safe API sequence 合成控制通过。当前 wrapper Git tree 未包含上游 libpng C 源码，故尚无实际 Git blob 命中；真实产品调用点仍 unknown |

精确源码来自 `git show <commit>:<path>`，没有读取或改动 G 盘仓库的工作树文件。报告称 libtiff 仓库工作树干净，但当前再次检查时看到它已有 tracked modifications；因此只用固定提交对象复核，不把当前工作树状态写成干净，也未触碰这些改动。

## 验收结果

- `tests.detectors.test_known_disclosed_cves`：8 项通过，包括正反控制、libtiff fixed、curl 显式深度限制、libpng fixed version/API sequence、partial parse blocked 并保留候选，以及 candidate-only 义务。
- 以 `run_reviewed_detectors` 从各自精确本地 Git commit 扫描上述三个源码文件：libtiff 命中 CVE-2025-9900、curl 命中 CVE-2026-92391、cJSON 命中 CVE-2026-67216，三项 source_binding 均为 `bound`。libtiff 和 cJSON 解析为 partial，故其 DetectorRun=`blocked`、analysis_status=`partial`，但词法候选被保留；curl 解析与 DetectorRun 均为 complete。`validated_vulnerability` 仍为 0。
- 当前首批检测器支持 4 个 CVE 代码族，不覆盖审查记录里其余公开 CVE；也不等于对 17 项漏洞完成全量回归。
- 用于规则开发的已披露案例不是独立 holdout，不能据此声称 Recall 达标。未做当前 OpenHarmony 产品构建、入口/权限链或产品 PoC 核验，`validated_vulnerability` 不因本规则变化。

## 规则限制

这些是窄源码签名，不是通用污点分析。源码重构、宏展开、跨文件封装、不同分支或元数据格式可能产生漏报；cJSON 递归比较与 MIME 层级还需要结合使用点和攻击者控制才能判断 DoS 可达。unknown/partial 输入不报 safe，检测器返回 blocked 并保留覆盖限制。产品修复状态、组件实际编入、API 调用者与受影响版本必须继续追源。
