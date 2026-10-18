# 已披露漏洞候选扫描（2026-10-19）

## 结论与范围

针对 `OHScanner_G盘源码漏洞审查记录_20261018.md`，`ohscanner.known_disclosed_cves` 从 0.1.0 升至 0.5.0，支持 8 项有具体本地源码线索的公开 CVE 形态：CVE-2025-9900、CVE-2025-25212、CVE-2025-27247、CVE-2026-46675、CVE-2026-67215、CVE-2026-67216、CVE-2026-92391、CVE-2026-9079。每个命中都是 `candidate`，仍绑定源 SHA、规则版本、CWE，并保留组件构建、产品入口、攻击者控制和影响等证据义务；`validated_vulnerability` 不升级。

17 项公开 CVE 审查清单中，当前规则覆盖 8 个 CVE 形态：7 个固定源码候选命中，1 个固定源码形态显示已有修复迹象；审查清单仍有 9 项没有正向可检出形态：有的缺少对应源码，有的缺精确根因映射，有的当前快照有修复线索或版本不在受影响范围。不是“17 项都扫描通过”，也不是 Recall 结果。

## 固定源码回放

复现脚本 `d20_disclosed_cve_replay.py` 只读取 G 盘仓库的固定 Git 对象，两次重复运行并比较 tree、snapshot、候选身份和覆盖状态。输入仓库工作树中的未提交内容不会进入实验。原始逐项 JSON 在 `D20_KNOWN_CVE_REPLAY.json`。

| 仓库/固定版本 | 命中 | 状态与边界 |
|---|---|---|
| third_party_libpng `e57b1079564a`，构建输入 `libpng-1.6.55.tar.gz` | CVE-2026-46675，`png.h:277` | 初始 D20 为归档成员直接回放；D22 已验证普通 Runner 与面板 API→Worker→报告→源码查看均识别该候选，两次报告候选身份一致。Tree-sitter 部分解析，Detector blocked，任务 completed_with_limitations。归档/成员 SHA 双重绑定，不是产品漏洞确认。 |
| third_party_libtiff `d4a0516c477dfbaf1153ae295893ab75aadd63d4` | CVE-2025-9900，`libtiff/tif_getimage.c:621` | Runner 绑定 Git tree/blob/snapshot；候选重复一致，解析 partial，run blocked。 |
| third_party_curl `1386bb128bb060b284309397b97adcaaec21c003` | CVE-2026-92391，`lib/mime.c:1146` | Runner 绑定 Git tree/blob/snapshot；候选重复一致，run completed。 |
| third_party_cJSON `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748` | CVE-2026-67216，`cJSON.c:3067`；CVE-2026-67215，`cJSON_Utils.c:808` | Runner 绑定 Git tree/blob/snapshot；两候选重复一致，解析 partial，run blocked。cJSON-Utils 的产品构建包含条件仍需核验。 |
| miscservices_pasteboard `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | CVE-2025-25212，`pasteboard_service.cpp:222`；CVE-2025-27247，`pasteboard_service_stub.cpp:41` | Runner 绑定固定 Git tree/blob/snapshot；候选重复一致，run blocked。它是 2022 旧快照，不是 v5.0.3 产品构建证明。 |

libpng 归档成员同时记录上游归档 Git blob、归档 SHA-256 和 `png.h` SHA-256。D22 通过 `/api/v1/detectors` 检查面板目录注册，再以固定提交重复执行真实 API→Worker→报告→源码查看流程；候选路径为 `libpng-1.6.55.tar.gz.members/libpng-1.6.55/png.h:277`。每条结果仍不是 OpenHarmony 产品漏洞确认。公开披露事实与受影响版本以审查记录引用的公告/上游安全页为准。

## 规则与回归

- CVE-2025-9900：先对栅格目标指针按图像尺寸偏移的危险形态；正例、已校验尺寸/非偏移修复形态对照。
- CVE-2025-25212：Pasteboard observer 集合写入但函数内未见按进程身份配额；生命周期、外部限流和真实调用者仍需复核。
- CVE-2025-27247：在同一源码文件中连接 Binder `GET_PASTE_DATA` dispatch、handler 和数据返回；只在路径内没有可见权限检查时保留候选，不能排除文件/系统服务外部授权。
- CVE-2026-46675：libpng 1.6.0–1.6.58 版本标记或 `png_read_info` 后未读图像行就调用 `png_read_end`；版本 1.6.59 和安全读取顺序为负例。
- CVE-2026-67215：JSON Patch apply 对值做深复制、批量处理 patch，并在 cleanup 调用递归释放且函数内无可见深度限制；有上限的控制为负例。官方描述要求攻击者可控 JSON Patch 输入，且 cJSON_Utils 构建/产品调用入口仍未知（[Red Hat CVE 说明](https://access.redhat.com/security/cve/cve-2026-67215)）。
- CVE-2026-67216：`cJSON_Compare` 对对象递归比较并重复线性 key lookup；普通解析、非递归比较为负例。
- CVE-2026-92391：拥有子 MIME 的释放回调重入 `curl_mime_free`，且相关路径无可见深度上限；有限深度控制为负例。

`tests.detectors.test_known_disclosed_cves` 当前 11 项测试通过，包含 vulnerable/fixed、安全、无关、partial 候选保留及上述剪贴板两项控制；另有归档索引、限制/损坏处理、source manifest 与面板源码查看回归。最终全量 Python 回归 915 项通过（910 passed / 5 skipped / 0 failed），前端 Node 测试 17/17、TypeScript 检查、`compileall`、D22 JSON 解析与 `git diff --check` 通过。生产 Web bundle 构建未通过，原因是 WSL 的 `node_modules` 带 Linux esbuild，而唯一可用 Node 是 Windows 运行时；Web 源码未修改。用于构造规则的已披露样本是调参/回归集，不能作为独立 holdout。

## 已证实的上游修复信息与 PoC 边界

CVE-2026-46675 的上游维护者公告确认 libpng 1.6.0–1.6.58 受影响、1.6.59 修复：压缩 zTXt/iTXt/iCCP 块异常退出解压后，zlib 输入指针可能仍指向已释放内存；若调用方在读取图像行前执行 `png_read_end`，可能触发 use-after-free，最坏结果为进程崩溃。可核对 [libpng 维护者公告与修复提交](https://www.openwall.com/lists/oss-security/2026/09/29/4) 和 [libpng 官方主页](https://libpng.org/pub/png/libpng.html)。

- 已确定的修复建议：升级 vendored libpng 到 1.6.59 或更高版本，或应用维护者修复 [aa77ef38c17ab2fc1b41bec09fb973c6a386641d](https://github.com/pnggroup/libpng/commit/aa77ef38c17ab2fc1b41bec09fb973c6a386641d)。临时规避：未读图像行时不要调用 `png_read_end`；若确需读尾部块，先按公告要求启动图像行读取。
- 已复现的是静态候选检测：固定 Git commit `e57b1079564a02a50321ec528aa6e41884979d32` 中有 libpng 1.6.55 源码归档；D22 经面板重复得到同一候选，源码查看 SHA 与候选一致。它不是触发 use-after-free 的运行时 PoC。
- 没有 OpenHarmony 产品镜像/构建清单来确认这个 tarball 最终被编入具体产品，也未确认外部输入能到达相应调用序列。因此 OpenHarmony 产品状态仍为 `candidate/unknown`，`validated_vulnerability=0`；不能提交一个声称验证了产品影响的 exploit PoC。
- 其余 6 项组件候选目前仅有静态规则和正反控制，没有在本轮取得完整受影响产品构建、可执行漏洞 PoC 和修复后组件重验的证据；不填造 PoC 或影响版本。

D22 的可重复面板/候选回归脚本与结果分别见 `d22_archive_runner_panel.py` 和 `D22_ARCHIVE_RUNNER_PANEL.json`。测试 fixture 是扫描器规则回归，不作为漏洞利用 PoC。

## 未覆盖项及不可推断事项

审查记录余下 9 项尚未获得正向可检出形态：CVE-2026-27648 本地镜像缺 web_webview 源码；CVE-2022-45877 当前旧代码不足以证明 PIN 明文传输；CVE-2026-58313、CVE-2026-28733、CVE-2026-25850、CVE-2026-28751 缺少当前快照到公告根因/受影响产品版本的可靠闭环（其中部分 master 有修复迹象）；CVE-2025-57052 当前 cJSON 有修复迹象；CVE-2026-33636 当前 libpng 补丁清单包含修复；CVE-2026-92392 当前 curl 8.8.0 低于其受影响版本；未扫描、不命中和有修复线索都不自动代表安全。

没有 OpenHarmony 产品产物/构建来源、产品级入口、权限与攻击者控制、影响证据及必要的受控动态验证，因此当前所有结果仍为候选，产品 `confirmed/reportable=0`。静态命中和组件级 Harness 不证明产品漏洞。下一步是补真实修复提交的正反样例，再用冻结且独立标注的数据评估召回；当前 8 个规则家族结果（7 个候选命中、1 个修复形态控制） 不代表对 17 项清单或整个项目达到完整覆盖。


## 2026-10-19 D23 calibration

D20/D22 remain bound to 0.3.0 and D23 to 0.4.0. Current 0.5.0 binds CVE-2025-9900 to the TIFFReadRGBAImageOriented body so unrelated comparisons in preceding functions cannot suppress it. A pinned Git replay hit line 621 twice with stable identity; coverage remains blocked/partial. D23 targeted regression was 10/10; current 0.5.0 detector regression is 11/11. See [D23 rule calibration and fix review](D23_LIBTIFF_CVE_2025_9900_RULE_CALIBRATION.md) and the reproduction script.


## 2026-10-19 D24 curl credential-clear rule

Detector 0.5.0 adds a positive vulnerable-shape rule for CVE-2026-9079 and a negative fixed-shape control. The official curl advisory covers libcurl 8.8.0-8.20.0 and identifies fix commit 88c7e16cceec816a2df45c89. The pinned G-drive 8.8.0 source contains fix-equivalent unconditional credential clearing, so the Runner produces no candidate for this CVE on that snapshot. The two-file scan is blocked/partial; no finding is not a safe verdict. No product caller, handle reuse, credential disclosure, or product impact is established. Details: D24_CURL_CVE_2026_9079_REPLAY_REPORT.md and d24_curl_cve_2026_9079_replay.py.
