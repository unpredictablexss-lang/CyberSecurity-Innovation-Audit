# 已披露漏洞候选扫描（2026-10-19）

## 结论与范围

针对 `OHScanner_G盘源码漏洞审查记录_20261018.md`，`ohscanner.known_disclosed_cves` 当前为 0.14.0，支持 16 项有具体源码线索的公开 CVE 形态：CVE-2022-45877、CVE-2025-9900、CVE-2025-25212、CVE-2025-27247、CVE-2025-57052、CVE-2026-25850、CVE-2026-28733、CVE-2026-28751、CVE-2026-27648、CVE-2026-33636、CVE-2026-46675、CVE-2026-67215、CVE-2026-67216、CVE-2026-92391、CVE-2026-9079、CVE-2026-92392。每个命中都是 `candidate`，仍绑定源 SHA、规则版本、CWE，并保留组件构建、产品入口、攻击者控制和影响等证据义务；`validated_vulnerability` 不升级。

17 项独立公开 CVE 审查清单中，当前规则覆盖 16 个 CVE 条目；剩余 CVE-2026-58313 仍没有可靠的正向规则映射。D20-D24 固定 G 盘快照记录的结果保持不变；D25 对 cJSON 上游漏洞父提交/修复提交进行精确源码对照；D35 新增 filemanagement_storage_service 两条官方分支固定源码正反对照；D36 新增 CVE-2026-28733 的跨函数 map-iterator 生命周期候选，并发现官方 mutex 补丁与当前 5.1 源码仍保留该结构；D37 用 CVE-2026-28751 的 MTP 满长度 xattr 源码修复对照新增边界读取候选；D38 对 CVE-2026-92392 完成 curl 8.22.0/8.23.0 固定源码正反回放。所有规则样本仍是开发/回归材料，不是独立 holdout，也不能据此声称 17 项或全项目的 Recall。

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
- CVE-2026-27648：FlowbufStrAtIndex 未核对 offset 与长度是否仍处于共享 flowbuffer 数据区；ProcessNativeProxyResultNewFlowbuf 在重建 dataList 时按 curIndex 写入但循环无容器上界。两类风险独立保留：只要范围检查或目标数组上界之一仍缺失，就保留 candidate。官方 6.0/5.1/5.0.3 修复 PR 分别为 [#7093](https://gitcode.com/openharmony-tpc/chromium_src/pull/7093)、[#7110](https://gitcode.com/openharmony-tpc/chromium_src/pull/7110)、[#7108](https://gitcode.com/openharmony-tpc/chromium_src/pull/7108)。详细固定 commit、重放和限制见 D28_WEBVIEW_CVE_2026_27648.md.

- CVE-2026-33636：新增 ARM NEON 调色板扩展规则，分别检查 RGBA 4 像素和 RGB 8 像素函数是否处理不完整尾块，以及是否恢复预调整的输出指针。固定官方 libpng 1.6.55 源码保留两条候选，官方 1.6.56 修复源码为 0；原始文件 Git blob/SHA-256 均锁定并重复三轮。G 盘 OpenHarmony 镜像记录已指出对应补丁清单含修复，但具体产品依赖/构建仍未知。该回放是组件源码规则回归，未运行 ARM NEON PoC，产品状态不是 confirmed。详见 D29_LIBPNG_NEON_CVE_2026_33636.md.

- CVE-2025-9900：先对栅格目标指针按图像尺寸偏移的危险形态；正例、已校验尺寸/非偏移修复形态对照。
- CVE-2025-25212：Pasteboard observer 集合写入但函数内未见按进程身份配额；生命周期、外部限流和真实调用者仍需复核。
- CVE-2025-27247：在同一源码文件中连接 Binder `GET_PASTE_DATA` dispatch、handler 和数据返回；只在路径内没有可见权限检查时保留候选，不能排除文件/系统服务外部授权。
- CVE-2026-46675：libpng 1.6.0–1.6.58 版本标记或 `png_read_info` 后未读图像行就调用 `png_read_end`；版本 1.6.59 和安全读取顺序为负例。
- CVE-2026-67215：JSON Patch apply 对值做深复制、批量处理 patch，并在 cleanup 调用递归释放且函数内无可见深度限制；有上限的控制为负例。官方描述要求攻击者可控 JSON Patch 输入，且 cJSON_Utils 构建/产品调用入口仍未知（[Red Hat CVE 说明](https://access.redhat.com/security/cve/cve-2026-67215)）。
- CVE-2026-67216：`cJSON_Compare` 对对象递归比较并重复线性 key lookup；普通解析、非递归比较为负例。
- CVE-2026-92391：拥有子 MIME 的释放回调重入 `curl_mime_free`，且相关路径无可见深度上限；有限深度控制为负例。

已披露 CVE 样本来自规则开发语料，是调参/回归集，不能作为独立 holdout。D29 增加了两份官方原始文件哈希校验、三轮稳定重放和 Workbench API→Worker→报告→源码查看的修复前后集成测试；这些证明候选引擎能识别该已知根因并绑定源码，仍不构成独立召回评估。

## 已证实的上游修复信息与 PoC 边界

CVE-2026-46675 的上游维护者公告确认 libpng 1.6.0–1.6.58 受影响、1.6.59 修复：压缩 zTXt/iTXt/iCCP 块异常退出解压后，zlib 输入指针可能仍指向已释放内存；若调用方在读取图像行前执行 `png_read_end`，可能触发 use-after-free，最坏结果为进程崩溃。可核对 [libpng 维护者公告与修复提交](https://www.openwall.com/lists/oss-security/2026/09/29/4) 和 [libpng 官方主页](https://libpng.org/pub/png/libpng.html)。

- 已确定的修复建议：升级 vendored libpng 到 1.6.59 或更高版本，或应用维护者修复 [aa77ef38c17ab2fc1b41bec09fb973c6a386641d](https://github.com/pnggroup/libpng/commit/aa77ef38c17ab2fc1b41bec09fb973c6a386641d)。临时规避：未读图像行时不要调用 `png_read_end`；若确需读尾部块，先按公告要求启动图像行读取。
- D22 的固定 Git commit `e57b1079564a02a50321ec528aa6e41884979d32` 面板回放最初只验证了静态候选和源码绑定；D30 随后在该提交中的 libpng 1.6.55 构建归档上用 ASan 复现了组件 UAF，并对上游修复做同输入重测。D30 仍不证明具体 OpenHarmony 产品构建和调用路径。
- 没有 OpenHarmony 产品镜像/构建清单来确认这个 tarball 最终被编入具体产品，也未确认外部输入能到达相应调用序列。因此 OpenHarmony 产品状态仍为 `candidate/unknown`，`validated_vulnerability=0`；不能提交一个声称验证了产品影响的 exploit PoC。
- 其余 6 项组件候选目前仅有静态规则和正反控制，没有在本轮取得完整受影响产品构建、可执行漏洞 PoC 和修复后组件重验的证据；不填造 PoC 或影响版本。

D22 的可重复面板/候选回归脚本与结果分别见 `d22_archive_runner_panel.py` 和 `D22_ARCHIVE_RUNNER_PANEL.json`。测试 fixture 是扫描器规则回归，不作为漏洞利用 PoC。

## D30：CVE-2026-46675 运行时组件复现

D30 在 G 镜像中实际跟踪的 libpng 1.6.55 构建归档上补齐了独立的组件级 ASan PoC：构造 CRC 正确的 PNG，异常 zTXt 后接触发 chunk buffer 重分配的长 tEXt，再按 `png_read_info` → `png_read_end` 顺序处理。3/3 在旧源码报 heap-use-after-free；对解压副本应用精确上游修复提交 `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` 后，同一输入 3/3 不再触发。先读图像行和不触发 buffer 重分配两个控制各 3/3 无 UAF。归档 SHA-256 与 G 仓库 HEAD blob 一致；固定修复对照是把官方修复提交应用到 1.6.55 副本，不是完整构建 1.6.59。详见 [D30 PoC/修复报告](D30_LIBPNG_CVE_2026_46675_REPORT.md)、C PoC、重放脚本和 JSON。组件 UAF confirmed；OpenHarmony 产品构建、调用顺序和影响仍 unknown，`validated_vulnerability=0`。


## 未覆盖项及不可推断事项

审查清单中剩余 1 项目前没有可靠的正向规则映射：CVE-2026-58313 仍缺少从公告根因到可审源码形态的闭环（master 有修复迹象）。CVE-2026-92392 已由 D38 建立窄源码形态候选；G 盘镜像提交 HEAD 的 curl 8.8.0 低于其受影响版本。未扫描、不命中和有修复线索都不自动代表安全。CVE-2026-33636 虽新增历史组件版本检测形态，但 G 镜像显示本地补丁清单已有该修复，因此它不作为当前产品漏洞报告。

没有 OpenHarmony 产品产物/构建来源、产品级入口、权限与攻击者控制、影响证据及必要的受控动态验证，因此当前所有扫描结果仍为候选，产品 `confirmed/reportable=0`。静态命中和组件级 Harness 不证明产品漏洞。当前已覆盖 17 项独立审查条目中的 16 个窄源码形态，CVE-2026-58313 尚未覆盖；规则开发样本不能替代冻结且独立标注的数据，也不代表对整个项目达到完整覆盖。D25/D29/D35/D36/D37 上游旧/新源码对照不能替代冻结 holdout。


## 2026-10-19 D23 calibration

D20/D22 remain bound to 0.3.0 and D23 to 0.4.0. Current 0.5.0 binds CVE-2025-9900 to the TIFFReadRGBAImageOriented body so unrelated comparisons in preceding functions cannot suppress it. A pinned Git replay hit line 621 twice with stable identity; coverage remains blocked/partial. D23 targeted regression was 10/10; current 0.5.0 detector regression is 11/11. See [D23 rule calibration and fix review](D23_LIBTIFF_CVE_2025_9900_RULE_CALIBRATION.md) and the reproduction script.


## 2026-10-19 D24 curl credential-clear rule

Detector 0.5.0 adds a positive vulnerable-shape rule for CVE-2026-9079 and a negative fixed-shape control. The official curl advisory covers libcurl 8.8.0-8.20.0 and identifies fix commit 88c7e16cceec816a2df45c89. The pinned G-drive 8.8.0 source contains fix-equivalent unconditional credential clearing, so the Runner produces no candidate for this CVE on that snapshot. The two-file scan is blocked/partial; no finding is not a safe verdict. No product caller, handle reuse, credential disclosure, or product impact is established. Details: D24_CURL_CVE_2026_9079_REPLAY_REPORT.md and d24_curl_cve_2026_9079_replay.py.


## 2026-10-19 D25 cJSON CVE-2025-57052

Detector 0.6.0 adds the one-character `pointer[0]` versus `pointer[position]` root-cause signature. The exact upstream parent commit produces one CVE-2025-57052 candidate at `cJSON_Utils.c:285`; the official fix commit produces none for this CVE. A rootless component PoC with synthetic JSON demonstrates that the malformed pointer `/1844674407370955160B` resolves the synthetic array element in the old source and is rejected after the fix. This is a component API reproduction, not an OpenHarmony product PoC; product inclusion, caller reachability, and impact remain unknown, so `validated_vulnerability=0`. Details: D25_CJSON_CVE_2025_57052_REPORT.md, `D25_CJSON_CVE_2025_57052_POC.c`, and `d25_cjson_cve_2025_57052_replay.py`.


## D28 WebView CVE-2026-27648

新增规则经官方 6.0 发布线固定快照 6539ea501a7a 中的真实修复前提交 a2de9fed 命中 1 条 candidate（nweb_handler_delegate.cc:4510），修复提交 18c5ba4d 无命中；二者均在该发布线历史内。Tree-sitter 未运行，两个 run 均 blocked。另有 Workbench API 到 Worker、报告和源码查看的回归，确保候选携带固定源码 SHA 并保持 validated_vulnerability=0。复现细节和边界见 D28 WebView 报告与 JSON 回放结果。

## D31 libtiff CVE-2025-9900 动态组件对照

D31 在固定 `third_party_libtiff@d4a0516c477dfbaf1153ae295893ab75aadd63d4` 上重复得到 `tif_getimage.c:621` 候选，source SHA-256 与 Git 对象相同。CMake 构建的 ASan 组件 PoC 以合法 16×16 调色板 TIFF 请求写入 16×1 栅格，旧版 3/3 在 `put8bitcmaptile` 报 WRITE 访问；应用上游 MR !732 的完整尺寸处理改动后 0/3 报告，16×16 安全控制 0/3。代码、回放脚本与机器结果见 `D31_LIBTIFF_CVE_2025_9900_REPORT.md`、`d31_libtiff_cve_2025_9900_replay.py` 和 `D31_LIBTIFF_CVE_2025_9900_REPLAY.json`。

此处 confirmed 只表示固定 libtiff 4.7.0 组件路径出现 ASan 越界写；漏洞公告描述更强的 write-what-where 风险，但本 Harness 未证明任意地址可控或代码执行。OpenHarmony 产品构建、攻击者可控调用入口及影响仍 unknown，扫描命中仍为 candidate，`validated_vulnerability=0`。此处是固定源码 Runner 回放，不是本轮 UI API 回归；扫描页集成与其他面板路径验证见 D22/D30。

## D33 CVE-2022-45877 device-manager PIN 传输

0.10.0 增加 OnGroupCreated 同函数内 PIN→authToken→认证响应 SoftBus 发送链规则。对官方固定旧源码 97c3d5c7b07a0ab599afcc1464143b255e7dbb68 命中 1 条 candidate（dm_auth_manager.cpp:348）；修复提交 8bea775dc169bca2d9a1ce57ada2d86cbd179163 不命中。两份 Git 源文件 SHA 固定在 JSON 结果。旧/新 detector run 均 blocked（partial AST），结果只验证组件规则对已知根因的正反识别。NVD 将 OpenHarmony 3.1 至 3.1.4（含）列为受影响；目标产品实际版本、构建纳入、SoftBus 通道可观察性及产品影响 unknown。组件历史根因 confirmed，不升级产品 finding 或 validated_vulnerability。详见 [D33 组件 PoC 与修复复审](D33_CVE_2022_45877_REPORT.md)、回放脚本和 JSON。

## D35 CVE-2026-25850 external-volume 权限扩大

`known_disclosed_cves` 0.11.0 新增 filemanagement_storage_service 的精确路径/方法形态。官方 5.1 与 6.0 MR 分支中，`DoMount4Ext` / `DoMount4Hmfs` 在挂载成功后对挂载树递归调用 `TravelChmod(..., 0777)`；固定修复分支删除这两处调用。D35 直接读取四个 pinned commit 的 Git 对象，校验 tree/blob/SHA-256，并校验 helper 的递归实现。两条 release pair 均为旧源 2 candidate、修复源 0；direct replay 设 parse `not_run`，所以两端覆盖为 blocked，candidate 保留。组件问题与官方公告相符；不证明产品镜像采用受影响提交或未授权主体能读到具体数据。详见 [D35 报告](D35_FILEMANAGEMENT_CVE_2026_25850_REPORT.md)、脚本和 JSON。D35 是源码扫描复现，不是 runtime permission PoC。

## D36 CVE-2026-28733 storage statistics iterator lifetime

0.12.0 增加同文件跨函数候选：GetUserStatistics 返回共享 opStatistics_ map iterator，多个 handler 在 helper 返回、内部锁已释放后写 it->second；GetTempStatistics 在另一调用路径复制并清空同一 map。官方 5.1 修复 MR !2114 确实给两个 helper 加了 mutexStats_，但当前 5.1 头与补丁 blob 完全相同，迭代器仍逃逸锁作用域。固定父提交、补丁提交和当前 release head 的源文件 SHA 均由 D36 replay 校验，三者各报告 1 条 candidate。因因果调度和完整服务动态复现尚未验证，该项是并发/UAF 候选，不断言官方补丁无效，也不升级产品确认；修复建议是把读取/更新放在统一锁保护的 API 内并让快照清空与更新互斥，避免向调用者返回容器迭代器。详见 D36_CVE_2026_28733_REPORT.md、脚本和 JSON。

## D37 CVE-2026-28751 MTP xattr 长度边界

0.13.0 新增 NotifyMtpMounted 窄形态：同函数内按 MTP_DEVICE_NAME_LEN 分配缓冲区、以同一上限调用 getxattr、仅在 len < 上限时写 NUL，随后将 value 当 C 字符串消费。官方 6.0 父提交命中 1 条 candidate；官方 MTP 修复提交和当前 6.0 head 为 0。当前 5.1 文件不含此函数/调用签名，零命中仅表示这条规则未匹配，不是安全结论。固定 Git tree/blob/SHA 校验见 D37 replay JSON。源代码形态 ASan harness 对满长非 NUL 输入 3/3 报 heap-buffer-overflow；预留一字节并在 <= 边界写终止符的控制 0/3 报错。该 harness 不是完整服务构建或产品利用；产品版本、外部 xattr 来源、MTP 攻击路径和影响仍 unknown。详见 D37_CVE_2026_28751_REPORT.md、回放脚本和 JSON。

## D38 CVE-2026-92392 libcurl HTTP/2 upload UAF

0.14.0 新增 `lib/multi.c::multi_done` 窄序列规则。curl 8.22.0-DEV 公告前源码在连接过滤器通知和 pending handle 调度之前尚未完成 `Curl_req_done`，命中 1 条 CWE-416 candidate；8.23.0-DEV 修复源把请求清理提前，并在连接池返回后调度，命中 0 条。G 盘 `third_party_curl` 的固定提交 `1386bb128bb060b284309397b97adcaaec21c003` 声明版本 8.8.0，版本不在公告受影响范围，命中 0 条。版本缺失或冲突时保留源码形态候选并标注适用性 unknown。

回放只读 pinned Git objects；G 盘镜像工作树有大量未提交删除状态，因此不读工作树内容。回放的 `parse_status=not_run` 使 DetectorRun 保持 `blocked`，候选仍保留；未跑完整仓库 Tree-sitter/Runner、HTTP/2 reset PoC 或 OpenHarmony 产品构建。上游修复建议为升级 curl 8.23.0 或应用官方修复提交；产品版本、入口与影响仍 unknown，`validated_vulnerability=0`。详情见 [D38 报告](D38_CVE_2026_92392_REPORT.md)、固定源 [JSON](D38_CVE_2026_92392_REPLAY.json) 与回放脚本。
