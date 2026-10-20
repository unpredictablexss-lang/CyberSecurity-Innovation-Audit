# OpenHarmony 已披露漏洞与人工候选审查报告

审查日期：2026-10-18  
报告目的：补全下午人工审查输出；将公开 CVE、当前镜像对应代码状态、产品可达性和自行发现的候选分开，避免把历史发行版公告、组件 Harness 或静态线索误写成产品级漏洞。  
来源记录：会话副本 E:\读研\网络安全创新大赛\实验记录\agentR0R1R2用真实漏洞测试.docx（75 段落、无表格）。该文件是会话记录，只作为恢复结论的线索；下面的公开披露状态另以公告/上游安全页核对。  
本轮人工审查未使用 OHScanner。

## 结论先看

这份补充后的清单逐条核查 **17 项独立公开漏洞**。libpng 安装补丁清单还出现 CVE-2026-33416、CVE-2026-34757 两个编号，但本报告未将它们作为独立发现展开；因此全文共提及 19 个不同 CVE 编号。无论数量如何，这都不等于当前 OpenHarmony 产品漏洞数量：

- 公开公告确认的是对应 CVE 曾影响列出的历史发行版或上游组件。
- 当前本地源码中，能确认组件级缺陷并有本地重现证据的项目包括 libpng CVE-2026-46675、libtiff CVE-2025-9900；libcurl CVE-2026-92391 和 cJSON CVE-2026-67216 的组件路径有源码依据，但产品调用链仍未知。
- 多项 OpenHarmony CVE 针对旧发行分支；当前 master 已有修复迹象、当前对应仓库缺失，或具体代码映射尚未建立。
- **没有确认当前 OpenHarmony 产品上可由攻击者触发的重大漏洞，也没有确认新的 0day。**
- 自行发现的签名材料、并发状态和跨账号副作用均保留为 candidate；它们不是已确认漏洞。

## 结论标签

| 标签 | 本报告中的含义 |
| --- | --- |
| confirmed | 只确认紧随标签写明的事实，例如官方已披露、指定源码存在对应逻辑，或隔离组件测试复现；不自动代表产品漏洞。 |
| candidate | 有可疑代码路径，但攻击者可达性、安全影响或可利用性未闭环。 |
| unknown | 当前证据不足以判定。 |
| 排除/未匹配 | 已有具体反证，或本地版本不在受影响范围；不计作本地漏洞发现。 |

产品级漏洞结论还需要产品构建/版本、攻击入口、权限与攻击者控制、真实调用路径、CIA 影响及必要的动态验证。测试 Harness、ASan/计时实验和 CVE 公告本身都不能替代这些证据。

## 一、已公开披露的漏洞

以下先给公开披露事实，再单独写本地审计结果。官方公告确认旧发行版曾受影响，不等于当前 master 仍受影响。

### A. 本地组件中找到对应危险代码或组件级复现

#### CVE-2026-46675 — libpng 顺序读取中的悬空指针读取

- **公开披露：confirmed。** libpng GHSA 于 2026-09-29 发布：libpng 1.6.0–1.6.58 受影响，1.6.59 修复。特制 zTXt/iTXt/iCCP 块配合调用方先调用 png_read_info()、未读取图像行便调用 png_read_end()，可能使解压继续读取已释放的输入缓冲。公告给出的最坏影响是崩溃，不是代码执行。
- **本地组件：confirmed。** 仓库 G:\OpenHarmony-GitCode-Mirror\campaign-100-20261017\repos\third_party_libpng，master，HEAD e57b1079564a，工作树干净。README.OpenSource 和 BUILD.gn 指向 libpng 1.6.55；install.py 从 libpng-1.6.55.tar.gz 构建，现有补丁名单包含 CVE-2026-33416、CVE-2026-33636、CVE-2026-34757，但未列 CVE-2026-46675。手机产品配置包含 libpng。
- **动态证据边界：** 先前在 WSL /tmp 的隔离副本用特制 PNG 和 ASan 复现了堆 use-after-free；对临时副本应用上游修复后，同一输入不再触发。仓库本身未改动。**这是组件 Harness 证据，不是 OpenHarmony 产品崩溃确认。**
- **产品状态：unknown。** 当前镜像非测试源码中没有找到满足公告所需罕见顺序的产品调用点；没有设备或产品构建验证。
- **来源：** [libpng 官方 GHSA](https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j)；[上游修复提交](https://github.com/pnggroup/libpng/commit/aa77ef38c17ab2fc1b41bec09fb973c6a386641d)。

#### CVE-2025-9900 — libtiff 调色板读取越界写

- **公开披露：confirmed。** Red Hat 公告描述特制 TIFF 元数据可造成 write-what-where 风险；上游 4.7.1 发布说明包含修复。
- **本地组件：confirmed。** 仓库 G:\OpenHarmony-GitCode-Mirror\campaign-100-20261017\repos\third_party_libtiff，master，HEAD d4a0516c477d，工作树干净；本地版本为 4.7.0。关键路径在 libtiff/tif_getimage.c 的 put8bitcmaptile / TIFFReadRGBAImageOriented。
- **动态证据边界：** 先前在隔离副本以特制 16×16 调色板 TIFF 和较小目标缓冲运行 ASan，观察到越界写。该结果确认组件级问题路径；未证明远程代码执行，也未找到产品中会以受攻击者控制尺寸调用该 API 的入口。
- **产品状态：unknown。**
- **来源：** [Red Hat CVE-2025-9900 公告](https://access.redhat.com/security/cve/cve-2025-9900)；[libtiff 4.7.1 发布说明](https://libtiff.gitlab.io/libtiff/releases/v4.7.1.html)；[TIFFReadRGBAImage API](https://libtiff.gitlab.io/libtiff/functions/TIFFReadRGBAImage.html)。

#### CVE-2026-92391 — libcurl 深层 MIME 释放递归导致栈溢出

- **公开披露：confirmed。** curl 官方 2026-10-14 公告说明，通过公开 API 构造数千层嵌套 MIME 后，curl_mime_free() 递归释放会耗尽栈并崩溃；官方定为低危。受影响版本 7.56.0–8.22.0，8.23.0 修复。
- **本地组件：confirmed。** 仓库 G:\OpenHarmony-GitCode-Mirror\campaign-100-20261017\repos\third_party_curl，master，HEAD 1386bb128bb0，工作树干净。curlver.h 标记 8.8.0，BUILD.gn 编入 lib/mime.c；mime.c 的子结构清理会递归调用 curl_mime_free()。
- **产品状态：unknown。** request_request 当前可见的 curl_adp.cpp 构造平面表单，没有证据显示产品入口可构造数千层嵌套结构。本轮没有完成 curl 的动态复现。
- **来源：** [curl 官方 CVE-2026-92391 公告](https://curl.se/docs/CVE-2026-92391.html)；[上游修复提交](https://github.com/curl/curl/commit/d7546809d5bd548b69ec49fca2)。

#### CVE-2026-67216 — cJSON_Compare 指数级 CPU 复杂度

- **公开披露：confirmed，但来源评级有差异。** GitHub Advisory 将 GHSA 标为 Unreviewed；Red Hat 也发布了 CVE 说明，并指出必须由宿主程序显式将输入交给 cJSON_Compare() 与结构匹配的参考文档比较，普通 JSON 解析入口本身不足以触发。
- **本地组件：candidate / strong source match。** G:\OpenHarmony-GitCode-Mirror\repos\third_party_cJSON（独立于 98 仓库 campaign 目录），master，HEAD 0c2c9dff82cc，工作树干净，版本 1.7.19。代码包含 cJSON_Compare() 递归对象比较路径。此前观察到嵌套输入比较耗时快速增长，但这只是组件级计时实验。
- **产品状态：unknown。** 抽样产品调用点未确认把攻击者可控输入送入该比较函数；没有产品级 DoS 复现。
- **来源：** [GitHub Advisory GHSA-ff2v-f99f-wm3f](https://github.com/advisories/GHSA-ff2v-f99f-wm3f)；[Red Hat CVE-2026-67216 说明](https://access.redhat.com/security/cve/cve-2026-67216)。

#### CVE-2026-67215 — cJSON JSON Patch 递归导致资源耗尽

- **公开披露：confirmed。** Red Hat 记录了对不可信 JSON Patch 输入的无界递归/栈资源耗尽问题。
- **本地组件：candidate / code-path match。** 本地 cJSON 1.7.19 源码包含 cJSON_Utils JSON Patch 实现；构建配置中 cJSON_Utils.c 仅在 ohos_lite 路径编译，标准配置主要编译 cJSON.c。
- **产品状态：unknown。** 尚未证明标准产品镜像编入该 Utils 文件，也未找到攻击者可控调用点；本项不作为已确认的 OpenHarmony 产品漏洞。
- **来源：** [Red Hat CVE-2026-67215 说明](https://access.redhat.com/security/cve/cve-2026-67215)。

### B. OpenHarmony 或上游公告确认，但当前本地产品状态未确认

#### CVE-2026-27648 — web_webview 越界写

- **公开披露：confirmed。** OpenHarmony 2026 年 4 月公告列为 CVSS 8.8，影响 5.0.3、5.1.0、6.0 发布线；漏洞涉及 NWebHandlerDelegate::FlowbufStrAtIndex 未校验 ashmem flowbuffer 范围及 curIndex 容器索引。修复分别见 chromium_src PR #7093、#7110、#7108。
- **本地状态：unknown。** campaign-100-20261017 当前目录没有 web_webview 仓库，因此不能从本地快照确认受影响代码或修复状态；没有运行 PoC。
- **来源：** [OpenHarmony 2026 年 4 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-04.md)；[6.0 修复 PR #7093](https://gitcode.com/openharmony-tpc/chromium_src/pull/7093)。

#### CVE-2025-25212 — 剪贴板观察者无限注册导致本地 DoS

- **公开披露：confirmed。** OpenHarmony/NVD 记录影响 v5.0.3 及以前版本；官方 PR #1539 将观察者按 (userId, PID) 管理、限制每进程数量并在应用退出时清理。官方 CNA 与 NVD 的 CVSS 分别为 3.3 和 5.5，存在评分差异。
- **本地历史快照：confirmed。** miscservices_pasteboard 仓库 master，HEAD dd22c7cb5e5f，工作树干净，组件版本 3.1（提交日期 2022-07-22）。services/core/src/pasteboard_service.cpp:221 将观察者直接放入集合而无数量上限，:290 遍历并通知。该本地旧快照支持“历史源码存在无限累积路径”。
- **当前产品：unknown。** 该快照不是 v5.0.3 的精确构建；调用权限、具体产品服务注册和运行时资源影响未在设备验证。
- **来源：** [NVD CVE-2025-25212](https://nvd.nist.gov/vuln/detail/CVE-2025-25212)；[官方修复 PR #1539](https://gitcode.com/openharmony/distributeddatamgr_pasteboard/merge_requests/1539)；[OpenHarmony 安全公告归档](https://gitcode.com/openharmony/security/tree/master/zh/security-disclosure)。

#### CVE-2022-45877 — 跨设备认证 PIN 明文传输

- **公开披露：confirmed。** OpenHarmony 2022 年 12 月公告记录 3.1 至 3.1.4 发布线存在跨设备认证 PIN 明文传输问题；公告 CVSS 8.3，NVD 评分 5.3。修复 PR #915 从认证令牌移除 PIN，改由设备本地 UI 处理。
- **本地状态：unknown。** campaign 镜像缺少 distributedhardware_device_manager 和 applications_hap。只有旧 security_deviceauth，其中 PIN 进入 PAKE 参数；这不足以证明 PIN 以明文上网。
- **来源：** [OpenHarmony 2022 年 12 月公告](https://gitcode.com/openharmony/security/blob/master/en/security-disclosure/2022/2022-12.md)；[NVD CVE-2022-45877](https://nvd.nist.gov/vuln/detail/CVE-2022-45877)；[设备管理器修复 PR #915](https://gitcode.com/openharmony/distributedhardware_device_manager/merge_requests/915)。

#### CVE-2026-58313 — bundlemanager_app_domain_verify UAF

- **公开披露：confirmed。** OpenHarmony 2026 年 8 月公告列出 v6.1 发布线 UAF，本地攻击者可导致任意代码执行，CVSS 7.8。
- **本地状态：unknown / 有保护迹象。** bundlemanager_app_domain_verify master，HEAD 80513aacffbb，工作树干净；frameworks/common/include/utils/lru_cache_util.h 中 LRU 访问带互斥保护。但公告未在摘要中给出足以将该 CVE 精确映射到此处 LRU 代码的根因，所以不能仅凭这把锁宣布根因已修复，也不能说当前 master 仍受影响。
- **来源：** [OpenHarmony 2026 年 8 月公告邮件](https://lists.openatom.io/hyperkitty/list/security%40openharmony.io/thread/IJ5WNUSUCN7CDCFQLO4FWYGJONVN2WYL/)；[官方 2026 年 8 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-08.md)；[相关仓库 PR #229](https://gitcode.com/openharmony/bundlemanager_app_domain_verify/pull/229)。

#### CVE-2026-28733 — filemanagement_storage_service UAF

- **公开披露：confirmed。** OpenHarmony 2026 年 5 月公告记录 v5.1.0 发布线 UAF，公告影响为本地任意代码执行，CVSS 6.5。
- **当前本地：看起来已有并发保护，但未做发布版本验证。** filemanagement_storage_service master，HEAD cf373c3bf087，工作树干净；services/storage_daemon/ipc/src/storage_daemon_provider.cpp:362 起访问统计表时取 mutexStats_，:415-417 在同一锁下复制并清空表；修复参考 PR #2114。当前 master 未复现公告中的同一缺陷，未对 v5.1 发布分支做二进制或动态核验。
- **来源：** [OpenHarmony 2026 年 5 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-05.md)；[修复 PR #2114](https://gitcode.com/openharmony/filemanagement_storage_service/pull/2114)。

#### CVE-2026-25850 — 外置卷挂载权限设置可能导致信息泄露

- **公开披露：confirmed。** OpenHarmony 2026 年 5 月公告记录外置卷处理权限问题，涉及 5.1/6.0 发布线。
- **当前本地：似乎已修复，发布线映射未闭环。** 当前 filemanagement_storage_service master 未找到生产路径调用递归 TravelChmod；现有 ext4 路径未见对整棵目录递归 chmod 0777，HMFS 路径设置挂载根目录权限为 0775。修复参考 #2666、#2674。没有对具体产品镜像和文件系统组合动态验证。
- **来源：** [OpenHarmony 2026 年 5 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-05.md)；[PR #2666 补丁](https://gitcode.com/openharmony/filemanagement_storage_service/pull/2666.patch)；[PR #2674 补丁](https://gitcode.com/openharmony/filemanagement_storage_service/pull/2674.patch)。

#### CVE-2026-28751 — filemanagement_storage_service 输入校验不足导致 DoS

- **公开披露：confirmed。** OpenHarmony 2026 年 4 月公告列出 5.0.3、5.1、6.0 发布线，CVSS 3.3。
- **本地状态：unknown。** 仓库存在，但本轮材料没有把公告根因映射到具体源码或修复提交；不据公告推断本地 master 有漏洞。
- **来源：** [OpenHarmony 2026 年 4 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-04.md)。

#### CVE-2025-27247 — 剪贴板权限绕过/敏感信息泄露

- **公开披露：confirmed。** OpenHarmony 2025 年 6 月公告列 v5.0.3，CVSS 5.5。
- **本地历史路径：confirmed / 当前状态 unknown。** 旧 miscservices_pasteboard 快照的 GET_PASTE_DATA 服务路径未见服务端读取权限检查；该仓库是 2022 年组件快照，不是 v5.0.3 对应代码。后续 API 12 / OpenHarmony 5.0.0.18 加入读取授权，所以不能将旧路径写成当前 5.0.3 或当前 master 的漏洞。
- **来源：** [OpenHarmony 2025 年 6 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md)；[NVD CVE-2025-27247](https://nvd.nist.gov/vuln/detail/CVE-2025-27247)；[OpenHarmony 5.0.0 发布说明](https://github.com/openharmony/docs/blob/master/en/release-notes/OpenHarmony-v5.0.0-release.md)。

#### CVE-2025-57052 — cJSON JSON Pointer 数组索引校验

- **公开披露：confirmed。** OpenHarmony 2026 年 6 月公告将其列为 third_party_cJSON 漏洞，CVSS 9.8，影响 5.0.3 和 5.1.0 发布线。
- **当前本地：已有修复迹象。** 独立根目录 third_party_cJSON 当前为 1.7.19；current cJSON_Utils.c 的 JSON Pointer 数组索引使用位置游标，而旧受影响实现使用错误的 pointer[0]。当前本地代码不匹配旧缺陷；未审计具体 5.0.3/5.1 发布镜像。
- **来源：** [OpenHarmony 2026 年 6 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-06.md)；[上游修复提交](https://github.com/DaveGamble/cJSON/commit/74e1ff4994aa4139126967f6d289b675b4b36fef)。

#### CVE-2026-33636 — libpng ARM Neon 调色板边界访问

- **公开披露：confirmed。** OpenHarmony 2026 年 5 月公告列第三方 libpng 漏洞；上游 GHSA 描述 ARM Neon 调色板路径越界。
- **当前主 libpng：有补丁。** third_party_libpng/install.py 补丁清单包含 CVE-2026-33636.patch。
- **产品状态：unknown。** graphic_standard 中另有 Flutter 依赖线索，但 third_party_flutter 仓库不在当前 campaign 镜像，无法确认产品最终 pin 的 Flutter/libpng 版本及该补丁是否覆盖该产物。
- **来源：** [OpenHarmony 2026 年 5 月公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026/2026-05.md)；[libpng 上游 GHSA-wjr5-c57x-95m2](https://github.com/pnggroup/libpng/security/advisories/GHSA-wjr5-c57x-95m2)。

### C. 已核对但当前快照不应计作漏洞

#### CVE-2026-92392 — curl HTTP/2 上传 UAF：本地版本不在受影响范围

- **公开披露：confirmed。** curl 官方公告列受影响 8.12.0–8.22.0；低于 8.12.0 不受影响。公告虽讨论满足多项约束时可能转成 RCE，但不能把该影响套到不在受影响版本范围的本地代码。
- **当前本地：not affected by version。** third_party_curl 为 8.8.0，低于引入版本 8.12.0。
- **来源：** [curl 官方 CVE-2026-92392 公告](https://curl.se/docs/CVE-2026-92392.html)。

#### CVE-2026-9079 — curl 代理密码残留

- **公开披露：confirmed。** curl 官方 CVE 表列出该问题及受影响版本范围含 8.8.0。
- **当前本地：未列为已确认漏洞。** 会话复核指出 setopt.c 附近存在代理凭据清理逻辑；目前只有这一处局部对应关系，没有单独完成公告根因到补丁 hunk 的审计。因此状态记为 unknown/疑似已修复，不能仅凭版本号报漏洞，也不把“已修复”写成 confirmed。
- **来源：** [curl 官方 CVE 列表](https://curl.se/docs/CVE-2026-9079.html)。

## 二、人工发现的重大候选

以下均为 candidate，不是已确认漏洞。这里的“自己发现”表示线索由本轮源码审查发现，不代表已经完成漏洞报告或产品验证。

### UpdateApp 仓库中的公开开发签名材料

- **已确认事实：** update_update_app 仓库跟踪 signature/OpenHarmony.p12、.cer、.csr 等材料。仓库 master，HEAD a4fd66e7da16，工作树干净。build-profile.json5 的 release 配置引用这些文件。
- **密钥核验边界：** 先前用 OpenHarmony 签名工具公开文档中的示例口令验证过容器可打开；仅记录容器含证书及私钥条目，不输出口令或私钥。仓库 .cer 指纹与 P12 中同名证书不匹配，仓库构建配置中的口令也不能打开该容器。官方资料说明 SDK 可提供开发签名材料，并建议商用产品替换。
- **结论：candidate / impact unknown。** 尚无证据证明量产镜像信任该开发根证书、存在用该密钥签出的恶意 HAP，或设备会接受替换包。不能据此宣称提权或系统代码执行。
- **位置与来源：** G:\OpenHarmony-GitCode-Mirror\campaign-100-20261017\repos\update_update_app\signature\OpenHarmony.p12；build-profile.json5:6、19-29；[官方签名校验说明](https://github.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-sigverify.md)；[hapsigntool 使用指南](https://gitee.com/openharmony/docs/blob/master/en/application-dev/security/hapsigntool-guidelines.md)。

### app_domain_verify 共享优先级字段竞争

- **状态：candidate；安全影响 unknown。** app_domain_verify_task_mgr.h:46 配置 4 个 worker；verify_task.cpp:39-53、136-138 为同一个 VerifyTask 调度多个 URI 回调并读取 appVerifyBaseInfo_.priority；domain_verifier.cpp:22-35、61-83、93-105 可能写该共享字段；verify_http_task.cpp:47-62 将回调交回同一个 VerifyTask。
- **风险边界：** 静态证据支持并发读写候选；没有 TSan、设备测试或利用验证，也未证明可绕过域名校验或提升权限。当前仓库 master HEAD 80513aacffbb，工作树干净。
- **位置：** G:\OpenHarmony-GitCode-Mirror\campaign-100-20261017\repos\bundlemanager_app_domain_verify\frameworks\verifier\src\verify_task.cpp 等。

### storage_service 统计表读取竞争

- **状态：candidate；影响 unknown。** storage_daemon_provider.cpp 中 opStatistics_ 在多个位置访问；部分访问由 mutexStats_ 保护，但 StorageRadarThd 对 opStatistics_.empty() 的检查曾发现未持同一把锁。需要先确认所有调用上下文和对象生命周期，再以 TSan 或受控并发验证。
- **当前证据边界：** 尚无 TSan 结果、产品影响或利用路径；不作为已确认的 CVE-2026-28733 根因。公开 CVE 与此候选是两件事。
- **位置：** G:\OpenHarmony-GitCode-Mirror\campaign-100-20261017\repos\filemanagement_storage_service\services\storage_daemon\ipc\src\storage_daemon_provider.cpp，特别是 :181-187、:362、:415-417、:453 及统计线程相关代码。

### security_asset 跨账号参数触发前置副作用

- **状态：candidate / impact unknown。** stub.rs:182-188 从请求映射构造 CallingInfo，携带可选 UserId，并在进入具体应用操作权限校验前调用 upgrade_single_clone_app_data；permission_check.rs 对显式 UserId 要求系统 HAP 与跨本地账号权限。
- **风险边界：** 目前只确认存在权限检查前的前置状态操作线索；没有证明普通应用可越权读取/写入跨账号数据。后续应验证调用身份、克隆数据升级的副作用和失败回滚行为。
- **位置：** security_asset 的 services stub、calling_info.rs:55-79、db_operator/src/common/permission_check.rs:31。

## 三、作为误报或未成立线索记录

- security_asset 群组删除线索：请求仍经过 Bundle Manager 成员资格校验；没有确认未授权删除。
- request_request 的 O_NOFOLLOW/路径线索：FD 后续会按 canonical app base 校验；没有演示目录逃逸。
- request_request 的 FD 双重关闭线索：MsgParcel write_file 会复制文件描述符；未确认双重关闭。
- security_deviceauth 的负长度 IPC 线索：相关 IPC stub 仅允许 native SYSTEM_CORE 调用；没有低权限攻击路径证据。
- 旧剪贴板“任意应用可读”线索：旧代码快照中确有服务端无读取授权路径，但 API 12 / 5.0.0.18 后续增加读取授权。按历史缺陷记录，不能当当前 0day。

## 四、仓库、范围和未修改内容

- campaign-100-20261017\repos 当前目录计数为 98；另有独立根目录 G:\OpenHarmony-GitCode-Mirror\repos\third_party_cJSON。会话副本当时记录“100 个样本仓库”，与本轮实际目录计数不同，因此本报告采用当前可复核的 98，不宣称完成全仓审计。
- 本轮重新读取了相关干净仓库的分支、HEAD 和状态；定向核验的源码仓库为 master、工作树 clean。独立 cJSON 位于 alternate root，也为 master、HEAD 0c2c9dff82cc、clean。
- device_soc_hisilicon、kernel_linux_6.6、xts_tools 仍有负责人既存 dirty worktree（本轮状态分别约 16,632、82,027、32,167 个状态条目）；只读取状态，没有读写、覆盖、清理这些目录。
- 没有修改任何源码仓库，没有使用扫描器，没有对设备或运行服务做攻击实验，没有推送、合并或创建 PR。唯一写入是本报告。
- 两项隔离组件 ASan 复现（libpng、libtiff）写入 WSL /tmp，不改源仓库；它们只能确认组件 Harness 现象，不能作为产品漏洞确认。
- 后续优先补证顺序：先确认 CVE-2026-27648 对应发行源码或构建；再确认 cJSON_Compare 与 JSON Patch 的实际产品调用方；最后对 app_domain_verify 和 storage_service 候选做有边界的并发验证，并从入口、权限到实际影响闭环。

## 五、OHScanner C线真实源码复放补记（2026-10-19）

本节补入 C 线 Ark Runtime 静态扫描结果，和前文人工审查结论分开。扫描使用固定的本地官方 Ark Runtime Git 对象、生产 `ohscan-run`、`light-ast` 单文件 scope；扫描不触发 fetch。候选只表示该源码/路径满足规则，不等于组件运行时漏洞或产品漏洞。完整身份、可重放命令和限制见本仓库 `research/deliveries/c-line/ark-runtime-coverage-ledger-20261019.json` 及 C8 报告目录。

| 案例 | 公告/源码根因事实 | 生产入口静态结果 | 组件动态复现 | 产品漏洞确认 |
| --- | --- | --- | --- | --- |
| CVE-2025-24304 / TypedArray Map | OpenHarmony 公告确认 Ark Runtime 越界写并列出受影响发布线；!11130 的源码/测试修复是新建结果数组的类型令牌来源。CVE 与该具体提交的直接一对一映射未证实，属于强推断。 | 官方 5.0.2 pin 到 release fix：Map 根因候选 1→0；固定侧仍有 Filter、With、ToReversed 三个未决同类候选，整文件 partial/blocked，家族固定版验收未通过。 | 未构建/未运行。 | 未确认产品构建、攻击路径或影响。 |
| IBS5YG / TypedArray Filter 结果类型来源 | 上游 issue/PR 与父/修复 diff 指向 Filter 将源对象类型令牌用于 species-sensitive 新结果的 indexed store；未核实 CVE/安全公告。 | 精确直接父/修复：TypeOrigin 候选 1→0；CLI 分析 partial/blocked。产品快照与 master 的 0 告警伴随 unresolved/partial，不能作为安全结论。 | 上游回归未构建/未运行。 | 未确认。 |
| I7KZJ7 / TypedArray 缓冲区长度乘法 | 上游源码/测试显示 32 位元素宽度乘元素数后用于分配、而复制仍按元素数循环；无已核实 CVE/安全公告，安全影响未动态确认。 | 初始无适用规则；新乘法规则接入后，精确父/修复呈 root-specific 1→0。两侧 full-file 分析仍 partial/blocked。 | 未运行；相关大内存回归未构建。 | 未确认。 |
| IC7B8Q / TypedArray Map 分配异常 | 上游父/修复和回归源码显示 NewTypedArray 可能留 pending exception，Map 在检查异常前读取结果 HClass；无 CVE/安全公告关联。 | 生产 CLI 父版本 2 个异常路径候选→修复版 0；两次均因整 TU partial 而 blocked。 | 未构建/未运行递归栈耗尽回归。 | 未确认。 |
| IAO7GO / Reflect.apply 异常传播 | 官方上游 issue 与源码测试支持异常传播根因；未核实安全分类或 CVE。 | 生产入口父/修复均 0，但原因是 `native_inline_lowering.cpp` 不满足当前 Ark Runtime 语义 selector（0 applicable files），属于未分析/漏覆盖，不能计作修复命中或安全。 | 未运行。 | 未确认。 |
| I7W51D / TypedArray 长度窄化 | 上游修复将长度转换由有符号 32 位改为无符号 32 位，回归预期 RangeError；现有证据未建立内存破坏或安全影响。 | 乘法规则父/修复 0→0，detector blocked/partial；此机制没有对应窄化规则，不记为安全通过。 | 未运行。 | 不据此确认漏洞。 |
| IB8BCA / DataView 索引宽度与边界 | 上游源码/测试支持索引宽度调整；尚无具体越界见证或安全公告。 | 选定源码范围父/修复 0→0，detector blocked/partial，缺少适用的 DataView/Atomics 边界模型。 | 未运行。 | 未确认。 |
| IAO7E8 / TypedArray Filter 接收者类型校验顺序（PR !9063） | 固定父提交 `c4c52fb57b6e204128e1520340c8e66c8e708981` 在 `GetViewedArrayBuffer(thisValue)` 前只有空值检查，随后才验证 EcmaObject 与 Fast TypedArray；普通对象可设置 TypedArray 原型。修复 `2a70904be0e21a37a666eb00cab49d02068260ea` 将 buffer 读取移入同接收者 `IsFastTypeArray` 成功分支。无 CVE/安全公告关联已核实；PR 页面本轮浏览器不可访问，来源由本地官方上游 Git 对象、精确 diff 和新增回归源码核对。 | 新 receiver-type-guard 规则经生产 CLI：父版本 Filter 位置 1413 命中 1，修复版同根因 0；两份运行均 completed-with-limitations、detector blocked，故为静态候选响应，不是完整 TU 安全结论。 | 未构建/未运行上游 `typedarrayfilter` 回归。 | 未确认产品绑定、入口/权限、攻击者控制与实际影响。 |

本次新规则追踪 `GetObjectType(LoadHClass(receiver))` 到 `IsFastTypeArray` 的同对象类型来源，并用生成控制流图判断该成功分支是否支配 `GetViewedArrayBuffer(receiver)`。变量改名、正确分支和错误接收者单元控制通过；精确历史 Filter 父/修复 1→0。邻近 `LastIndexOf` 的 `IsTypedArray(thisValue)` 检查作为同机制安全变体控制，父与修复源码均为 matched。该验证不是独立盲留出集。无法由当前局部模型证明的路径保留 unknown。

### 分层状态

- **A 研究机制观察：** 已完成。接收者的运行时类型检查必须支配 TypedArray backing-buffer 访问；只检查 EcmaObject 不够。
- **B 精确真实源码静态复放：** 已完成到候选级。!9063 父/修复源码及 blob/hash 固定；结果 1→0。
- **C 生产入口集成：** 已通过 `ohscan-run` 触发新规则；完整文件仍 blocked/partial，生产准入与全范围保证未通过。
- **D 组件/运行时动态验证：** 未执行；没有可核对的精确构建产物和回归运行结果。
- **E 产品漏洞证据：** 未建立。没有产品构建关联、真实入口与权限链、攻击者控制或具体 CIA 影响证据。

未对无独立标注集的样本计算 Precision/Recall。其他尚未逐项具备精确生产复放报告的 C 线家族继续以 ledger 中记录为准；缺失结果仍为未分析，不作通过结论。
