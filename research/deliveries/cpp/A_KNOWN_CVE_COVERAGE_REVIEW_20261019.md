# A 线已披露 CVE 检测覆盖审查

- 审查日期：2026-10-19
- 审查基线：`origin/main` / `HEAD` = `db77164fdc2af0da02e4d3efc056d84694fd68e8`
- 审查对象：`src/ohscanner/detectors/known_cves.py`、`tests/detectors/test_known_disclosed_cves.py`、detector catalog，以及来源审查记录 `CyberSecurity-Innovation-Audit-c4/research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`
- 范围：来源记录列出的 17 个公开 CVE 编号；这是扫描器源码规则覆盖审查，不是产品漏洞确认，也不替代版本、构建、调用链或运行时验证。

## 执行摘要

`known_cves.py` 对下表 17 个编号均存在相应的源码模式或版本规则。CVE-2026-92392 与 CVE-2026-9079 位于来源记录的“当前快照不应计作漏洞”部分，故列出规则仅表示检测能力，不应因此把当前组件判定为受影响。

该 detector 的 `supported_languages` 是 C/C++，实际规则在 `known_cves.py` 内用词法/正则和局部函数体扫描实现（`known_cves.py:510–538`），不是 C++ AST 规则。`src/ohscanner/detectors/catalog.py:37–41` 将 `ohscanner.known_disclosed_cves` 设为 `default_enabled: False`；对应测试也明确检查它不在默认 detector 列表（`test_known_disclosed_cves.py:445–453`）。所以“规则存在”不等于常规 profile 默认扫描这些 CVE；需要显式启用该 detector 的 profile 才会执行。

每条 finding 由 `_finding` 统一标为组件源码 candidate，并携带组件身份、产品构建、攻击路径、影响等未满足义务（`known_cves.py:12–19`）。遵守来源记录的状态定义：组件候选、历史源码事实、unknown 均不等同于已确认的当前 OpenHarmony 产品漏洞。来源报告特别说明没有确认当前产品可由攻击者触发的重大漏洞或新 0day（来源记录 `:12–16,22–27`）。

## 17 项公开编号与规则映射

“覆盖”列描述当前规则能否对报告所述的某类源码形态产生候选，不证明扫描器已分析实际受影响产品、版本或调用路径。行号均指上述源码与测试文件。

| CVE / 报告所述机制 | 当前规则与回归证据 | 覆盖审查、版本/产品限制与建议补测 |
|---|---|---|
| **CVE-2026-46675** libpng `png_read_info` 后未读行即 `png_read_end`，及受影响版本 | 版本 1.6.0–1.6.58 检测 `known_cves.py:339–346`；调用序列检测 `:386–395`。测试分别覆盖 1.6.55/1.6.59 与危险/安全调用序列 `test_known_disclosed_cves.py:360–370`。 | **有模式覆盖，产品路径 unknown。** 版本匹配只是组件版本线索；序列规则是单函数词法判断。建议补官方修复前后调用样例、带间接行读取或分支的安全控制，并将版本候选与调用方候选分开。来源报告称 libpng 组件级复现成立，但没有确认产品调用点：来源 `:35–41`。 |
| **CVE-2025-9900** libtiff `TIFFReadRGBAImageOriented` 光栅偏移越界 | wrapper 中 `(rheight - img.height) * rwidth` 偏移规则 `known_cves.py:244–266`；测试覆盖危险/修复表达式和在另一函数内的 guard `test_known_disclosed_cves.py:272–287`。 | **有模式覆盖，守卫与根因路径仍弱。** 规则未在危险 wrapper 内证明同函数尺寸 guard 是否支配调用；测试的 guard 刻意放在另一个函数，不能验证这一情形。建议加真实 tif_getimage.c 修复前后样例、同函数 guard、报告指出的调色板路径控制。组件级 ASan 证据不等于产品入口/影响确认：来源 `:43–49`。 |
| **CVE-2026-92391** libcurl 深层 MIME 所有权释放递归导致栈耗尽 | `cleanup_part_content`、`mime_subparts_free`、`curl_mime_free`、setter 结构联合匹配 `known_cves.py:328–338`；合成跨函数正例和深度限制负例 `test_known_disclosed_cves.py:300–304`。 | **有覆盖，语义验证偏弱。** 几个函数体被拼接后通过名称/文本判断递归与所有权关系；建议用 curl 官方漏洞/修复版本源文件 fixture 验证真实调用关系、所有权开关和深度限制的不同写法。来源记录认为本地 8.8.0 落在公告影响范围，但产品能否形成数千层 MIME 仍 unknown：`:51–56`。 |
| **CVE-2026-67216** cJSON_Compare 递归对象比较与重复线性匹配 | 检查 `cJSON_Compare` 函数体中至少两处递归调用、`get_object_item` 和 `cJSON_ArrayForEach`，`known_cves.py:267–272`；递归和 parse-only 控制 `test_known_disclosed_cves.py:289–298`。 | **有模式覆盖，复杂度和产品触发仍属 candidate/unknown。** 词法结构不能证明指数级增长，也不能证明攻击者输入进入 `cJSON_Compare`。建议增加对照结构/规模的组件测试及真实上游实现 fixture；不要把普通解析入口作为触发证据。来源 `:58–63`。 |
| **CVE-2026-67215** cJSON JSON Patch 嵌套导致递归资源耗尽 | 检查 `apply_patch` 深拷贝/删除、`cJSONUtils_ApplyPatches` 调用和缺少明显深度限制，`known_cves.py:407–419`；合成正例/限深负例 `test_known_disclosed_cves.py:423–429`。 | **有候选模式，构建和调用方 unknown。** 来源称 `cJSON_Utils.c` 仅在 ohos_lite 路径编译，未证实标准产品编入或存在攻击者可控入口：`:65–70`。建议以真实受影响/修复源码补 fixture，并记录编译目标/产品构建的独立证据，避免仅因文件存在就称产品受影响。 |
| **CVE-2026-27648** web_webview Flowbuffer 越界读取/写入 | 检查 `FlowbufStrAtIndex` 范围与 `ProcessNativeProxyResultNewFlowbuf` 的目的容器索引，`known_cves.py:436–472`；危险、修复、部分修复、无关函数与 partial-parse 覆盖 `test_known_disclosed_cves.py:455–522`。 | **两类已描述机制均有模式覆盖，目标源码/产品 unknown。** 规则依赖函数名、`dataList` 及局部变量模式；建议补公告对应仓库修复前后源码，测试表项索引自身边界、加法溢出、变量重命名和等于边界。来源快照缺 web_webview 仓库且无 PoC：来源 `:74–78`。 |
| **CVE-2025-25212** 剪贴板观察者无限注册导致本地 DoS | `AddPasteboardChangedObserver` 集合插入且本函数未见 PID/token 或 quota 时告警，`known_cves.py:396–406`；合成漏洞/修复 fixture 与 27247 共测 `test_known_disclosed_cves.py:431–443`。 | **有候选覆盖，跨函数限额可能漏判。** helper、共享容器或服务外层的 caller quota 不在当前函数体模式内。来源支持旧历史快照无限累积路径，但不是 v5.0.3 精确构建，当前产品 unknown：`:80–85`。建议加限额封装 helper、进程清理生命周期、真实公告修复前后样例。 |
| **CVE-2022-45877** 跨设备认证 PIN 被序列化进响应 | 要求同一 `OnGroupCreated` 中 PIN 写入、token 序列化、响应构造、SoftBus 发送，`known_cves.py:473–507`；正例、移除 PIN 的修复形态、跨函数无关形态和 partial parse `test_known_disclosed_cves.py:241–270`。 | **有候选覆盖，不证明明文网络可见。** 规则不判断传输加密、对端可见性或具体发行构建。来源当前镜像缺设备管理器/应用仓库，旧 PAKE 参数本身不足以证明明文传输，产品状态 unknown：`:87–91`。建议补官方修复提交两侧源码及加密/本地处理负例。 |
| **CVE-2026-58313** bundlemanager_app_domain_verify UAF | 匹配 LRU list/iterator-map 及 Get/Put/Clear 无共同锁，`known_cves.py:169–217`；哈希固定的 vulnerable/fixed fixture、partial parse、路径控制 `test_known_disclosed_cves.py:30–56`。 | **模式有 fixture，但 CVE 根因归因未闭环（重点问题一）。** 来源明确说公告摘要不足以把 CVE 精确映射到 `lru_cache_util.h`，不能因当前 master 有锁就宣布该 CVE 修复，也不能断言当前仍受影响：来源 `:93–97`。现规则却直接报告 `CVE-2026-58313`，测试名也称 `real_lru_fix_pair`。最小动作：取得公告根因与 PR #229 的具体 hunk/调用对象映射前，将该命中作为通用 LRU iterator/UAF candidate，不使用精确 CVE 归因；补证后再建公告对应的版本固定 fixture。 |
| **CVE-2026-28733** filemanagement_storage_service UAF | 检查 `StorageDaemonStub::GetUserStatistics` 返回共享 map iterator、调用方解引用及 `GetTempStatistics` 清表，`known_cves.py:95–132`；测试明确“iterator_escape_survives_mutex_patch” `test_known_disclosed_cves.py:92–142`。 | **有相邻并发 UAF 候选，披露根因映射未闭环（重点问题二）。** 来源记录讨论的是 `storage_daemon_provider.cpp`：同一 `mutexStats_` 下复制并清空统计表，并称当前 master 看似已有保护；它没有证实规则所查 `StorageDaemonStub` 的 iterator escape 就是 CVE-2026-28733 根因：来源 `:99–103`。测试能说明“锁内取 iterator、锁外使用”这一通用风险，不证明它对应公告。最小动作：拆出通用 iterator-lifetime 候选，暂停该规则的精确 CVE 标签；对公告发布分支、PR #2114 和 provider/stub 实际源码逐 hunk 映射后，再补受影响/修复真实源码对照。 |
| **CVE-2026-25850** 外置卷递归 chmod 扩大权限 | 限定 `external_volume_info.cpp` 两挂载方法并检查 `0777` + `TravelChmod`，`known_cves.py:75–93`；两方法、修复、无关路径测试 `test_known_disclosed_cves.py:57–90`。 | **旧形态有覆盖；当前产品版本线映射未完成。** 来源称当前 master 未找到递归 `TravelChmod` 生产路径，HMFS 根权限为 0775，发布线/文件系统组合未验证：来源 `:105–109`。建议补 PR #2666/#2674 的真实 patch fixture，覆盖根目录权限设置、非递归 chmod、不同文件系统分支；扫描旧版本命中保持 candidate。 |
| **CVE-2026-28751** storage_service 输入校验不足 DoS | 规则将 `NotifyMtpMounted` 的容量分配、full-length `getxattr`、严格 `<` 导致无 NUL 后 `std::string(value)` 关联到 CVE，`known_cves.py:134–167`；同一合成形态及“多 1 字节 + <=”控制 `test_known_disclosed_cves.py:144–178`。 | **归因证据缺失（重点问题三）。** 来源明确记载“未把公告根因映射到具体源码或修复提交”，且本地状态 unknown：来源 `:111–115`。当前检测器和测试反而把一个具体 MTP xattr 越界读场景标为该 CVE，但没有报告内证据证明二者相同。最小动作：先将其降为未归因的本地候选或暂不冠 CVE；审阅 4 月公告及真实仓库/修复提交，确认根因后再用修复前后 blob、边界长度与终止符回归建立映射。 |
| **CVE-2025-27247** 剪贴板读取权限绕过/信息泄露 | 检查 Binder 映射、分发、`GetPasteData` 和 `WriteParcelable`，且 dispatch/handler 未见本地权限检查，`known_cves.py:420–435`；与观察者 CVE 合成共测 `test_known_disclosed_cves.py:431–443`。 | **历史模式候选覆盖；当前状态 unknown。** 权限可能由文件外/服务外层执行，当前 regex 无跨层证明。来源只确认 2022 旧快照路径，指出后续 API 12 / 5.0.0.18 增加读取授权，不能外推成当前漏洞：来源 `:117–121`。建议增加外层授权及官方旧版/修复版源码 fixture。 |
| **CVE-2025-57052** cJSON JSON Pointer 数组索引游标错误 | 检查 `decode_array_index_from_pointer` 循环条件使用 `pointer[0]` 并累积 `pointer[position]`，`known_cves.py:273–297`；漏洞、修复和无关形态测试 `test_known_disclosed_cves.py:306–324`。 | **旧缺陷形态覆盖；当前组件有修复迹象。** 来源称本地 cJSON 1.7.19 使用位置游标，未审计精确发布镜像：来源 `:123–127`。建议把精确上游修复提交作为固定 fixture，补数字前缀、非数字字符、尾部 `/` 边界样例；不要将旧版受影响公告直接当作当前 master 漏洞。 |
| **CVE-2026-33636** libpng ARM NEON 调色板边界访问 | 对两个 NEON 扩展函数检查向量 tail 和目的指针恢复，`known_cves.py:347–385`；回归 fixture 锁定 vulnerable/fixed blob SHA-1 与 SHA-256、双 finding、不完整修复、无关控制，`test_known_disclosed_cves.py:372–421`。 | **当前规则中源码回归依据较强。** 来源称主 libpng 补丁清单含该修复，但 Flutter 依赖 pin 和最终产品产物 unknown：来源 `:129–134`。建议继续补构建配置/Flutter 最终依赖证据；扫描器命中只表示源码候选，不证明目标产品包含该 NEON 实现。 |
| **CVE-2026-92392** curl HTTP/2 上传 UAF（来源明确排除当前快照） | 规则检查 `multi_done` 清理顺序并结合 curl 版本范围/回补版本，`known_cves.py:29–72,219–243`；测试涵盖 8.8.0、affected range、fixed backports、未知/冲突版本，`test_known_disclosed_cves.py:180–239`。 | **版本边界覆盖较完整；当前快照不应告警。** 来源明确本地 curl 为 8.8.0，低于 8.12.0 引入版本：来源 `:138–142`。未知或冲突版本时 finding 只能表达 applicability unknown；建议真实版本宏与回补注释冲突时仍保持 unknown，不用代码形态直接升级状态。 |
| **CVE-2026-9079** curl 代理凭据残留（来源标为 unknown/疑似已修复） | 检查 `CURLOPT_PROXYUSERPWD` 中旧凭据只在新解析组件非空时才释放，`known_cves.py:298–327`；合成漏洞/修复形态测试 `test_known_disclosed_cves.py:326–358`。 | **有模式规则，但公告根因与本地代码 hunk 尚未核对。** 来源仅记录 setopt.c 附近存在清理逻辑，未独立完成根因/补丁审计，状态 unknown/疑似已修复：来源 `:144–148`。建议在映射官方 CVE 修复提交前将告警限定为通用凭据清理 candidate；补真实 setopt.c 两侧源码及 NULL 清除已有 user/password 两字段控制。 |

## 优先回归与证据闭环

1. **先修正 CVE 归因层**：对 58313、28733、28751 分别补公告根因→仓库→真实源码/修复提交的证据链；证据未满足前，使用一般 LRU iterator、共享 map iterator 或 xattr 字符串终止候选语义，不把 candidate 冒充已确认 CVE 根因。
2. **对合成 fixture 建真实代码锚点**：优先 92391、67216、67215、25212、27247、27648、45877、9900、25850、9079。每条用公告对应的受影响源码和修复源码建立固定 blob/hash 回归，同时保留 safe/fixed/unrelated/部分修复控制。
3. **覆盖词法规则的主要失效面**：加入 guard 位于同一函数/被 helper 封装、标识符改名、分支支配、整数边界、深度上限的等价写法、跨函数调用和解析 partial 的控制。没有分析到或 parse incomplete 的部分必须保持 unknown/blocked，不能作为未命中或安全证明。
4. **在显式 profile 启用前设验收门**：catalog 默认关闭是当前事实；若要实现披露 CVE 扫描覆盖，应通过指定 profile 显式启用并核验扫描输出中 detector 版本、scope、解析状态、finding obligations。默认关闭不得被解读为规则无效，也不得把手动选择 detector 的 fixture 结果当作生产扫描已覆盖。

## 来源定位

- 审计来源报告：`CyberSecurity-Innovation-Audit-c4/research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`。公开漏洞及其组件/产品状态见 `:29–148`；unknown/candidate 定义及产品确认门槛见 `:22–27`；CVE 归因审慎原则见 `:12–16`。
- Detector 入口、候选语义、限额和 partial parse 行为：`src/ohscanner/detectors/known_cves.py:12–19,510–538`。
- catalog 默认关闭：`src/ohscanner/detectors/catalog.py:37–41,96`。
- 默认关闭回归：`tests/detectors/test_known_disclosed_cves.py:445–453`。
- 各 CVE 对应规则与 fixture 行号见上表。

