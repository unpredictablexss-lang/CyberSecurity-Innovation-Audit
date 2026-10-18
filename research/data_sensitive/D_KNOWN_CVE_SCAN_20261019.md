# 已披露漏洞候选扫描（2026-10-19）

## 结论与范围

针对 `OHScanner_G盘源码漏洞审查记录_20261018.md`，`ohscanner.known_disclosed_cves` 从 0.1.0 升至 0.2.0，支持 6 项有具体本地源码线索的公开 CVE 形态：CVE-2025-9900、CVE-2025-25212、CVE-2025-27247、CVE-2026-46675、CVE-2026-67216、CVE-2026-92391。每个命中都是 `candidate`，仍绑定源 SHA、规则版本、CWE，并保留组件构建、产品入口、攻击者控制和影响等证据义务；`validated_vulnerability` 不升级。

17 项公开 CVE 审查清单中，本轮固定源码回放命中 6 项候选，另 11 项没有声称检出：有的缺少对应源码，有的缺精确根因映射，有的当前快照有修复线索或版本不在受影响范围。不是“17 项都扫描通过”，也不是 Recall 结果。

## 固定源码回放

复现脚本 `d20_disclosed_cve_replay.py` 只读取 G 盘仓库的固定 Git 对象，两次重复运行并比较 tree、snapshot、候选身份和覆盖状态。输入仓库工作树中的未提交内容不会进入实验。原始逐项 JSON 在 `D20_KNOWN_CVE_REPLAY.json`。

| 仓库/固定版本 | 命中 | 状态与边界 |
|---|---|---|
| third_party_libpng `e57b1079564a`，构建输入 `libpng-1.6.55.tar.gz` | CVE-2026-46675，`png.h:277` | 从 Git 跟踪的源码归档中读取 `png.h` 并调用第一方检测器；两次候选一致。Tree-sitter 部分解析，run blocked。仓库 Runner 尚不展开源码归档，因此这是归档成员的固定哈希回放，不宣称普通仓库 Runner 已覆盖嵌套包。 |
| third_party_libtiff `d4a0516c477dfbaf1153ae295893ab75aadd63d4` | CVE-2025-9900，`libtiff/tif_getimage.c:621` | Runner 绑定 Git tree/blob/snapshot；候选重复一致，解析 partial，run blocked。 |
| third_party_curl `1386bb128bb060b284309397b97adcaaec21c003` | CVE-2026-92391，`lib/mime.c:1146` | Runner 绑定 Git tree/blob/snapshot；候选重复一致，run completed。 |
| third_party_cJSON `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748` | CVE-2026-67216，`cJSON.c:3067` | Runner 绑定 Git tree/blob/snapshot；候选重复一致，解析 partial，run blocked。 |
| miscservices_pasteboard `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | CVE-2025-25212，`pasteboard_service.cpp:222`；CVE-2025-27247，`pasteboard_service_stub.cpp:41` | Runner 绑定固定 Git tree/blob/snapshot；候选重复一致，run blocked。它是 2022 旧快照，不是 v5.0.3 产品构建证明。 |

libpng 归档成员同时记录了上游归档 Git blob、归档 SHA-256、`png.h` SHA-256；该条采用研究脚本直接调用检测器，不冒称公共 Runner 接受归档输入。每条候选仍不是产品漏洞确认。公开披露事实与受影响版本以审查记录引用的公告/上游安全页为准。

## 规则与回归

- CVE-2025-9900：先对栅格目标指针按图像尺寸偏移的危险形态；正例、已校验尺寸/非偏移修复形态对照。
- CVE-2025-25212：Pasteboard observer 集合写入但函数内未见按进程身份配额；生命周期、外部限流和真实调用者仍需复核。
- CVE-2025-27247：在同一源码文件中连接 Binder `GET_PASTE_DATA` dispatch、handler 和数据返回；只在路径内没有可见权限检查时保留候选，不能排除文件/系统服务外部授权。
- CVE-2026-46675：libpng 1.6.0–1.6.58 版本标记或 `png_read_info` 后未读图像行就调用 `png_read_end`；版本 1.6.59 和安全读取顺序为负例。
- CVE-2026-67216：`cJSON_Compare` 对对象递归比较并重复线性 key lookup；普通解析、非递归比较为负例。
- CVE-2026-92391：拥有子 MIME 的释放回调重入 `curl_mime_free`，且相关路径无可见深度上限；有限深度控制为负例。

`tests.detectors.test_known_disclosed_cves` 当前 9 项测试通过，包含 vulnerable/fixed、安全、无关、partial 候选保留及上述剪贴板两项控制。扩展后全量 Python 回归 909 项通过、5 skipped、0 failed；`compileall`、D20 JSON 解析、`git diff --check` 通过。全部 5 个固定源样本复跑一致。Web 源码未改，本轮未重跑前端构建。用于构造规则的已披露样本是调参/回归集，不能作为独立 holdout。

## 未覆盖项及不可推断事项

审查记录余下 11 项未被本轮检测器覆盖：CVE-2026-67215 尚需把 JSON Patch 递归根因和构建条件映射为独立规则；CVE-2026-27648 本地镜像缺 web_webview 源码；CVE-2022-45877 当前旧代码不足以证明 PIN 明文传输；CVE-2026-58313、CVE-2026-28733、CVE-2026-25850、CVE-2026-28751 缺少当前快照到公告根因/受影响产品版本的可靠闭环（其中部分 master 有修复迹象）；CVE-2025-57052 当前 cJSON 有修复迹象；CVE-2026-33636 当前 libpng 补丁清单包含修复；CVE-2026-92392 当前 curl 8.8.0 低于其受影响版本；CVE-2026-9079 的公告根因仍未映射。未扫描、不命中和有修复线索都不自动代表安全。

没有 OpenHarmony 产品产物/构建来源、产品级入口、权限与攻击者控制、影响证据及必要的受控动态验证，因此当前所有结果仍为候选，产品 `confirmed/reportable=0`。静态命中和组件级 Harness 不证明产品漏洞。下一步应先补可用的真实修复提交正反样例，再以冻结且独立标注的真实样本测召回；同时实现 build-archive 解包/子源绑定，才能把嵌套 libpng 上游包纳入常规仓库扫描。
