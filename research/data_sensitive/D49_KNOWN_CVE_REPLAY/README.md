# D49 已披露组件漏洞规则回放

时间：2026-10-19
OHScanner 代码：`ffaa4e28846f5dd4c5f8be26931b61fb5326792c`
Detector：`ohscanner.known_disclosed_cves@0.16.0`，显式注册、默认关闭
方法：从 G 盘只读镜像固定完整 Git commit，通过 OHScanner 的 Git 对象读取、归档源码索引、C/C++ 前端、Detector Runner 与覆盖报告路径执行；无网络 fetch、无源码 checkout/修改。原始机器报告保留任务状态、树、源码清单、归档绑定、解析覆盖、候选和 obligation。

| 组件 | 固定提交 | 文件数；完整 / partial 解析 | detector / task 状态 | 候选 |
|---|---|---:|---|---|
| third_party_libpng | `e57b1079564a02a50321ec528aa6e41884979d32`，tree `02b17492f4490ff2e4d17ba74e2080358a500059` | 99；38 / 61 | blocked / completed_with_limitations | CVE-2026-33636 ×2；CVE-2026-46675 ×1 |
| third_party_libtiff | `d4a0516c477dfbaf1153ae295893ab75aadd63d4`，tree `33beab3b3b50fe6678b1a74ed48ac3b69084c6ec` | 144；86 / 58 | blocked / completed_with_limitations | CVE-2025-9900 ×1 |
| third_party_cJSON | `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`，tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856` | 99；61 / 38 | blocked / completed_with_limitations | CVE-2026-67216 ×1；CVE-2026-67215 ×1 |
| third_party_curl | `1386bb128bb060b284309397b97adcaaec21c003`，tree `b96addd5821a610eb0ceacc7e7a83deda64690c2` | 884；663 / 221 | blocked / completed_with_limitations | CVE-2026-92391 ×1 |

七条诊断对应六个 CVE 身份。libpng 归档索引了 98 个 C/C++ 源文件；候选源文件经 `libpng-1.6.55.tar.gz.members/` 虚拟路径与归档 blob/SHA 绑定。准确源码位置和哈希见各 JSON 报告。四个运行的 `validated_vulnerability` 均为 0；候选仍要求产品构建、入口和影响证据。

组件证据边界：

- CVE-2026-46675 的 libpng 组件 ASan 与修复对照见 D30；D49 的版本命中本身只是候选，不等于产品受影响。
- CVE-2025-9900 的 libtiff 组件 ASan 与上游修复形态对照见 D31；产品影响仍 unknown。
- libpng CVE-2026-33636 命中两处 ARM NEON 源码；镜像里存在补丁材料不等于已确认归档构建应用补丁。两条命中仍是候选。
- cJSON 两条和 curl 一条是源码签名候选；本轮未对这三项运行动态 PoC。
- 规则正例/修复形态/安全与无关控制已有回归：`tests/detectors/test_known_disclosed_cves.py`。完整运行结果为 21 项 OK。控制测试只验证规则形状，不作为独立准确率数据。

这组回放证明扫描器能在真实固定源码树及 libpng 源码归档中保留已披露问题的候选，同时诚实报告解析不完整。它不是独立盲测集，也不能计算 TP/FP/FN、precision/recall；D5 的 M2 与产品级 M3 门槛仍未满足。

机器报告：`libpng.json` SHA-256 `2b40aa39355554815d364d105304c145398783bc3dec1d569b2b1d3a2253b87a`；`libtiff.json` `2ff11bc0e3498e27491d8aea5b38c1a1f59884821d675647b2ca0352cdfcf4d9`；`cjson.json` `1cefdf123c154e609dcb399ca1e5f89f933ccab3769c073fe94a5998012e1ef3`；`curl.json` `0dd9f884cc5510d19deeb37936728e2ea9af0f0964647667e4812cdb57cb88fb`。
