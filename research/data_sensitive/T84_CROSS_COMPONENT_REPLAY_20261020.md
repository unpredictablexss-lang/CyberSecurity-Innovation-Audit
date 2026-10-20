# T84：固定跨组件样本兼容性回归（2026-10-20）

本轮读取 Wi-Fi 和 IoT Connect 各一个固定真实源码文件，合计两个文件、26,362 字节。
对比本轮起点、首轮集成和 D85 三个固定实现；每版每文件重复两次，共 12 次 detector 执行。
两个样本均保持一个候选，候选依据、源码位置和 partial 覆盖一致，没有新增或消失。
这是单文件开发样本兼容性结果，不能扩大为两个完整组件的覆盖或准确率结果。

## 固定输入和身份核验

| 样本 | 固定源码提交 | 文件与字节 | 核验 |
|---|---|---|---|
| `openharmony/communication_wifi` | `e336c82b3b107d87f68c5e0448cc246b50b53b38` | `wifi/services/wifi_standard/wifi_framework/wifi_toolkit/utils/softap_parser.cpp`，5,160 字节 | SHA-256 与 Git blob SHA-1 均匹配 D40 记录；commit/tree 继承该记录，未本地重新核验 |
| `openharmony/communication_iot_connect` | `d8c0aef305601770c912dbdedc58a3f1e6efd30c` | `core/wifi/application/local_control/local_ctl_coap_api.c`，21,202 字节 | SHA-256 与 Git blob SHA-1 匹配 D27 记录；另外核验本地固定 commit→tree→path→blob |

Wi-Fi 输入来自已有 `tmp/t53-wifi-source-20261028` 缓存，SHA-256
`8f4e84d7eb5f86d892b15a2c1423db3260713ae0cf31a36621869321f9eb2388`，blob
`d1c56613712e4703765ce09084a12641dce5c4b0`。IoT 输入从 GitHub 固定提交的 raw URL 取回，SHA-256
`a3787e925f011e33c1c7f5458c536dd36920f6f1e708ae98cc47f21a6cd897de`，blob
`5b4a715c7ce7906460d2f1d0e089082cd7a92315`。没有对输入做换行或编码归一化。

IoT 的固定 commit 元数据另行获取到独立临时 bare 对象库；tree 为
`78db4611e16df5ee92328ceecf6c14baef8cb1a3`。离线脚本禁止 Git 网络传输与 lazy fetch，再检查 commit/tree/path/blob。
Wi-Fi GitHub 镜像拒绝该 commit（`not our ref`），因此未把它记为本地 Git 身份验证通过；已有字节与 blob 核验仍有效。
这些获取失败没有影响使用已经匹配原始记录的样本执行开发回归。

## 代码版本、执行与差异

| 版本 | 固定代码提交 | Wi-Fi 候选 | IoT 候选 | 每个样本的 detector 覆盖 |
|---|---|---:|---:|---|
| 0.21.0 | `6cbec8428a5c6c1ca86aa27b62ddc4ff2d06159f` | 1 | 1 | 1 partial，run blocked |
| 0.21.1 | `6f4f203ba4ab4dc811eb918a96bdd97531fddd08` | 1 | 1 | 1 partial，run blocked |
| 0.21.2 / D85 | `6131e8c26d2b29dc45022be982effb1c1e1d317e` | 1 | 1 | 1 partial，run blocked |

Wi-Fi 保留 `softap_parser.cpp:93` 的 `data.log.sensitive-value`：
`PassWordAnonymize(hotspotConfig.GetPreSharedKey()).c_str` 到 `WIFI_LOGI` public operand 0。
IoT 保留 `local_ctl_coap_api.c:602`：599 行 PBKDF2 输出，经 601 行 `UtilsHexify` 到 public 日志 operand 1。
三版的 finding signature 和 file outcome 都相同；源码和 parser 复用同一上下文，相关依赖已逐路径检查未变化。
因此观察到的是 detector 代码版本变化下这两条既有路径保持兼容，并没有实际候选增减需要归因。

两个文件的语法解析均 complete；这不等于安全分析 complete。敏感流 detector 仍报 partial/blocked，
权限、产品部署、实际日志可见性、可达性和影响没有得到验证。
单次 detector 执行约 Wi-Fi 0.0045–0.0058 秒、IoT 0.0145–0.0160 秒；没有把小样本耗时当作性能基准。
实际环境为 Python 3.13.9、tree-sitter 0.26.0，详见机器报告。

## 可复现命令和输入拒绝检查

工作树 `D:\openHarmonyScanner\worktrees\t84-cross-component-20261020` 下运行：

```powershell
D:\openHarmonyScanner\.venv-c-line\Scripts\python.exe research/data_sensitive/T84_cross_component_replay.py --wifi-source D:\openHarmonyScanner\tmp\t53-wifi-source-20261028\wifi\services\wifi_standard\wifi_framework\wifi_toolkit\utils\softap_parser.cpp --iot-source D:\openHarmonyScanner\tmp\t84-cross-component-source-20261020\communication_iot_connect\core\wifi\application\local_control\local_ctl_coap_api.c --iot-git-dir D:\openHarmonyScanner\tmp\t84-cross-component-source-20261020\communication_iot_connect.git --revision 6131e8c26d2b29dc45022be982effb1c1e1d317e --output research/data_sensitive/T84_CROSS_COMPONENT_REPLAY_20261020.json
```

脚本读取固定代码 Git blob，保存每版实现 SHA-256；重新检查两个既有 manifest 的原始哈希、
输入 SHA-256 和 Git blob SHA-1；发生字节不匹配就立即拒绝，不能继续产生“已验证”结果。
已额外实际执行篡改输入负例，`void fabricated() {}` 被拒绝为 `source bytes do not match pinned manifest: wifi`。
脚本本身不获取网络，不执行目标源码，也不修改 detector。

交付文件：本说明、`T84_cross_component_replay.py` 和完整机器结果 `T84_CROSS_COMPONENT_REPLAY_20261020.json`。
`git diff --check` 通过。真实源码留在独立缓存，不提交到仓库。

## 反馈和下一步

已向 D84/D85 返回：两个固定路径在 D85 前后仍兼容；本轮没有发现这两条路径的新具体反例。
这些路径没有覆盖 D85 新增的“局部 std::string 接收者零参数 c_str”形态，也没有覆盖 D84 的 compound assignment，
因此不能替代那两项变更的正例/修复/安全控制测试。
下一次扩展应选择具有这两类具体结构的真实源码路径，并先固定原始字节和身份，再执行相同对照。
现有样本是已使用的开发样本；无独立可靠标签，不报告 Precision/Recall，也不把零增减解释为没有漏报。
