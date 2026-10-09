# 队友 B 本地开发首轮交付记录

日期：2026-10-09。开发目录：D:\ICP。
主线参考：main@dcd9629f50a34545d75abc92c0a16c79723197db（上轮已读取；恢复后未重新查询远端）。
状态：研究原型交付，未接入主线、未 push、未建立正式 Detector 插件。

## 完成内容
1. 保留原 attack_surface_inventory.md 并附修订说明，新增 mmi_entry_verification.md，记录固定源码中真实分发和 parcel 读取关系。
2. 明确区分 AllocSocketFd 资源路径与 StubAddInputHandler 的 INPUT_MONITORING 检查路径，不合并不相关证据。
3. 新增标准库图算法研究原型：以调用者/权限/资源绑定 grant；记录未满足义务与见证路径，支持拒绝边撤销、身份变化及预算失败。
4. 保存 7 个标为 design/regression 的 synthetic fixtures；不是历史漏洞正例，也不是独立 holdout。
5. 新增源码 Git blob SHA-1/SHA-256/字节数离线校验，第三方下载内容放在忽略目录。
6. 修复根目录 unittest 发现问题，并增加错误输入/空 manifest/重复文件/非法哈希回归。

## 验证
- Windows Python 3.10.11，本地33项测试通过（包含3项新增 manifest 验证及1项算法错误类型测试）。
- 7个synthetic fixture复放通过。
- 固定清单12份文件核验通过（11个源码文件和LICENSE）；只验证内容完整性，不等于TU/CFG/权限语义或运行时验证。
- 包中的代码不访问网络、不执行外部扫描器、不修改受检源码。
- 未复跑主线测试、远端CI、CodeQL/Joern/Clang或WSL环境。

## 关键局限
原型输入为人工构造有向图，不能直接扫描 C++/ArkTS，也不能从图宣称真实漏洞。
非synthetic、partial、failed、not_run或不完整图均blocked/unknown。状态预算超出撤回不完整候选。
no_uncovered_sink_in_fixture只说明模型内无此候选，不是safe。
MMI结构研究没有公开CVE或已核验vulnerable/fixed修复对；其权限要求和设备入口可达性尚未确认。
原索引提到的运行日志未提供，仍runtime_validation=not_run、validated_vulnerability=0。

## 交付包
包中只有本地研究代码、自建fixtures、文档、来源清单及日志；没有第三方源码、虚拟环境或凭据。
verify_sources需要开发目录中的local_sources文件；交付包不包含这些文件，缺文件时会明确失败，不伪造通过。
接收方无需源码缓存即可运行单测和synthetic复放。

```powershell
python -m unittest discover -s tests -v
python -m research.experiments.interface.replay_fixtures
```

## 下一步
向负责人交付资产索引和MethodCard，确认实际敏感操作的权限要求及图事实来源；核对主线核心接口是否已冻结。
接口落地后按批准的required_facts实现受限源码事实提取与Detector桥接，随后做真实修复对/安全对照和独立holdout实验。
不自行新增主线schema/CLI，不直接推送或合并。
