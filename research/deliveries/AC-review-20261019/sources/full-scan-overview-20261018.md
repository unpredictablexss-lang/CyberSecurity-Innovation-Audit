# OpenHarmony 漏洞扫描器新一轮测试报告

生成时间：2026-10-18T17:59:21+08:00

扫描器提交：`0d9357ea22224b72c9756864dbd14b71a4723924`

运行签名：`1696df82f39e2564e0821c0ad2e837a00c6d83f9276bf5e0c38a3bd1f511700b`

## 一句话结论

本次 manifest 可证实 525 个项目，全部完成处理；共产生 416,577 条候选，但已验证漏洞数为 0。候选不是漏洞，当前缺少 ground truth，不能据此宣称识别率、漏报率或精确率。

## 项目完成情况

| 分类 | 数量 |
| --- | --- |
| completed | 37 |
| failed | 138 |
| partial | 350 |

| 状态 | 数量 |
| --- | --- |
| unknown | 525 |

## 关键限制

- 候选结果不是已确认漏洞。
- 当前没有 ground truth，不能计算真实识别率、漏报率或精确率。
- CWE-476 候选数量高，存在明显噪声，必须结合路径、数据流和运行时语义复核。
- 大仓库、Rust、Kernel、解析失败项目只能标记 partial/failed/unknown，不能写成安全或漏报。
- C/D 检测线为 research_unadmitted，不能宣称生产可用或已绕过 admission gate。
- third_party_pulseaudio 同步出现网络告警，最终依赖本地固定对象，不能宣称所有远端实时可达。
