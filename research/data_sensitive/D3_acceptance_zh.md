# 队友 D：D3 阶段验收文档（独立文档）

日期：2026-10-17。结论：已完成真实版本模型、最小历史算法扩展、前后源码实验与回归；有 1 条真实研究候选，但尚未成为公共 Runner 的正式候选或确认漏洞。

## 验收结果

| 项目 | 实际结果 |
| --- | --- |
| 起始 HEAD | d64d1787250fdff0f912c2733b2739cf6c78ff51；原分支干净、PR 无新评审 |
| 模型提交 | dc9ed46；精确前后版本、每端 10 依赖、来源/日志定义哈希 |
| 算法提交 | 7a75d9c；独立历史模式、分配/非空/成功边、受限一跳摘要 |
| 测试及冻结 HEAD | 88528b791323e25ea96108ab6c95cbc8f3ce646f |
| D 专项 | 25 个 unittest 方法通过；旧 71＋新 24 个设计控制 |
| 全量 | 537 项，526 通过、11 跳过、0 失败/错误 |
| 编译/格式检查 | compileall、git diff --check 通过 |
| 原九文件 | 公共候选 0，complete 0 / partial 3 / not_analyzed 6 / failed 0 |
| 历史前后各十文件 | 公共候选均 0，complete 0 / partial 4 / not_analyzed 6 / failed 0 |
| 真实独立探针 | 修改前 1，修改后 0；两次运行候选与覆盖一致 |
| 已确认漏洞 / PoC | 0 / 未执行 |
| holdout | 冻结后收集 3 个未标注新组件文件；独立评估未执行，无准确率 |

## 用大白话解释这次推进

以前主要证明“人工写的小样例能识别”。这次在未修改的真实鸿蒙历史代码中，找到了“请求 JSON 可以装会话密钥，解密成功后整个缓冲区被公开日志打印”的风险路径，并在删日志后的真实版本看到候选消失。

不过平台解析整个文件时，被其他函数里的宏卡住，所以这条发现来自明确标注的研究探针；网页/正式 Runner 还没有获得同样能力。也没有证明量产设备会实际输出、普通应用能读取，故不能说已确认一个真实信息泄露漏洞。

## 与任务目标对应

- A：真实日志删除前后实验已执行，输入固定到完整 Git 对象，双跑稳定。
- B：两个精确版本独立模型已实现，敏感性依据为 Base64 编码/解码的会话密钥字段及协议用途，日志依据为具体格式化与 public 适配。
- C：真实源码已执行，公共与私有结果分开；零候选和解析阻塞均有解释。
- D：模型、算法、测试分开提交，研究证据与独立三份文档交付；最终远端提交和 Draft 状态以发布核验回执为准。

实验 4 尚缺独立真实同名无关函数；真实脱敏形状未在受审模型上正式评估。独立真值与产品验证未完成，任务书允许先交付实际收集/盲审流程及阻塞 RFC，不能将这些缺口标为通过。

## 主要修复/新增机制

为旧 SoftBusLog 单独核验参数和默认公开语义，避免误用 HiLog 私有默认值。只有检查成功返回、分配与非空的局部路径才引入历史来源；失败、未初始化、未知别名、未审提交或依赖哈希不符时不硬报。同名遮蔽和成员覆盖有控制；未支持的复制成功状态与复杂语义保留限制。

## 复核入口

research/data_sensitive/D3_HANDOFF.md 是总入口；D3_MODEL_EVIDENCE.md 核对模型；D3_HISTORICAL_CASES.md 核对服务发现排除与 TCP 条件候选；D3_REAL_SCAN.json / .md 核对实际实验；D3_VALIDATION.json 核对日志 SHA 与 skip 理由。

本机 Ubuntu：/home/lzc/projects/OHScanner-teammate-D。专项命令：

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m unittest tests.detectors.data.test_sensitive_exposure tests.detectors.data.test_d2_semantics tests.detectors.data.test_d3_historical -v
TMPDIR="$PWD/.tmp" $PY -m unittest discover -s tests -v
```

11 项 skip 为既有语料/固定历史源码缺失与禁止宿主机执行的 Docker 测试；逐条理由见 JSON。未修改公共 Runner、Catalog、contracts、frontend、DB/UI 或其他队友模块；旧 71 控制哈希保持不变。

## 下一步审批点

先审核 D3_interface_requirements_zh.md 的局部事实与准入请求；再按 D3_research_plan_zh.md 补真实请求、日志与读取权限证据。不能将研究探针直接当生产能力，不自动 Ready、合并或确认漏洞。
