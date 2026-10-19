# D3 真实 Git 源码实验

本轮实际执行，不引用 D2 数字代替。实现/测试 HEAD 与文件冻结 SHA 见 D3_FREEZE.json，完整运行输入、tree/blob/source/snapshot、解析器环境、逐函数错误/Source/Sink/限制与输出哈希见 D3_REAL_SCAN.json。每种输入公共扫描和独立探针均重复两次，候选及覆盖一致；含耗时的报告不要求字节一致。

| 实验 | 公共候选 | 私有研究候选 | 公共覆盖 |
| --- | ---: | ---: | --- |
| nine-file-baseline | 0 | 0 | {'complete': 0, 'partial': 3, 'not_analyzed': 6, 'failed': 0} |
| tcp-before | 0 | 1 | {'complete': 0, 'partial': 4, 'not_analyzed': 6, 'failed': 0} |
| tcp-after | 0 | 0 | {'complete': 0, 'partial': 4, 'not_analyzed': 6, 'failed': 0} |

原九文件基线在开发开始和最终代码上实际重放，保持 0/3/6/0、候选 0。历史每端 10 文件，范围可比。修改前研究候选路径为成功解密输出 crypInfo.out（649 行）→ 受审一跳输出摘要 → 671 行 SoftBusLog 字符串参数；修改后输出语句删除。正式 Runner 并未产生这条真实候选，独立探针也未接入 Catalog。

## 实验 4：真实控制与缺口

D3_REAL_CONTROLS.json 固定原文件位置：目标函数的公开常量日志、ret 状态日志在研究遍历中不形成材料告警；日志实现文件被公共 Runner 分析为 partial 且无该来源。另一版本的显式 AnonymizeWrapper 输出仅确认保护形状，该版本无受审来源模型，安全检测结论仍 unknown。原九文件 auth_session_key.c 的宏解析失败如实记 not_analyzed。

同名无关普通函数、private 输出、未检查状态等有新增合成控制，但未收集到独立真实“同名冒充接口”对照。不得把合成 24 控制包装成全部真实五类实验完成；保护形状也不等于已验证匿名化效果。

## 执行方法

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m research.data_sensitive.d3_experiment \
  --history-repo /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/d3-upstream.git \
  --baseline-repo /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git \
  --output-dir outputs/reports/d-sensitive/d3/real
```

源码 Git 对象应显式事先获取；扫描加载器禁止隐式 fetch，不运行上游源码。历史获取使用官方 GitHub 镜像的精确提交，30 个依赖文件字节已验证。原始第三方文件、对象库及大日志留在本机，不推入项目。

## 四类计数

真实代码研究候选：修改前 1、修改后 0；真实公共 Runner 候选：均 0。合成开发控制：旧 71＋新 24，不是漏洞数。历史日志删除线索：核验 2 组，1 组作为条件研究对，1 组因开源 stub 路径不成立排除。已确认漏洞：0。
