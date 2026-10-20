# D 线接续切片：D88 / T87

D88针对T85证书框架固定头文件 `cf_log.h` 的C++语法partial问题。源码把空的 `extern "C"` 开闭括号分别放在两个 `#ifdef __cplusplus` 块中；tree-sitter原始解析将条件区间标为错误。D88只对连续、成对、顶层、body为空白的这类C++结构做等字节/等行的空格投影；C模式不应用。未配对、顺序错误、不同条件上下文、真实声明、注释/字符串/宏和函数/类/命名空间嵌套保持不变。

T87独立验证11项语法和偏移控制，并在固定三文件T85源码上从D87 `23abc16652866edf06f6d86d8c11ec5deb5be784` 到D88 `47bef6404919bc78121fae5fea8aa7408910b0e4`做新进程、完整 `src/` Git archive复放。原始 `cf_log.h` 的3266字节和SHA完全不变，仅解析投影中的11个非空白字节被空格替换；638条源调用的名称、参数和字节/行位置全部一致。原来partial的头文件变complete，Runner检查范围由2个文件扩为3个。

解释候选差异时区分direct detector和Runner：direct调用的完整三文件范围是21→20，仅第342行属性键候选移除；五条保留证据trace更新。Runner在D87基线已因header partial而忽略该头文件，原来就是20条；D88后仍为20，全部既有diagnostic ID与消息相同。稳定/occurrence身份因必要事实缺失继续unknown，没有把null相等当作身份证明。第347行输出参数和第349行未知LOGE包装调用仍保留。检测结果仍partial/blocked，不代表漏洞结论或准确率。

负责人集成HEAD：`6aa4a5937547fea123f4a3114e7d133430955118`。本轮实际复验：

- `python -m unittest discover -s tests/detectors/data -t . -q`：132项通过。
- known-CVE、known-case corpus与D83 adversarial套件：39项通过。
- D88与T87新增解析/边界测试：16项通过。
- T87固定实现重放：D87/D88独立控制各11项；direct 21→20、Runner20→20；原始调用位置不变。
- `git diff --check`及任务树JSON解析通过。

D88/T87提交与详细复现见 [D88 handoff](D88_HANDOFF_20261020.md)、[T87 handoff](T87_HANDOFF_20261020.md)；负责人日志保存在 `records/d-line-parallel-20261020-01a1571f/`。另有一项既有AST快照测试在当前Windows工作树报路径越界，已用原负责人AST源码复现，和本次修改无关，未修改其replay脚本。

下一条具名线索是D88恢复解析后仍保留的第349行：固定源码表明 `LOGE` 展开到 `CF_LOG_E`，但该参数是固定schema属性名，不是密码内容；未知macro和真实密码值仍需独立保护。D89/T88已启动，分别开发有界日志宏/参数角色绑定和独立真实值/未知宏反例反馈。
