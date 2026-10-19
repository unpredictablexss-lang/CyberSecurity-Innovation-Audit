# D v1 限制与未完成项

- 这是第一阶段窄范围研究原型，不是成熟的全程序污点检测器，也未确认真实漏洞。
- 拟议 detector ID 与源/日志模型待负责人审查，Catalog/UI 未注册，PR/合入不自动代表已验收。
- 默认模型仅匹配一个已研究仓库及固定commit；其它版本返回blocked，需要重新审核来源。
- 6类来源并不覆盖全部凭据/PII；不将 caller token、标识符、长度、状态、布尔比较当秘密。
- 静态类型名字不等于真实类型绑定；同文件冒名保守处理，跨文件冒名、using/typedef、重载、
  继承和复杂指针仍有缺口。未初始化/已清零对象可能产生候选，初始化事实必须复核。
- 模型不证明生成/复制成功；失败路径、零长度、数值取值、条件可行性和物理内存内容未知。
- 分支join仅may-flow，不建CFG；循环/switch/try/lambda/return中的调用和复杂成员写入不完整。
- 未知函数可能变换/修改/逃逸参数：保留受限依赖及partial，可能有误报也可能漏掉间接传播。
- 支持格式子集；位置参数、PRI宏、动态格式、未知转换、转义差异和不一致参数明确partial。
  字符串参数不自动等于秘密，指针地址输出不按本规则判为密钥材料泄露。
- Private/default-private operands with sensitive flows are conditional candidates; review sink implementation, product privacy configuration, log collection policy, and reader access. This does not prove public exposure.
- 当前公共Runner先跳过partial AST，再调用要求ast的检测器；D不能私自绕过这个公共行为。
  真实复测9文件仅3个进入部分分析、6个未分析，零候选不代表无风险。
- 没有4个已验证的真实危险日志示例；没有真实漏洞修复对、CVE、独立holdout和准确率。
  合成32个控制用例不能替代这些材料。
- 同范围复跑比较的是同一D版本，不能说before/after算法改进；后续算法升级须冻结旧输出。
- 不实现另两条拟议diagnostic/file规则；不涉B的IPC/Parcel/ArkTS/WebView，不涉A/C算法。
- 未调用外部扫描器，没有运行不可信构建、PoC或设备攻击；因此也没有产品CIA影响结论。
- 尚需负责人ID/接口与正式集成审查、真实候选与产品日志证据、独立标注和隔离验证。
