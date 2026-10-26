# 队友 D D4 接口需求（提交平台负责人）

## 目标

让 D 的历史静态风险研究在不绕过 Runner 覆盖语义的前提下，能够把**被精确版本证据审查过的局部函数**纳入统一 OHScanner，并把 `partial`、未知、证据义务准确保留下来。不得由 D 私自实现一套 Parser/Runner。

## 需要平台提供的 Frontend/Runner 接口

1. **局部分析单元**：输入仓库、完整 commit/tree、路径、源码 SHA-256、目标函数名/签名；返回函数 AST、参数与局部声明、嵌套类型身份、范围及 source span。
2. **语法与依赖证据**：返回目标函数是否有错误节点、错误是否与目标函数/摘要重叠、相关声明是否可解析；宏展开与 include 绑定状态明确表达为 complete/partial/unknown。
3. **覆盖合同**：局部函数可分析时只准许该函数证据，不把同一文件其余未分析代码标为 complete；未解析的宏、间接调用或跨文件类型必须保留 limitation。
4. **来源绑定**：所有局部单元与依赖绑定到 repository、commit/tree、revision、path、blob、SHA-256、Frontend 版本和解析配置，重复运行有稳定身份。
5. **调用摘要合同**：允许 Detector 提交经审查的精确摘要：函数签名、输出参数索引、输出类型/成员、分配器、成功返回常量；不接受宽泛的仅按名字匹配。
6. **Sink 摘要合同**：允许为一个确切 profile 指定 sink 名、格式参数索引、格式语法、默认隐私级别；未识别格式和动态 wrapper 结果是 unknown，不自动视作公开或安全。
7. **控制用例**：API 提供正例、固定/私有安全例、同名无关例以及宏/类型缺失时的拒绝例，供公共 Runner 集成测试。

## D 可提交的 Detector 配置

D 侧仅提供 profile 描述与规则：source 函数/参数摘要、字段、sink 语义、精确源码证据、消息类型条件及 evidence obligations。D 不要求独立平台、不要求 Catalog/UI 自动 Ready，也不要求改变公共扫描中的未知范围默认值。

## 运行态接口

静态证据充足后，通过平台**现有**隔离 Docker Worker/测试 Harness 提交已审阅输入；回收镜像 digest、命令/配置、Secure-C/日志适配器依赖版本、`vsprintf_s` 返回值、stdout/stderr、日志等级、格式化字节长度、原始日志是否被拒绝、最终 HiLog/printf 输出、持久化状态、测试身份与产物 SHA。设备读取测试至少覆盖 hdc/shell、普通应用 UID 和明确未授权主体，并采集服务端拒绝/允许证据；同时记录目标镜像的 HiLog socket 实际路径、权限位、owner/group、调用进程 UID/GID/补充组，以及运行时是否经 `hilogControl` 或其他读取接口，验证产品配置是否不同于同期上游 `0600 logd:logd` 的静态线索。Runner 不得把动态结果自动提升为漏洞确认；报告阶段要求人工复核读取权限与产品影响。

## 当前阻塞

本机未发现可执行的 Docker CLI；没有指定产品 build、设备或日志 ACL 证据。接口验收前，正式扫描范围维持 `partial`/未分析。
