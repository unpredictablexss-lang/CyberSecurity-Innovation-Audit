# 队友 D：D3 接口需求（独立文档）

## 已有实证阻塞

TCP 修改前的 ProcessReceivedData:628–679 与 DecryptMessage:377–395 无直接解析错误重叠，但同文件 78、136、601 行的宏解析缺分号使公共 Runner 拒绝整文件。独立探针可产生 1 条条件候选，公共结果为 0；不能由 D 自行改 Runner 准入。

## P0：请求负责人决定的最小接口

| 事实/策略 | 请求内容 | 验收标准 |
| --- | --- | --- |
| 固定来源事实 | repository/commit/tree/blob/file SHA、parser/profile/producer/version | 不同文件版本不可混用，缺失即 unknown |
| 函数和错误区域 | 函数稳定 ID、范围、缺失节点/错误范围、依赖区间 | 能表达上述两个函数不直接与错误重叠，但不自动判 complete |
| 局部准入策略 | 是否允许 partial 文件内经审查函数进入正式检测 | 由公共负责人实现及兼容测试；保留文件 partial 和未覆盖义务 |
| 声明/宏/绑定事实 | MsgCryptInfo、SoftBusLog、列表宏、实际 include 与构建分支 | 宏与类型依赖可解释，不能仅按名称认可符号 |
| 参数与成功边 | 调用身份、参数 2 输出成员、SOFTBUS_OK 分支及初始化限制 | 失败边、未检查状态、nullable 输出不凭空引入材料 |

## P1：提高证据可信度

提供版本化受限调用摘要的来源文件哈希、写出字段、成功条件与预算；提供日志 format_index、secure-C 与 HiLog 语义区分、格式化长度成功和构建选择事实。请求内容类型与真实入口证据不能由字符串变量名替代。

## P2：可选动态验证接口

若队长批准，复用现有 Docker Worker / 注册 Harness，传入固定源码、镜像 digest、合成凭据及修复前后/安全对照；返回触发、公开输出、读取主体与权限证据。D 不改公共队列、DB、Catalog 或 UI，不执行未经批准的 PoC。

## 兼容与验收

复用 SourceUnit、ScanContext、Finding、EvidenceObligations 与 file_outcomes，新增事实可选。以真实固定前后代码复核：公共准入前必须仍显示 not_analyzed；准入获准后若产生候选仍为 unassessed / partial，修复端消失需说明日志删除，不升级产品 fixed。A/B/C 和旧 71 控制继续通过。

负责人维护公共 schema、准入与注册；D 提供最小输入、模型和消费侧适配。当前只是 RFC，未修改公共内核。
