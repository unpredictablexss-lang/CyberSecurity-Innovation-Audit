# D4 未完成项

1. 已核对固定上游源码的标准 SoftBus 组件构建图，目标源文件进入仓库定义的标准 `softbus_server` 源集合；但尚无具体产品构建树、构建参数、宏展开、最终 target graph 和镜像清单，无法证明某一设备镜像实际选择并包含该 target。
2. 固定源码已确认日志使用 256 字节缓冲、先写 `[TRAN]` 前缀再调用 `vsprintf_s`；按 Secure-C 当前接口契约，格式化超长返回错误且该原始日志记录不会继续输出。目标产品实际链接的 Secure-C 版本未锁定，因此设备上的准确长度语义仍待核实。本机 `docker` 命令不可用，本轮没有动态 PoC。
3. 固定相邻日期 HiLog commit/tree 的配置、客户端和服务端四个源码对象已按 Git blob SHA-1、SHA-256、大小及递归 tree 路径离线核验。其源码配置将读取控制 socket 设为 `0600 logd:logd`，同期 SoftBus 服务身份是 `system` 或 `dsoftbus`；HiLog 配置同时含 `disabled: 1` 与 `start-mode: boot`，静态证据不能证明服务实际启动或 socket 已创建。仅当 hilogd 运行、该 socket 按配置创建且产品未覆写、调用主体无额外特权时，才能推出普通应用不能直接打开此控制 socket。它们是相邻日期的上游配置，不是同一产品构建快照；没有产品配置、服务启动状态、shell/hdc 身份或普通应用 UID 拒绝测试，不能判定目标产品读取 ACL。
4. 公共 Runner 对目标文件仍受局部解析准入限制；D4 不更改共享 AST/Runner。需要平台所有者按 RFC 提供局部函数/声明事实、宏/类型和覆盖边界的准入接口。
5. D4 泛化测试是合成 profile 设计控制，不是第二套真实上游 API 的实证，也不是盲审 holdout；没有 Precision/Recall。
6. 无已确认漏洞、产品影响或修复结论；版本间日志删除不证明其动机或安全效果。
7. 真实固定源码研究重放得到旧版 1 个候选、后版 0 个候选，但每版 10 个 required files 中各有 6 个 partial，结果状态均为 blocked；候选差异不是独立准确率、漏洞引入或修复证明。