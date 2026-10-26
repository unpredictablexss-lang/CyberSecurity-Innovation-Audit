# D3 两组真实历史改动核验

## 服务发现：排除为本轮有效正例

05ca843ed7f6968686a47283916b7553f12932ed → 273637945ecb7b53d5d9af3bfd4e48a40bb88252 确实删除 DISC_LOGI 的 registerCapaData public 输出。但同版本 disc_coap_capability.c 中 DiscCoapAssembleCapData 忽略输入并返回 SOFTBUS_FUNC_NOT_SUPPORT；调用方对此释放缓冲区并返回，不会继续到该日志。

因此当前开源实现不能证明该日志路径可达，更不能证明其包含秘密。其他供应商扩展可能不同，但没有源码证据，保持 unknown。已核验 DISC_LOGI 宏转发与匿名化日志上下文，不据标题“sensitive”给漏洞标签。不为此建立敏感 Source 正例模型。

## TCP：选为条件研究候选 / 日志删除回归对

d33177135ec6c6aaf4a4c42de1f6878652b330e3 → 63efce3ff7f2708527eb29216decaf5fe2dc33d0。

真实源码存在 PackRequest 会话密钥编码入 JSON、解密输出、旧 SoftBusLog 公开适配的上下文。修改前独立探针在 ProcessReceivedData:671 输出 1 条候选；修改后该语句被删除，候选为 0。同规则语义、同 10 个路径范围，两端分别绑定正确文件哈希。

目标文件在两端均有 LIST_FOR_EACH_ENTRY 类宏导致的缺分号解析区域（修改前 78、136、601 行）；目标函数与 DecryptMessage 均无直接错误重叠。公共 Runner 整文件不准入，因此两端公共候选都是 0。不能把公共零候选差异宣传成平台已经检出/修复真实漏洞。

这个案例提供材料与公开日志代码依据，但请求内容、格式化长度成功、构建开关、真实入口与非授权读取者未闭环，仍是条件 candidate。没有 CVE、确认漏洞或产品受影响版本结论。没有修改原上游源码，没有给真实源码插入日志或移除守卫以制造正例。
