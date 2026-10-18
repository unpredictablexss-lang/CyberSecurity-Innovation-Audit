# D2 历史修复调查（有界结果，不是漏洞确认）

2026-10-17 实际查询官方组织镜像的提交搜索：dsoftbus sensitive/privacy/泄露与
security_access_token log，每查询最多10条。总数/返回/截断记录在D2_HISTORY_SEARCH.json。
提交标题不能当漏洞证据；进一步实际读取了4个提交的文件补丁和父提交。

## 已核实的两组日志删除硬化对

1. pre-fix parent `05ca843ed7f6968686a47283916b7553f12932ed` →
   修改提交 `273637945ecb7b53d5d9af3bfd4e48a40bb88252`。
   文件core/discovery/coap/nstackx_coap/src/disc_nstackx_adapter.c：删除把注册服务数据作为
   DISC_LOGI public字符串输出的参数，保留常量日志。提交标题为Delete sensitive information printing。
2. pre-fix parent `d33177135ec6c6aaf4a4c42de1f6878652b330e3` →
   修改提交 `63efce3ff7f2708527eb29216decaf5fe2dc33d0`。
   文件core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c：删除
   SoftBusLog对解码/解析缓冲区crypInfo.out的字符串输出。

完整父子关系、两端tree、blob、源码SHA256、文件大小及删除日志行号在D2_HISTORY_MANIFEST.json。
源码从GitHub API获取，逐字节检查SHA256及Git blob SHA1；第三方文件仅在本地缓存。
不是在源码里插日志或删守卫制造的修复对。未绑定任何CVE。

## 能证明与不能证明

能证明两端文件身份及日志删除机制；尚不能证明数据一定包含当前模型支持的密钥材料、
生产环境日志权限或产品影响。DISC_LOGI/旧SoftBusLog不在D1/D2当前Sink模型中，两端历史commit
也没有受审默认Source模型。因此两组都是“真实日志硬化线索”，不是当前规则的已通过
vulnerable/fixed真值正例，更不能宣称D2检出了真实历史漏洞。

默认模型对这些历史提交应blocked，不为凑命中临时扩展模型。当前尚未取得可用于本规则
真实有效性验收的同型敏感材料正例/修复对，这一缺口仍存在。

另两条核查：33d2cded693daa51a249d31463d4e75e56b01da3是广泛匿名化/隐私改动，不能仅按标题
推定某密钥泄露被修复；0d93578a8d173473cec51b246761efd57355f3f6主要是构建宏词语重命名，
排除为本规则历史漏洞样例。其余搜索含资源泄漏/日志级别/测试词语，不能混为信息泄露。

优先GitCode的具体API核对尝试返回404（见D2_HISTORY_SOURCE_CHECK.json）；这只说明该请求
未取得提交对象，不证明GitCode不存在此commit。已明确使用GitHub组织镜像备选，未声称
GitCode/Gitee交叉身份已通过，更未自动切换HEAD。

## 五类对照的准备状态

- vulnerable：真实产品/秘密性标签尚缺；现有合成正例不冒充真实漏洞。
- fixed：有真实日志删除端点，但是否满足当前来源/Sink模型仍未知。
- safe：当前固定组件长度/状态/常量日志是非材料对照，需要独立确认标签。
- unrelated：构建命名/资源泄漏等有明确排除机制。
- unknown：未审查历史Source/Sink、日志隐私/权限和partial代码必须单列。

下一步由负责人选一组线索，先研究数据构造、所含材料和旧日志API语义，再决定是否建立
新的固定版本模型；不能把扩大模型后的结果与当前9文件/0.1模型混评。

链接：
- https://github.com/openharmony/communication_dsoftbus/commit/273637945ecb7b53d5d9af3bfd4e48a40bb88252
- https://github.com/openharmony/communication_dsoftbus/commit/63efce3ff7f2708527eb29216decaf5fe2dc33d0
