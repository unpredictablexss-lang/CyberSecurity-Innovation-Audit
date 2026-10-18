# B 线公开漏洞回归与描述符证据改进（2026-10-19）

## 结论

本轮继续扩展 B 线的公开漏洞固定源码回归集，并改进 AUTH-01 对源码自定义描述符常量的判定。

- 新增两个官方 SA 中继漏洞修复对：CVE-2023-0035（communication_dsoftbus）和 CVE-2023-0036（inputmethod_imf）。两个易受影响提交各产生 1 条 ipc.relay.descriptor-boundary 候选，官方修复提交都降为 0。
- 前一轮 CVE-2025-25212 与 CVE-2025-27247 修复对仍分别为 1 → 0。目前四个公开漏洞根因都有固定源码回归结果；这只证明静态候选和公开根因/补丁相符，不是产品可利用性验证。
- 八仓固定提交在 detector 0.9.8 下重跑，总候选仍为 30。候选规则与 file:line 集合不变；aafwk 一条 AUTH-01 的理由由“未识别到描述符校验”改为“校验值与接口声明不一致”。
- 同属软总线的 CVE-2022-42463 为易受影响/修复版本各 0 条。其修复是 DSoftBus 网络回调 sessionName 白名单；当前检测器只建模 Binder OnRemoteRequest，所以这是明确未覆盖的入口类型，不是通过的回归。
- 全量测试 674 passed、36 skipped；git diff --check 通过。所有扫描报告的 validated_vulnerability 仍为 0。

## AUTH-01 描述符常量改进

当分析范围同时包含唯一 IRemoteStub<I> 接口身份、类自有 DESCRIPTOR 字符串定义以及接口的 DECLARE_INTERFACE_DESCRIPTOR 字面值时，分析器会比较两个精确字面值。相同才认可为有效校验；不同时保留候选并显示两侧值和来源行。接口不唯一、声明缺失、字符串转义未解码或定义歧义时，保持未知，不猜测。

在固定 aafwk_standard 提交 834a566b1372268c7bbb0c40362322f812ca6efc 上，ReverseContinuationSchedulerPrimaryStub 的 DESCRIPTOR 为 ohos.abilityshell.ReverseContinuationSchedulerMaster，而 IReverseContinuationSchedulerPrimary 声明 ohos.appexecfwk.ReverseContinuationSchedulerPrimary。检测器现在说明存在描述符校验，但比较对象不匹配；这仍不是产品影响或可达性的证明。

## 新增漏洞修复对

| CVE | 易受影响提交 → 修复提交 | 结果 | 文件解析 |
|---|---|---:|---|
| CVE-2023-0035 | communication_dsoftbus fe305c9fba103c1d5a1e2139d18c1d4d70b7e92c → 319168676be4b58127e49b38fa96703991c5a203 | 1 → 0 | 两侧 partial |
| CVE-2023-0036 | inputmethod_imf 1da19fb5651d23e5969cabe7e10cf79897961b36 → 540daea718730751ed21eabc6674c912c0fae5fd | 1 → 0 | 两侧 complete |

CVE-2023-0035 修复在 SoftBusClientStub 增加 parcel interface token 与 GetDescriptor 比较。CVE-2023-0036 修复在 PlatformCallbackStub switch 前增加同类 token 校验。来源为 OpenHarmony 2023-01 公告、DSoftBus PR !2140 与 inputmethod_imf PR !228。固定 Git tree、报告和 SHA-256 见 G 盘 B线已披露漏洞回归_20261019/v0.9.8扩展/manifest.json。

CVE-2022-42463 的官方修复 PR !2348 在 OnRecvAuthChannelRequest 解包后加入允许的 sessionName 检查。易受影响/修复两侧都未产生候选，因为当前 detector 的入口契约不覆盖网络认证回调。下一步如果要扩展，应做独立的 network callback 入口模型，并绑定输入、身份字段、策略检查和敏感效果；不要把所有 OnRecv* 函数泛化为入口。

## 八仓复测与边界

八仓纳入 6,407 个源码文件，parse complete/partial/not_run 为 4,302/1,733/372，候选 30 条，validated_vulnerability=0。30 个候选的位置与规则集合没有变化。没有独立 holdout，不报告 precision/recall；未运行设备 PoC 或完整产品构建。

主结果与机器可复核报告在 G 盘：
- B线已披露漏洞回归_20261019/v0.9.8扩展/增补报告.md
- B线已披露漏洞回归_20261019/v0.9.8扩展/manifest.json

独立公开来源：OpenHarmony 2023-01 安全公告 https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2023/2023-01.md；2022-10 安全公告 https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2022/2022-10.md。
