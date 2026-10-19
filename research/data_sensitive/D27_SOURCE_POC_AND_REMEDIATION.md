# D27 源码级复现 PoC 与修复建议

日期：2026-10-19  
规则：`ohscanner.data.sensitive_exposure` 0.15.0 / `data.log.sensitive-value`  
结论：**固定组件源码中的派生密钥到公开 INFO 日志路径已确认；OpenHarmony 产品漏洞仍为 unknown。**

## 已确认的事实

审计对象固定为 `openharmony/communication_iot_connect` commit `d8c0aef305601770c912dbdedc58a3f1e6efd30c`，Git tree `78db4611e16df5ee92328ceecf6c14baef8cb1a3`。文件 `core/wifi/application/local_control/local_ctl_coap_api.c` 的 Git blob 为 `5b4a715c7ce7906460d2f1d0e089082cd7a92315`，内容 SHA-256 为 `a3787e925f011e33c1c7f5458c536dd36920f6f1e708ae98cc47f21a6cd897de`。

在 `localCtlSessKeyGen` 中，PBKDF2 将派生结果写入 `localCtlKey`；随后 `UtilsHexify` 把该数据转换到 `localCtlKeyStr`；第 602 行的 `IOTC_LOGI` 将字符串写入日志。固定版本的日志适配器使用 HiLog `%{public}s` 格式输出。以上是对该 commit 源码行为的确认，不依赖 G 盘当前 dirty working file。

## 可重复的源码级 PoC

这是**扫描器复现 PoC**：验证固定 Git 源码能否稳定产生绑定源码哈希的候选，并检查面板 API、Worker、报告和源码视图的证据链。它不会执行被审计程序，不会触发设备日志，不是产品利用 PoC。

前置条件：仓库对象库位于 `/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/communication_iot_connect`，且包含上述 commit。运行：

```bash
cd /home/audit/ohscanner/worktrees/d-commercial-expansion-20261018
.venv-web/bin/python research/data_sensitive/d27_iotc_panel_replay.py --output /tmp/D27_IOTC_PANEL_REPLAY.json
```

通过条件：脚本退出码为 0；同一 commit 的两次扫描具有相同的 tree、snapshot、候选身份和源码哈希；候选位于 `local_ctl_coap_api.c:602`；候选源码视图 SHA-256 与诊断绑定一致。预期状态仍是 detector `blocked`、任务 `completed_with_limitations`、`validated_vulnerability=0`。原始双次运行记录见 [D27_IOTC_PANEL_REPLAY.json](D27_IOTC_PANEL_REPLAY.json)，规则控制样例见 `tests/detectors/data/test_sensitive_exposure.py`。

## 修复建议

优先删除输出 `localCtlKeyStr` 的日志语句。若诊断确有需要，只记录固定事件名、成功/失败和非敏感错误类别，不记录密钥、认证码、令牌或可逆编码。不要用截断、散列或十六进制转换替代删除，除非经过独立审查证明该变换不可用于恢复或关联敏感材料。

回归检查应覆盖 INFO 开启和关闭的构建/运行配置，确认最终日志缓冲、设备日志及可导出诊断包中都不含派生密钥字节；并增加测试保证 `localCtlKey`、`localCtlKeyStr` 不进入日志参数。修复提交后在补丁版本重跑规则，要求候选消失，同时其他正常非敏感日志控制样例仍可通过。

## 尚不能确认的事项

日志中的 PBKDF2 输入来自 `ctx->authCodeInfo.authCode`；活动 `transKey` 经过单独的 `DevSvcProxyGetAuthInfo()` 路径。两个输入是否相同尚无证据。当前也没有证明该组件进入具体产品构建、目标设备启用该 INFO 级别、日志读取者权限、密钥可被实际重用或对产品造成安全影响。因此不能把本条报告称为已确认产品漏洞，也不能提供真实设备攻击 PoC、影响版本或 CVSS 结论。确认这些事项需要产品构建清单、调用入口与身份路径、日志配置/访问控制证据，以及受控的修复前后验证。

