# AUTH-01 最小 PoC 闭环样板

本目录把一个已绑定的历史样本从 Detector 候选串到本地隔离组件 PoC 和报告片段。
它复用 `src/ohscanner`、`src/workbench/validation.py` 和 AUTH-01 Harness，不创建第二套扫描器，
也不自动确认漏洞。

## 运行

在 Ubuntu WSL、已存在的固定本地源码库和固定 Docker 镜像上运行：

```bash
cd /mnt/e/网安/CyberSecurity-Innovation-Audit
.venv-web/bin/python research/poc/auth01_minimal_loop/run_minimal_loop.py
```

默认输出为 `outputs/poc-loop/auth01-20261014/run-001`。脚本拒绝覆盖非空证据目录。

## 固定样本

- 目标：`openharmony/inputmethod_imf`
- vulnerable：`e663b47013d534a56165ab7467fbb3e14bf7172b`
- fixed：`5eaddcab19bc4b22544f4bee1e8894fc2d6505dc`
- 历史根因绑定：`CVE-2023-0036` / `OpenHarmony-SA-2023-0102`
- Detector：`ohscanner.interface.ipc` `0.5.0`
- 候选：`ohscanner.interface.ipc:c590c70a85c68412`

## 证据链

1. 固定 commit/tree/blob/source SHA 与可达性引文重新核验。
2. 固定提交扫描产生候选与 `EvidenceObligation`。
3. 生成执行前人工复核清单。
4. 仅通过 Docker 验证适配器运行 vulnerable/fixed/patched 三方组件 Harness。
5. 保存 sanitizer 配置、行为差异、稳定重放、命令、输入 manifest、日志和哈希。
6. 生成 `evidence-record.json`、`report-fragment.md` 与 `artifact-manifest.json`。

最终状态固定为 `candidate / possible_hit / unassessed`，`validated_vulnerability=0`。
组件级触发不证明真实产品入口、权限边界或 CIA 影响；报告片段不能直接升级为 reportable。
