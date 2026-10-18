# OpenHarmony A 线 30 份报告抽查与沙箱验证

本目录是 `D:\openHarmonyScanner\outputs\01a14d00-bc78-7ac2-9520-210d4b92b1ac` 的远端交付镜像。

## 结论

- 固定种子 `20261018` 确定性抽取 30 份报告：20 份有候选、10 份零候选。
- 345 条候选全部复核：高优先级 283 条、普通优先级 62 条。
- 0 个 `confirmed`，0 个专用漏洞 PoC；9 条 `not_reproduced`，336 条 `not_testable`。
- “高危候选”仅表示验证优先级，不表示扫描器已经确认高危漏洞。

## 文件

- `report/technical-report.md`：完整技术报告。
- `report/technical-report.pdf`：评审版 PDF。
- `openharmony-a-line-sample30.xlsx`：低认知负担四页签 Excel。
- `evidence/`：抽样、溯源、候选逐条判定、Docker 沙箱证据、环境与哈希。
- `poc/`：零确认漏洞记录；没有伪造的 `poc/<finding-id>/` 目录。
- `evidence/reconciliation.json`：JSON、Markdown、Excel、PDF 统计对账。
- `evidence/hashes.json`：原输出根目录 60 个文件的 SHA-256 清单。

## 远端打包边界

本 Git 交付不包含 `evidence/sandbox/scratch/bin/` 下的本地编译二进制。它们属于可重建构建产物，未进入提交；其字节大小和 SHA-256 已保存在 `evidence/hashes.json` 与 `evidence/sandbox/sandbox_file_hashes.json`。源码控制、编译脚本、运行日志、退出结果和环境指纹均保留。

Docker Hub 当时不可用，验证镜像使用本地 NVIDIA CUDA Ubuntu 22.04 镜像别名；为保证 sanitizer 地址映射稳定，运行参数包含 `seccomp=unconfined` 与 `setarch -R`。通用正/负控制只证明验证方法有效，不证明抽样产品组件存在漏洞。
