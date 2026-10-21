# 外接盘 OpenHarmony-100 与 B 线实验材料

来源：`G:\OpenHarmony-GitCode-Mirror\campaign-100-20261017\results`。本目录复制了 `执行总结.md`、ABCD 线实测分析、未扫描仓库覆盖说明、候选诊断数量拆解、detector 统计，以及 B Detector 0.12.1 的完整固定漏洞/修复版本回归（43 个文件，复制 SHA-256 与原盘逐项相同）。

同一仓库材料包中的 `B线/当前分支_v0.12.12/` 是之后团队分支上的回归，不应与本目录的 0.12.1 混作同一版本或同一实验。

原盘保留了多份逐步生成的 OpenHarmony-100 XLSX。其 `OpenHarmony-100扫描结果_20261018_part211.xlsx` 为 55,844,523 字节，SHA-256 `a77e79bef0151835de1b61ecc953742f511a5d3141c43788da26c27c336993c6`；不入 Git，避免提交超过 1 GB 解压规模的重复生成表。评委需要原始表时，请从上述 G 盘路径单独复制，并先校验此哈希。

本目录中的 campaign 报告是当时的实验快照，未扫描仓库范围见覆盖说明；候选数量与命中数不能解释为真实漏洞数量、准确率或召回率。每项产品适用性和修复前后差异以报告内的固定 commit、scope、Detector 版本和 `validated_vulnerability` 为准。