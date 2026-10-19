# 测试与限制报告

## 已有测试证据

- Python：822 passed，12 skipped，1 warning，731 subtests passed。
- Web：npm test 16/16；npm run build 通过。
- 全量扫描：525/525 manifest 项目处理完成。

## 不能下的结论

- 不能把候选写成已确认漏洞。
- 不能计算真实识别率、漏报率、精确率。
- 不能把 partial/failed/unknown 项目写成安全或漏报。
- 不能把 C/D 的 research_unadmitted 写成生产可用。
- 不能把 525 个项目改写为 807 个库。
