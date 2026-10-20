# D 线第 19 轮：D103/T102 固定真实源码切片

D103/T102完成固定OpenHarmony源码切片复放。对象为arkui_napi revision `bfe8fad…`、tree `941f9…`，三个源文件共33,437 bytes，并校验7个源码/BUILD blob与SHA。BUILD的6个cpp中只将helper.cpp纳入本次选定范围；4个同仓依赖头可定位但未展开，其余跨仓/include身份仍unknown，完整GN/build未运行。

在敏感规则0.21.17下，直接结果0候选、Runner 0候选，但两者均blocked；解析3 files complete，分析3 files partial，217个原始调用事实稳定。T102 11项独立核对与D103一致。源码里存在一个受预处理enum switch，不属于最近的bounded switch admission；comma/recovery形态未出现。0不表示安全结论，真实WriteLog输出形态也未匹配当前sink模型。

D103脚本 `fb41368c949cf400434ea99f6c562638c2825708`，证据 `c511a1c6654569d1c7fdd16bfb9e9a5bfadda1e2`，T102独立复核 `a5ba6ab10b375d6b5565e85f2f8f456e6db38eb2`；证据pin更新 `adee570778e7c60285d9319f7e8b781238f3bb19`。收尾第三轮D104/T103已启动，完成后只做最终有界验收并停止。
