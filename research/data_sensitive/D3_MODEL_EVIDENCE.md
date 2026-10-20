# D3 历史 Source / Sink 原始依据

模型文件：src/ohscanner/detectors/data/historical_profiles.json；每端 10 个 required_files、完整版本与 evidence 行号/哈希均在其中。原默认 models.py 保持原字节。

仓库 openharmony/communication_dsoftbus；修改前 d33177135ec6c6aaf4a4c42de1f6878652b330e3，修改后 63efce3ff7f2708527eb29216decaf5fe2dc33d0。Git 原始提交确认父子关系，文件 blob SHA-1 和 SHA-256 均核验；完整清单 D3_SOURCE_MANIFEST.json。来源为官方组织 GitHub 镜像，GitCode 具体 API 请求返回 404，跨镜像身份尚未核验。

## Source 依据

softbus_message_open_channel.c 的 PackRequest 将 appInfo->sessionKey 经 SoftBusBase64Encode 编码，加入 SESSION_KEY JSON 字段；同文件 UnpackRequest 取出此字段并 Base64Decode 回会话密钥。协议头将 SESSION_KEY 定义为相应 JSON 字段名；AppInfo 声明与传递 ChannelInfo.sessionKey 的代码提供用途上下文。因此来源不是基于 key 字符串命名猜测，而是明确的编码、构造、反向解码与会话密钥使用关系。

目标 trans_tcp_direct_message.c 的 DecryptMessage 在修改前 377–395 行，将输出缓冲区绑定 cryptInfo->out（387 行），调用 AuthDecrypt，失败时返回错误，成功更新 outLen。ProcessReceivedData 先分配 out，检查非空，649 行检查 DecryptMessage 状态，解析 JSON；671 行将整个 out 当字符串打印。源位置为成功边 649 行，不是说该行生成了密钥。

必须保留条件：只有携带 PackRequest 会话密钥的请求数据才满足材料前提；reply/error 或其他 JSON 不一定携带秘密。该模型识别可能的密钥承载路径，不保证每次到达日志的数据都有密钥，也未自动追完整网络调用链。

## Sink 依据

core/common/include/softbus_log.h 声明参数 module、level、fmt、...；core/common/log/softbus_log.c 的 SoftBusLog 读取配置阈值，vsprintf_s 到 256 字节缓冲区，再调用 SoftBusOutPrint。adapter/common/log/softbus_adapter_log.c 对 ERROR 分支使用 %{public}s，SOFTBUS_PRINTF 分支用 printf。故这个版本普通 %s 不是默认 HiLog 私有槽位；格式位置为 2。

feature_config 默认 ADAPTER_LOG_LEVEL 为 0，只能作为该源码默认配置依据，不能证明量产运行配置。实际构建选择、阈值、模块/等级合法、格式化是否成功、长度上限、读取者权限仍待核验。过长日志可能格式化失败，不应假设任何长度材料都会输出。

## 审核状态与传播预算

模型是 research_source_reviewed，待队长验收；只绑定上述两个版本，语义相同，修复端不因没有日志而改变 Source 条件。最多一跳明确摘要，支持简单成员、指针别名赋值与局部成功分支，不支持泛化解密器、任意跨文件调用、复杂指针或未知构建变体。依赖缺失不加载模型，未知字段不因命名升级为秘密。
