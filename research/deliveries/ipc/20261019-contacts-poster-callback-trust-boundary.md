# Contacts Poster callback 信任边界复核

核对日期：2026-10-19

## 结论

八组件候选清单中 Contacts 有 4 条观察，位于 CommonEvent helper 和 Poster callback stub。成员函数指针语法归一化后，stub 的两条观察仍为 partial。固定源码追踪表明 PosterCallStub 是本进程创建并传给外部 com.ohos.accountcontactsservice/ContactsPosterServiceExtAbility 的 callback remote object；其 OnRemoteRequest 接收对端请求，再按 event 发布 CommonEvent。

Contacts DataAbility 的 Query 有 READ_CONTACTS 检查，contacts/download_posters 会创建 PosterCallAdapter。但这只约束初始查询调用者；异步 callback 的 IPC caller 是后续持有 callback binder 的 extension service，不能把 Query 的 permission check 当成 callback handler 的调用者鉴权。SetSubscriberPermissions(WRITE_CONTACTS) 设置的是 CommonEvent 订阅者权限；本仓代码没有找到 callback caller 的独立身份/权限检查。

extension 实现、访问策略和调用 callback 的触发条件不在该仓库。当前结论是 unresolved external dependency / candidate，不是确认漏洞；也不能仅因存在 READ_CONTACTS 闸门就降为误报。没有设备或 extension runtime 证据，不标 confirmed、不关联 CVE。

## 固定源码身份

- 仓库 openharmony/applications_contacts_data
- commit 341cc3bf41b48e9a5f278dd088f40a2041d2f1c9；tree 2054824c04bb403eeea128a9262edfb3001efa4f
- Stub dataBusiness/poster/src/poster_call_stub.cpp：blob 7cf9459f8f3b360dd85ba1587afc2a792e8a79fa；SHA-256 da61331914d7d1f92afea3b58eff862d0b1b2f98ec102258d7807cf8798a7f50
- Adapter poster_call_adapter.cpp：blob bbc05e587a2ba0edf9c544bc585c372e855658d3；SHA-256 29e9e2ebc7b8a9af55f930825490f30d0e5ffb4a96b5f0cb0e552353694eb123
- Proxy poster_call_proxy.cpp：blob 5f949449bcbd2628519883e865ea15de9a49807f；SHA-256 265a57f01deb21cdf9204482fbc792ef29aa4523e5c6a95870f643731c25d065
- Ability Query contacts_data_ability.cpp：blob c93e950725adc93276916b3c96c5ac7a5bb5b6b7；SHA-256 c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6
- CommonEvent helper contacts_common_event.cpp：blob efc70f78762a685a34540c3c55fae661fa56b91e；SHA-256 c0c53335e18655f994029dbf1ab07344c15fb44bfb46b85829147f4e1b5dad93
- Database contacts_database.cpp：blob ce8918ba8af7a2f26763508f874ff98c913ec617；SHA-256 5d2dfadc56ef05e361efc6c13da8e25b3a10971075924e80b9a5592c12cf839e
- Callback connection poster_call_connection.cpp：blob 4172c19315ac3f32afb45df85d0fba77aa66dfb3；SHA-256 09d7478fb940d9e577369f2a0c2e0cd4afc7cd1ddfae6d10a5e510fcfb13c6ac
- candidate keys：e09b38825062b1eb、555380bed70f8cff（stub AUTH-01, lines 44/46）；helper 441fd618768f69b5（AUTH-02）及 456f3a6f9f736ad8（AUTH-01）

## 固定源码链

1. ContactsDataAbility::Query 在 contacts_data_ability.cpp:1283-1290 检查 READ_CONTACTS；失败返回。CONTACTS_DOWNLOAD_POSTERS 在 :1408-1411 将 columnsTemp[0] 交给 ContactsDataBase::DownLoadPosters。
2. contacts_database.cpp:2524-2534 创建 PosterCallAdapter 并调用 DownLoadPosters。
3. poster_call_adapter.cpp:37-74 将 Want 目标固定为 bundle com.ohos.accountcontactsservice、extension ContactsPosterServiceExtAbility，再连接服务。:65-68 临时 ResetCallingIdentity，调用后恢复。
4. poster_call_connection.cpp:25-43 异步连接完成时构造 PosterCallProxy 并调用 DownLoadPosters。
5. poster_call_proxy.cpp:45-96 写接口描述符、transaction ID、两个同一 callback binder 和 payload，再发送 POSTER_BATCH_DOWNLOAD_CODE。PosterCallbackStub 在本地创建并作为 RemoteObject 写入 Parcel（:59-74）。
6. extension 持有 callback object 后发 RESULT_GET_ONE 请求进入 PosterCallStub::OnRemoteRequest。poster_call_stub.cpp:32-53 按 event 选择 DOWNLOAD_DONE_EVENT_CODE 或 DOWNLOAD_RESULT_EVENT_CODE，再调用 SendPosterEvent；handler 内未比较 interface token 或 caller UID/token。
7. contacts_common_event.cpp:62-68 使用固定 action POSTER_EVENT 和 WRITE_CONTACTS subscriber permission 发布 CommonEvent；:40-48 把权限放入 SetSubscriberPermissions。

## 解析与候选解释

原八仓报告把 poster_call_stub.cpp 标为 partial；探针定位到第 21 行 include 闭引号后的一个 ASCII 空格。行尾归一化探针保持文件长度、LF 偏移和函数/调用索引，但 B lane 未实现共享 Parser 修复，所以两条 stub 观察仍是 partial/unknown。

contacts_common_event.cpp 的 AUTH-02 表示敏感发布调用没有识别到 caller authorization；AUTH-01 表示 callback entry 到 helper 没有匹配 descriptor guard。它们没有证明 publisher 是任意 app，也没有证明 CommonEvent 一定接受该调用。READ_CONTACTS 与 WRITE_CONTACTS 是不同权限域，不能将初始入口检查当 callback caller check，也不能将 subscriber filter 当 publisher authentication。

## 下一步

获取并固定 extension 源码/制品、权限声明与绑定策略；在受控设备/镜像验证 extension 能否构造 RESULT_GET_ONE、event/payload 是否绑定可信后端结果，以及 CommonEvent Publisher 按哪个 token/UID 鉴权。检查 POSTER_EVENT subscriber 集合和 WRITE_CONTACTS 保护。若 extension 可信且 callback 只接受不可伪造的结果，可据固定架构判相应观察误报；若不可信主体可控且造成安全影响，再按证据门升级。证据不全时保持 unknown。Parser 属共享 Parser owner，修复后同 commit/tree/scope 重跑；B lane 不改 src/parser。

本轮只增加研究复核记录，没有改规则、候选状态、Parser 或目标仓库；没有构建产品、运行 PoC/Harness、提交或推送。
