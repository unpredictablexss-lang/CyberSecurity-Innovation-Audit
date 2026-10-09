# IPC入口、权限与跨函数分析：第三轮交付

2026-10-09；本地目录D:\ICP；主线参考main@dcd9629f50a34545d75abc92c0a16c79723197db，仍无正式Detector核心实现。

## 两项需求的已实现范围

自动入口：从IRemoteStub/IPCObjectStub类声明、OnRemoteRequest的MessageParcel签名、实际被find(code)和成员指针调用使用的map分发，以及直接return handler(data, reply)的switch分发识别源码入口。未使用的map、无stub基类的同名函数不当作入口。
自动源码权限：按跨文件调用追踪AccessTokenKit::VerifyAccessToken，以及HAP信息获取和APL位约束；绑定入口参数、局部常量、GetCallingTokenID的语法来源。读取token信息本身不算权限约束。
权限结论：这是源码中观察到的约束，而不是独立的官方产品授权政策。缺检查的接口不能从自己的代码反推出它本来必须要求什么权限；缺政策或设备上下文保持unknown。

宏：读取全部宏定义变体及来源hash。受限token展开支持非条件、非变参、无#或##、定义唯一的对象/函数宏、嵌套宏和do/while(0)，保留原行号映射。定义冲突、条件编译、变参、字符串化、拼接及递归耗尽标unknown。MMI的CHKPR两个配置分支仅提取共同的判空return语法，不忽略日志副作用，也不将它视为权限guard。
复杂调用：通过固定源码的DelayedSingleton对象宏关联PerHelper接收者；重载歧义和未知接收者不猜测。虚函数override和std::bind目标仅记录可能的目标和延期调用，保留动态类型/执行时机/身份上下文unknown。
跨函数：默认最多5层，可配置0..8层，并限制256默认状态；记录定义缺失、解析partial、循环与预算。局部变量在调用前且同一可见语法作用域中才传播，赋值后原token来源失效。这不是完整别名分析/SSA/CFG或编译器语义。
结果：权限helper的调用、否定布尔条件、拒绝分支return结构和特殊身份return true路径分别保存；else的角色不会被错记为正条件。没有证明条件可满足性、guard支配关系或设备可达性。

## 真实固定源码结果

OpenHarmony multimodalinput_input@2468d204d3f276c373841e057af35985296c8421，15份文件（含LICENSE）哈希绑定。
自动识别33个源码分发入口、23条源码权限约束链，包含3条INPUT_MONITORING链。这些是源码事实计数，不是漏洞数或统计检出率。
MMI INPUT_MONITORING链来自StubAddInputHandler、StubRemoveInputHandler、StubMarkEventConsumed，关联调用者token；条件与HAP/NATIVE/SHELL分支保留。AllocSocketFd未在当前已解析链中发现该权限约束，不据此认定存在越权。
33个入口的覆盖均为partial（存在外部定义、宏副作用或动态调用缺口）。不写safe、不写miss，validated_vulnerability=0。

## 验证和边界

Windows Python3.10.11、tree-sitter0.25.2、tree-sitter-cpp0.23.4；92项测试通过，pip check通过。
真实源码smoke核验：33个入口、23条约束、3条monitor权限、ALLOC_SOCKET_FD=0、AllocSocketFd不混入monitor权限链、CHKPR共同return语法。
所有自建样例仍属design/regression，无独立holdout。未执行PoC、设备测试、外部扫描器对照或WSL验证。没有确认漏洞，也没有泛化为任意IPC/RPC框架。
不支持自动推断缺失的官方安全政策、全C++预处理/TU、任意RPCIDL生成器、反射、全程序虚调用/指针别名或复杂路径可满足性。源码中的宏和函数有限分析已实现；通用完整分析不可宣称已完成。

## 运行

```powershell
cd D:\ICP
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m research.experiments.interface.replay_ipc_inventory
```

`RepositoryIndex(...).inventory()`自动产生入口和权限索引；`analyze_with_macros(source, model, headers)`提供受限宏展开后的候选检查。两者是本地研究接口，不冒充主线DetectorAPI；没有新的产品CLI、公共schema或provider变更。
在线下载只用于开发准备；上述分析不联网、不执行外部工具、不修改受检源码。第三方源码只留忽略目录；交付包含来源清单和宏片段的许可证说明。

## 每个入口的观测

|处理函数|事务|观察到的源码约束|覆盖|
|---|---|---|---|
|MultimodalInputConnectStub::StubHandleAllocSocketFd|IMultimodalInputConnect::ALLOC_SOCKET_FD|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubAddInputEventFilter|IMultimodalInputConnect::ADD_INPUT_EVENT_FILTER|PermissionHelper::APL_SYSTEM_CORE|partial|
|MultimodalInputConnectStub::StubSetPointerVisible|IMultimodalInputConnect::SET_POINTER_VISIBLE|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubSetPointerStyle|IMultimodalInputConnect::SET_POINTER_STYLE|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubGetPointerStyle|IMultimodalInputConnect::GET_POINTER_STYLE|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubIsPointerVisible|IMultimodalInputConnect::IS_POINTER_VISIBLE|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubRegisterInputDeviceMonitor|IMultimodalInputConnect::REGISTER_DEV_MONITOR|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubUnregisterInputDeviceMonitor|IMultimodalInputConnect::UNREGISTER_DEV_MONITOR|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubGetDeviceIds|IMultimodalInputConnect::GET_DEVICE_IDS|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubGetDevice|IMultimodalInputConnect::GET_DEVICE|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubSupportKeys|IMultimodalInputConnect::SUPPORT_KEYS|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubGetKeyboardType|IMultimodalInputConnect::GET_KEYBOARD_TYPE|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubSetPointerSpeed|IMultimodalInputConnect::SET_POINTER_SPEED|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubGetPointerSpeed|IMultimodalInputConnect::GET_POINTER_SPEED|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubSubscribeKeyEvent|IMultimodalInputConnect::SUBSCRIBE_KEY_EVENT|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubUnsubscribeKeyEvent|IMultimodalInputConnect::UNSUBSCRIBE_KEY_EVENT|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubMarkProcessed|IMultimodalInputConnect::MARK_PROCESSED|unknown / 未观察到约束|partial|
|MultimodalInputConnectStub::StubAddInputHandler|IMultimodalInputConnect::ADD_INPUT_HANDLER|PermissionHelper::APL_SYSTEM_BASIC_CORE; ohos.permission.INPUT_MONITORING|partial|
|MultimodalInputConnectStub::StubRemoveInputHandler|IMultimodalInputConnect::REMOVE_INPUT_HANDLER|PermissionHelper::APL_SYSTEM_BASIC_CORE; ohos.permission.INPUT_MONITORING|partial|
|MultimodalInputConnectStub::StubMarkEventConsumed|IMultimodalInputConnect::MARK_EVENT_CONSUMED|ohos.permission.INPUT_MONITORING|partial|
|MultimodalInputConnectStub::StubMoveMouseEvent|IMultimodalInputConnect::MOVE_MOUSE|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubInjectKeyEvent|IMultimodalInputConnect::INJECT_KEY_EVENT|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubInjectPointerEvent|IMultimodalInputConnect::INJECT_POINTER_EVENT|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubSetAnrListener|IMultimodalInputConnect::SET_ANR_OBSERVER|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubRegisterCooperateMonitor|IMultimodalInputConnect::REGISTER_COOPERATE_MONITOR|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubUnregisterCooperateMonitor|IMultimodalInputConnect::UNREGISTER_COOPERATE_MONITOR|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubEnableInputDeviceCooperate|IMultimodalInputConnect::ENABLE_INPUT_DEVICE_COOPERATE|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubStartInputDeviceCooperate|IMultimodalInputConnect::START_INPUT_DEVICE_COOPERATE|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubStopDeviceCooperate|IMultimodalInputConnect::STOP_DEVICE_COOPERATE|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubGetInputDeviceCooperateState|IMultimodalInputConnect::GET_INPUT_DEVICE_COOPERATE_STATE|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubSetInputDevice|IMultimodalInputConnect::SET_INPUT_DEVICE_TO_SCREEN|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubGetFunctionKeyState|IMultimodalInputConnect::GET_FUNCTION_KEY_STATE|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
|MultimodalInputConnectStub::StubSetFunctionKeyState|IMultimodalInputConnect::SET_FUNCTION_KEY_STATE|PermissionHelper::APL_SYSTEM_BASIC_CORE|partial|
