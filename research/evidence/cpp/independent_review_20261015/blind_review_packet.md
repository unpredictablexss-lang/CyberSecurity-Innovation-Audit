# A 线 shared_ptr 盲审包

使用顺序：先只看本文件和 blind_review_packet.json，完成并冻结全部盲审标签；
之后才打开 blind_review_key.json 和 review_supplement.json/md 做首轮对照。

- 盲审项：45
- 固定 review ledger SHA-256：`6fc11cc43cd653cad449022ae16a3d5a2b110e353065d2ae53a13738f97f5404`
- 固定 holdout manifest SHA-256：`c014f96a356a5671e6afd545e518122099c6173a7d65947ef083722741fdd30a`

每项必须输出 `vulnerable/fixed/safe/unrelated/unknown`、证据位置、排除理由、待补事实和最小复现方向。

## `00c8ae87a8576190`

- 位置：`interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h:32:22`
- Symbol / operation：`jsCallBack_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`20706185efad40245b844eb5b1397da2de26a1f42b5d6dc4719ea5520f300348`

```cpp
  24: namespace Rosen {
  25: class JsPiPWindowListener : public IPiPLifeCycle,
  26:                             public IPiPActionObserver,
  27:                             public IPiPControlObserver,
  28:                             public IPiPWindowSize,
  29:                             public IPiPActiveStatusObserver {
  30: public:
  31:     JsPiPWindowListener(napi_env env, const std::shared_ptr<NativeReference>& callback)
  32:         : env_(env), jsCallBack_(callback) {}
  33:     ~JsPiPWindowListener();
  34:     std::shared_ptr<NativeReference> GetCallbackRef() const;
  35:     void OnPreparePictureInPictureStart(PiPStateChangeReason reason) override;
  36:     void OnPictureInPictureStart(PiPStateChangeReason reason) override;
  37:     void OnPreparePictureInPictureStop(PiPStateChangeReason reason) override;
  38:     void OnPictureInPictureStop(PiPStateChangeReason reason) override;
  39:     void OnPictureInPictureOperationError(int32_t errorCode) override;
  40:     void OnRestoreUserInterface(PiPStateChangeReason reason) override;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `03ac81fdf0dad858`

- 位置：`interfaces/innerkits/wm/wm_animation_common.h:265:37`
- Symbol / operation：`animationSystemParams` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`

```cpp
 257: 
 258:     // LCOV_EXCL_START
 259:     bool Marshalling(Parcel& parcel) const override
 260:     {
 261:         if (!parcel.WriteParcelable(animationParams.get())) {
 262:             return false;
 263:         }
 264: 
 265:         if (!parcel.WriteParcelable(animationSystemParams.get())) {
 266:             return false;
 267:         }
 268: 
 269:         bool hasNeedAnimation = (needAnimation != nullptr);
 270:         if (!parcel.WriteBool(hasNeedAnimation)) {
 271:             return false;
 272:         }
 273:         if (hasNeedAnimation && !parcel.WriteBool(*needAnimation)) {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `0984ba53e4891550`

- 位置：`interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:117:71`
- Symbol / operation：`data_` / `read`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`

```cpp
 109:     std::vector<int32_t> grantResults;
 110:     std::vector<int32_t> errorReasons;
 111:     std::vector<bool> dialogShownResults;
 112:     std::shared_ptr<RequestAsyncContext> data = nullptr;
 113: };
 114: 
 115: class AuthorizationResult : public Security::AccessToken::TokenCallbackStub {
 116: public:
 117:     AuthorizationResult(std::shared_ptr<RequestAsyncContext>& data) : data_(data) {}
 118:     ~AuthorizationResult() override = default;
 119: 
 120:     void GrantResultsCallback(const std::vector<std::string>& permissionList,
 121:         const std::vector<int>& grantResults) override;
 122:     void WindowShownCallback() override;
 123: 
 124: private:
 125:     std::shared_ptr<RequestAsyncContext> data_ = nullptr;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `0a21bb32264c7d75`

- 位置：`interfaces/innerkits/wm/wm_animation_common.h:261:37`
- Symbol / operation：`animationParams` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`

```cpp
 253:      * @brief Whether application-defined window size limits are allowed to exceed system limits.
 254:      */
 255:     bool isWindowLimitsForcible = false;
 256:     bool minimizeOnStart = false;
 257: 
 258:     // LCOV_EXCL_START
 259:     bool Marshalling(Parcel& parcel) const override
 260:     {
 261:         if (!parcel.WriteParcelable(animationParams.get())) {
 262:             return false;
 263:         }
 264: 
 265:         if (!parcel.WriteParcelable(animationSystemParams.get())) {
 266:             return false;
 267:         }
 268: 
 269:         bool hasNeedAnimation = (needAnimation != nullptr);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `0c076a622b333f8d`

- 位置：`previewer/include/wm_animation_common.h:281:54`
- Symbol / operation：`excludeFromDock` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`

```cpp
 273:         if (!parcel.WriteBool(minimizeOnStart)) {
 274:             return false;
 275:         }
 276: 
 277:         bool hasExcludeFromDock = (excludeFromDock != nullptr);
 278:         if (!parcel.WriteBool(hasExcludeFromDock)) {
 279:             return false;
 280:         }
 281:         if (hasExcludeFromDock && !parcel.WriteBool(*excludeFromDock)) {
 282:             return false;
 283:         }
 284: 
 285:         bool hasExcludeFromRecent = (excludeFromRecent != nullptr);
 286:         if (!parcel.WriteBool(hasExcludeFromRecent)) {
 287:             return false;
 288:         }
 289:         if (hasExcludeFromRecent && !parcel.WriteBool(*excludeFromRecent)) {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `0dcfabb07e3a819e`

- 位置：`interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h:68:9`
- Symbol / operation：`asyncContextPtr` / `write`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d`

```cpp
  60: #endif
  61:     int32_t contextType_ = static_cast<int32_t>(REQUEST_GLOBAL_SWITCH_ON_SETTING);
  62: };
  63: 
  64: struct RequestGlobalSwitchAsyncContextHandle {
  65:     explicit RequestGlobalSwitchAsyncContextHandle(
  66:         std::shared_ptr<RequestGlobalSwitchAsyncContext>& requestAsyncContext)
  67:     {
  68:         asyncContextPtr = requestAsyncContext;
  69:     }
  70: 
  71:     std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContextPtr;
  72: };
  73: 
  74: class RequestGlobalSwitchAsyncInstanceControl {
  75:     public:
  76:         static void AddCallbackByInstanceId(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `109e777bac47451e`

- 位置：`kvstoremock/external_inner_kit/napi/include/extension_context.h:61:16`
- Symbol / operation：`abilityInfo_` / `read`
- Repository / commit：`openharmony/distributeddatamgr_kv_store` / `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- source SHA-256：`fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`

```cpp
  53: };
  54: 
  55: class ExtensionContext : public ContextImpl {
  56: public:
  57:     ExtensionContext() = default;
  58:     virtual ~ExtensionContext() = default;
  59: 
  60:     std::shared_ptr<AppExecFwk::AbilityInfo> GetAbilityInfo() const {
  61:         return abilityInfo_;
  62:     }
  63: 
  64:     void SetAbilityInfo(const std::shared_ptr<AppExecFwk::AbilityInfo> &abilityInfo) {
  65:         abilityInfo_ = abilityInfo;
  66:     }
  67: 
  68:     using SelfType = ExtensionContext;
  69:     static const size_t CONTEXT_TYPE_ID;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `11a9e51881bba4a3`

- 位置：`services/core/ability/status_cache/include/status_cache.h:27:67`
- Symbol / operation：`timeUtilsProxy_` / `read`
- Repository / commit：`openharmony/update_updateservice` / `e4942a33cc5ed29040e5c720bea3b2a8e4a79221`
- source SHA-256：`cd9dbbd3a2e16405198c2e6bc63f8178d4c45106b5d8a31a00f713d0f66bc6d9`

```cpp
  19: #include <cstdint>
  20: 
  21: #include "time_utils_proxy.h"
  22: 
  23: namespace OHOS {
  24: namespace UpdateEngine {
  25: class StatusCache {
  26: public:
  27:     StatusCache(std::shared_ptr<TimeUtilsProxy> timeUtilsProxy) : timeUtilsProxy_(timeUtilsProxy) {}
  28:     ~StatusCache() = default;
  29: 
  30:     bool IsChecking();
  31:     void SetIsChecking(bool isChecking);
  32: 
  33: private:
  34:     int64_t GetCurrentTime();
  35: 
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `189d9dc2fec1ba7c`

- 位置：`wm/include/picture_in_picture_controller_ani.h:57:9`
- Symbol / operation：`mainWindowXComponentController_` / `write`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`

```cpp
  49:     std::string GetPiPNavigationId() const override;
  50: 
  51:     inline std::shared_ptr<XComponentController> GetMainWindowXComponentController() const
  52:     {
  53:         return mainWindowXComponentController_;
  54:     }
  55:     inline void SetMainWindowXComponentController(std::shared_ptr<XComponentController> controller)
  56:     {
  57:         mainWindowXComponentController_ = controller;
  58:     }
  59:     inline int32_t GetFirstHandleId() const { return firstHandleId_; }
  60:     inline void SetFirstHandleId(int32_t id) { firstHandleId_ = id; }
  61:     inline sptr<PipOptionAni> GetPipOptionAni() const { return pipOption_; }
  62: 
  63: protected:
  64:     sptr<PipOptionAni> pipOption_ = nullptr;
  65:     ani_vm* vm_ = nullptr;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `18c96f591a6dca1e`

- 位置：`previewer/include/wm_animation_common.h:257:37`
- Symbol / operation：`animationSystemParams` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`

```cpp
 249:     bool minimizeOnStart = false;
 250: 
 251:     bool Marshalling(Parcel& parcel) const override
 252:     {
 253:         if (!parcel.WriteParcelable(animationParams.get())) {
 254:             return false;
 255:         }
 256: 
 257:         if (!parcel.WriteParcelable(animationSystemParams.get())) {
 258:             return false;
 259:         }
 260: 
 261:         bool hasNeedAnimation = (needAnimation != nullptr);
 262:         if (!parcel.WriteBool(hasNeedAnimation)) {
 263:             return false;
 264:         }
 265:         if (hasNeedAnimation && !parcel.WriteBool(*needAnimation)) {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `1fae182b80e03b31`

- 位置：`utils/include/ui_effect_controller_common.h:53:16`
- Symbol / operation：`backgroundFilter_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`

```cpp
  45: const int32_t UIEFFECT_INVALID_ID = -1;
  46: class UIEffectParams : public Parcelable {
  47: public:
  48:     bool Marshalling(Parcel& parcel) const override;
  49:     static UIEffectParams* Unmarshalling(Parcel& parcel);
  50: 
  51:     bool IsEmpty()
  52:     {
  53:         return backgroundFilter_ == nullptr && effect_ == nullptr;
  54:     }
  55: 
  56:     napi_status ConvertToJsValue(napi_env env, napi_value& val);
  57:     napi_status ConvertFromJsValue(napi_env env, napi_value val);
  58: 
  59: private:
  60:     std::shared_ptr<Filter> backgroundFilter_ = nullptr;
  61:     std::shared_ptr<VisualEffect> effect_ = nullptr;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `216f43693c1ed53f`

- 位置：`interfaces/innerkits/wm/wm_animation_common.h:273:52`
- Symbol / operation：`needAnimation` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`

```cpp
 265:         if (!parcel.WriteParcelable(animationSystemParams.get())) {
 266:             return false;
 267:         }
 268: 
 269:         bool hasNeedAnimation = (needAnimation != nullptr);
 270:         if (!parcel.WriteBool(hasNeedAnimation)) {
 271:             return false;
 272:         }
 273:         if (hasNeedAnimation && !parcel.WriteBool(*needAnimation)) {
 274:             return false;
 275:         }
 276: 
 277:         if (!parcel.WriteBool(isWindowLimitsForcible)) {
 278:             return false;
 279:         }
 280: 
 281:         if (!parcel.WriteBool(minimizeOnStart)) {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `262e8786de8d4855`

- 位置：`wm/include/picture_in_picture_controller_ani.h:53:16`
- Symbol / operation：`mainWindowXComponentController_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`

```cpp
  45:     ani_ref GetANICustomNodeController() override;
  46:     ani_ref GetANITypeNode() const override;
  47:     bool IsTypeNodeEnabled() const override;
  48:     bool IsPullPiPAndHandleNavigation();
  49:     std::string GetPiPNavigationId() const override;
  50: 
  51:     inline std::shared_ptr<XComponentController> GetMainWindowXComponentController() const
  52:     {
  53:         return mainWindowXComponentController_;
  54:     }
  55:     inline void SetMainWindowXComponentController(std::shared_ptr<XComponentController> controller)
  56:     {
  57:         mainWindowXComponentController_ = controller;
  58:     }
  59:     inline int32_t GetFirstHandleId() const { return firstHandleId_; }
  60:     inline void SetFirstHandleId(int32_t id) { firstHandleId_ = id; }
  61:     inline sptr<PipOptionAni> GetPipOptionAni() const { return pipOption_; }
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `28f5d974aafabd67`

- 位置：`interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h:61:9`
- Symbol / operation：`asyncContextPtr` / `write`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0`

```cpp
  53:     std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
  54: #endif
  55:     int32_t contextType_ = static_cast<int32_t>(OPEN_PERMISSION_ON_SETTING);
  56: };
  57: 
  58: struct OpenOnSettingAsyncContextHandle {
  59:     explicit OpenOnSettingAsyncContextHandle(std::shared_ptr<OpenPermOnSettingAsyncContext>& openAsyncContext)
  60:     {
  61:         asyncContextPtr = openAsyncContext;
  62:     }
  63: 
  64:     std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContextPtr;
  65: };
  66: 
  67: class OpenOnSettingAsyncInstanceControl {
  68:     public:
  69:         static void AddCallbackByInstanceId(std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `2933d6f08739598b`

- 位置：`interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h:33:22`
- Symbol / operation：`jsCallBack_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`b2de64e2e5bb197f96b1d7693dbe7aca4c5966cd31c9133b17f412c3615a40bc`

```cpp
  25: 
  26: namespace OHOS {
  27: namespace Rosen {
  28: class JsFbWindowListener : public IFbLifeCycle,
  29:                              public IFbClickObserver,
  30:                              public IFbDestroyObserver {
  31: public:
  32:     JsFbWindowListener(napi_env env, const std::shared_ptr<NativeReference>& callback)
  33:         : env_(env), jsCallBack_(callback) {}
  34:     ~JsFbWindowListener() override;
  35:     std::shared_ptr<NativeReference> GetCallbackRef() const;
  36:     void OnFloatingBallStart() override;
  37:     void OnFloatingBallStop() override;
  38: 
  39:     void OnClickEvent() override;
  40:     void OnDestroyEvent(const std::string& reason) override;
  41: 
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `29c57a4203eeb950`

- 位置：`wm/include/picture_in_picture_controller_base.h:141:16`
- Symbol / operation：`pipXComponentController_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`

```cpp
 133:     inline const Rect& GetWindowRect() const { return windowRect_; }
 134:     inline void SetWindowRect(const Rect& rect) { windowRect_ = rect; }
 135:     inline bool GetIsAutoStartEnabled() const { return isAutoStartEnabled_; }
 136:     inline void SetIsAutoStartEnabled(bool enable) { isAutoStartEnabled_ = enable; }
 137:     inline bool GetCurActiveStatus() const { return curActiveStatus_; }
 138:     inline void SetCurActiveStatus(bool status) { curActiveStatus_ = status; }
 139:     inline std::shared_ptr<XComponentController> GetPipXComponentController() const
 140:     {
 141:         return pipXComponentController_;
 142:     }
 143:     inline void SetPipXComponentController(std::shared_ptr<XComponentController> controller)
 144:     {
 145:         pipXComponentController_ = controller;
 146:     }
 147:     inline bool GetIsStoppedFromClient() const { return isStoppedFromClient_; }
 148:     inline void SetIsStoppedFromClient(bool stopped) { isStoppedFromClient_ = stopped; }
 149:     inline int32_t GetHandleId() const { return handleId_; }
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `2c4b4625bf41f268`

- 位置：`services/tokensyncmanager/include/remote/remote_command_executor.h:41:9`
- Symbol / operation：`ptrChannel_` / `write`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`

```cpp
  33:     virtual ~RemoteCommandExecutor();
  34: 
  35:     const std::shared_ptr<RpcChannel>& GetChannel() const
  36:     {
  37:         return ptrChannel_;
  38:     }
  39:     void SetChannel(const std::shared_ptr<RpcChannel>& ptrChannel)
  40:     {
  41:         ptrChannel_ = ptrChannel;
  42:     }
  43: 
  44:     /**
  45:      * @brief Factory method to create a rpc channel. we will only create SoftBusChannel by now.
  46:      *
  47:      * @param targetNodeId target device node id(udid)
  48:      * @return Returns <b>a shared_ptr</b> if the operation is successful, returns <b>nullptr</b> otherwise.
  49:      * @see SoftBusChannel
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `2fd1e3c72dcb88d7`

- 位置：`previewer/include/wm_animation_common.h:214:37`
- Symbol / operation：`animationConfig` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`

```cpp
 206:     AnimationType animationType = AnimationType::FADE_IN_OUT;
 207:     std::shared_ptr<WindowAnimationOption> animationConfig = nullptr;
 208: 
 209:     bool Marshalling(Parcel& parcel) const override
 210:     {
 211:         if (!parcel.WriteUint32(static_cast<uint32_t>(animationType))) {
 212:             return false;
 213:         }
 214:         if (!parcel.WriteParcelable(animationConfig.get())) {
 215:             return false;
 216:         }
 217:         return true;
 218:     }
 219: 
 220:     static StartAnimationSystemOptions* Unmarshalling(Parcel& parcel)
 221:     {
 222:         StartAnimationSystemOptions* startAnimationSystemOptions = new StartAnimationSystemOptions();
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `42a9712edb1f3512`

- 位置：`frameworks/common/js_proxy.h:42:16`
- Symbol / operation：`instance_` / `read`
- Repository / commit：`openharmony/distributeddatamgr_kv_store` / `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- source SHA-256：`38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`

```cpp
  34: public:
  35:     void SetInstance(std::shared_ptr<T> instance)
  36:     {
  37:         instance_ = std::move(instance);
  38:     }
  39: 
  40:     std::shared_ptr<T> GetInstance() const
  41:     {
  42:         return instance_;
  43:     }
  44: 
  45: protected:
  46:     // It is not allowed to directly use parent class objects for construction and destruction
  47:     JSProxy() = default;
  48:     ~JSProxy() = default;
  49: 
  50: private:
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `43861dc7e550047d`

- 位置：`interfaces/innerkits/wm/wm_animation_common.h:297:56`
- Symbol / operation：`excludeFromRecent` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`

```cpp
 289:         if (hasExcludeFromDock && !parcel.WriteBool(*excludeFromDock)) {
 290:             return false;
 291:         }
 292: 
 293:         bool hasExcludeFromRecent = (excludeFromRecent != nullptr);
 294:         if (!parcel.WriteBool(hasExcludeFromRecent)) {
 295:             return false;
 296:         }
 297:         if (hasExcludeFromRecent && !parcel.WriteBool(*excludeFromRecent)) {
 298:             return false;
 299:         }
 300:         return true;
 301:     }
 302:     // LCOV_EXCL_STOP
 303: 
 304:     static WindowCreateParams* Unmarshalling(Parcel& parcel)
 305:     {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `475c88d0bbd639f7`

- 位置：`kvstoremock/external_inner_kit/napi/include/extension_context.h:81:16`
- Symbol / operation：`abilityInfo_` / `read`
- Repository / commit：`openharmony/distributeddatamgr_kv_store` / `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- source SHA-256：`fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`

```cpp
  73: };
  74: 
  75: class AbilityContext : public Context {
  76: public:
  77:     AbilityContext() = default;
  78:     virtual ~AbilityContext() = default;
  79: 
  80:     std::shared_ptr<AppExecFwk::AbilityInfo> GetAbilityInfo() const {
  81:         return abilityInfo_;
  82:     }
  83: 
  84: protected:
  85:     std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo_;
  86: };
  87: 
  88: } // namespace AbilityRuntime
  89: } // namespace OHOS
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `4d1c3c0f1eb52fed`

- 位置：`kvstoremock/external_inner_kit/napi/include/extension_context.h:65:9`
- Symbol / operation：`abilityInfo_` / `write`
- Repository / commit：`openharmony/distributeddatamgr_kv_store` / `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- source SHA-256：`fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`

```cpp
  57:     ExtensionContext() = default;
  58:     virtual ~ExtensionContext() = default;
  59: 
  60:     std::shared_ptr<AppExecFwk::AbilityInfo> GetAbilityInfo() const {
  61:         return abilityInfo_;
  62:     }
  63: 
  64:     void SetAbilityInfo(const std::shared_ptr<AppExecFwk::AbilityInfo> &abilityInfo) {
  65:         abilityInfo_ = abilityInfo;
  66:     }
  67: 
  68:     using SelfType = ExtensionContext;
  69:     static const size_t CONTEXT_TYPE_ID;
  70: 
  71: protected:
  72:     std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo_;
  73: };
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `50d42b057f4213b2`

- 位置：`utils/include/surface_capture_future.h:73:29`
- Symbol / operation：`hdrPixelMap_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`

```cpp
  65:  
  66:     std::vector<std::shared_ptr<Media::PixelMap>> GetHDRResult(long timeOut)
  67:     {
  68:         std::unique_lock <std::mutex> lock(mutex_);
  69:         if (!DmUtils::safe_wait_for(conditionVariable_, lock,
  70:             std::chrono::milliseconds(timeOut), [this] { return IsReady(); })) {
  71:             TLOGE(WmsLogTag::DEFAULT, "wait for %{public}ld, timeout.", timeOut);
  72:         }
  73:         return { pixelMap_, hdrPixelMap_ };
  74:     }
  75: 
  76: protected:
  77:     void Call(std::shared_ptr<Media::PixelMap> pixelmap) override
  78:     {
  79:         if (!flag_) {
  80:             pixelMap_ = pixelmap;
  81:             flag_ = true;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `5c64a5975b7d348e`

- 位置：`wmserver/include/drag_controller.h:68:9`
- Symbol / operation：`vsyncCallback_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`9e59f4470eb1d59efaa1b12643d579b4f5315dc69a61250fbf3a05823f2efa23`

```cpp
  60: 
  61: /*
  62:  * MoveDragController is the class which is used to handle move or drag floating window
  63:  */
  64: class MoveDragController : public RefBase {
  65: public:
  66:     MoveDragController() : windowProperty_(new WindowProperty()), moveDragProperty_(new MoveDragProperty())
  67:     {
  68:         vsyncCallback_->onCallback =
  69:             [this](int64_t timeStamp, int64_t _) { this->OnReceiveVsync(timeStamp); };
  70:     }
  71:     ~MoveDragController() = default;
  72: 
  73:     bool Init();
  74:     void Stop();
  75:     void HandleReadyToMoveOrDrag(uint32_t windowId, sptr<WindowProperty>& windowProperty,
  76:         sptr<MoveDragProperty>& moveDragProperty);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `61fadc5b5d197135`

- 位置：`previewer/include/wm_animation_common.h:253:37`
- Symbol / operation：`animationParams` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`

```cpp
 245:     /**
 246:      * @brief Whether application-defined window size limits are allowed to exceed system limits.
 247:      */
 248:     bool isWindowLimitsForcible = false;
 249:     bool minimizeOnStart = false;
 250: 
 251:     bool Marshalling(Parcel& parcel) const override
 252:     {
 253:         if (!parcel.WriteParcelable(animationParams.get())) {
 254:             return false;
 255:         }
 256: 
 257:         if (!parcel.WriteParcelable(animationSystemParams.get())) {
 258:             return false;
 259:         }
 260: 
 261:         bool hasNeedAnimation = (needAnimation != nullptr);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `6dbe3a1c389d9083`

- 位置：`interfaces/kits/cj/accesstoken/include/at_manager_impl.h:115:86`
- Symbol / operation：`data_` / `read`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1`

```cpp
 107: 
 108: private:
 109:     int32_t sessionId_ = 0;
 110:     std::shared_ptr<RequestAsyncContext> reqContext_ = nullptr;
 111: };
 112: 
 113: class AuthorizationResult : public Security::AccessToken::TokenCallbackStub {
 114: public:
 115:     explicit AuthorizationResult(const std::shared_ptr<RequestAsyncContext>& data) : data_(data) {}
 116:     ~AuthorizationResult() override = default;
 117:     void GrantResultsCallback(const std::vector<std::string>& permissions,
 118:         const std::vector<int>& grantResults) override;
 119: 
 120: private:
 121:     std::shared_ptr<RequestAsyncContext> data_ = nullptr;
 122: };
 123: 
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `72b468b6e62a3bfc`

- 位置：`wm/include/picture_in_picture_controller_base.h:145:9`
- Symbol / operation：`pipXComponentController_` / `write`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`

```cpp
 137:     inline bool GetCurActiveStatus() const { return curActiveStatus_; }
 138:     inline void SetCurActiveStatus(bool status) { curActiveStatus_ = status; }
 139:     inline std::shared_ptr<XComponentController> GetPipXComponentController() const
 140:     {
 141:         return pipXComponentController_;
 142:     }
 143:     inline void SetPipXComponentController(std::shared_ptr<XComponentController> controller)
 144:     {
 145:         pipXComponentController_ = controller;
 146:     }
 147:     inline bool GetIsStoppedFromClient() const { return isStoppedFromClient_; }
 148:     inline void SetIsStoppedFromClient(bool stopped) { isStoppedFromClient_ = stopped; }
 149:     inline int32_t GetHandleId() const { return handleId_; }
 150:     inline void SetHandleId(int32_t id) { handleId_ = id; }
 151:     inline sptr<Window> GetMainWindow() const { return mainWindow_; }
 152: 
 153:     // diffrent between normal and web
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `7c0cc08d2a792c8c`

- 位置：`services/tokensyncmanager/include/remote/remote_command_executor.h:37:16`
- Symbol / operation：`ptrChannel_` / `read`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`

```cpp
  29: namespace AccessToken {
  30: class RemoteCommandExecutor final : public std::enable_shared_from_this<RemoteCommandExecutor>  {
  31: public:
  32:     explicit RemoteCommandExecutor(const std::string &targetNodeId);
  33:     virtual ~RemoteCommandExecutor();
  34: 
  35:     const std::shared_ptr<RpcChannel>& GetChannel() const
  36:     {
  37:         return ptrChannel_;
  38:     }
  39:     void SetChannel(const std::shared_ptr<RpcChannel>& ptrChannel)
  40:     {
  41:         ptrChannel_ = ptrChannel;
  42:     }
  43: 
  44:     /**
  45:      * @brief Factory method to create a rpc channel. we will only create SoftBusChannel by now.
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `8523ddac356a47a3`

- 位置：`sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67:86`
- Symbol / operation：`streamListener_` / `read`
- Repository / commit：`openharmony/communication_dsoftbus` / `652f88e0261ce4d0610f73cc451c26b84d2597af`
- source SHA-256：`66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`

```cpp
  59:         {
  60:             listener_->OnRippleStats(data);
  61:         }
  62: 
  63:     private:
  64:         std::shared_ptr<IStreamManagerListener> listener_ = nullptr;
  65:     };
  66: 
  67:     explicit StreamManager(std::shared_ptr<IStreamManagerListener> streamListener) : streamListener_(streamListener) {}
  68:     StreamManager() = delete;
  69:     virtual ~StreamManager() = default;
  70: 
  71:     int32_t CreateStreamClientChannel(IpAndPort &local, IpAndPort remote, Proto protocol,
  72:         int32_t streamType, std::pair<uint8_t*, uint32_t> sessionKey) override;
  73: 
  74:     int32_t CreateStreamServerChannel(IpAndPort &local, Proto protocol, int32_t streamType,
  75:         std::pair<uint8_t*, uint32_t> sessionKey) override;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `8bc53a1a1abb0b3c`

- 位置：`wm/include/picture_in_picture_controller.h:54:9`
- Symbol / operation：`mainWindowXComponentController_` / `write`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`

```cpp
  46:     std::string GetPiPNavigationId() const override;
  47:     
  48:     inline std::shared_ptr<XComponentController> GetMainWindowXComponentController() const
  49:     {
  50:         return mainWindowXComponentController_;
  51:     }
  52:     inline void SetMainWindowXComponentController(std::shared_ptr<XComponentController> controller)
  53:     {
  54:         mainWindowXComponentController_ = controller;
  55:     }
  56:     inline int32_t GetFirstHandleId() const { return firstHandleId_; }
  57:     inline void SetFirstHandleId(int32_t id) { firstHandleId_ = id; }
  58: 
  59: protected:
  60:     WMErrorResult CreatePictureInPictureWindow(StartPipType startType) override;
  61:     void UpdateWinRectByComponent() override;
  62:     void UpdatePiPSourceRect() const override;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `8bf2c12c014dda78`

- 位置：`interfaces/innerkits/wm/wm_animation_common.h:220:37`
- Symbol / operation：`animationConfig` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`

```cpp
 212:     std::shared_ptr<WindowAnimationOption> animationConfig = nullptr;
 213: 
 214:     // LCOV_EXCL_START
 215:     bool Marshalling(Parcel& parcel) const override
 216:     {
 217:         if (!parcel.WriteUint32(static_cast<uint32_t>(animationType))) {
 218:             return false;
 219:         }
 220:         if (!parcel.WriteParcelable(animationConfig.get())) {
 221:             return false;
 222:         }
 223:         return true;
 224:     }
 225:     // LCOV_EXCL_STOP
 226: 
 227:     static StartAnimationSystemOptions* Unmarshalling(Parcel& parcel)
 228:     {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `9428dad22daecdb4`

- 位置：`previewer/include/wm_animation_common.h:265:52`
- Symbol / operation：`needAnimation` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`

```cpp
 257:         if (!parcel.WriteParcelable(animationSystemParams.get())) {
 258:             return false;
 259:         }
 260: 
 261:         bool hasNeedAnimation = (needAnimation != nullptr);
 262:         if (!parcel.WriteBool(hasNeedAnimation)) {
 263:             return false;
 264:         }
 265:         if (hasNeedAnimation && !parcel.WriteBool(*needAnimation)) {
 266:             return false;
 267:         }
 268: 
 269:         if (!parcel.WriteBool(isWindowLimitsForcible)) {
 270:             return false;
 271:         }
 272: 
 273:         if (!parcel.WriteBool(minimizeOnStart)) {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `99ce5dad55f7c1af`

- 位置：`interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h:63:9`
- Symbol / operation：`asyncContextPtr` / `write`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560`

```cpp
  55:     std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
  56: #endif
  57:     int32_t contextType_ = static_cast<int32_t>(REQUEST_PERMISSION_ON_SETTING);
  58: };
  59: 
  60: struct RequestOnSettingAsyncContextHandle {
  61:     explicit RequestOnSettingAsyncContextHandle(std::shared_ptr<RequestPermOnSettingAsyncContext>& requestAsyncContext)
  62:     {
  63:         asyncContextPtr = requestAsyncContext;
  64:     }
  65: 
  66:     std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContextPtr;
  67: };
  68: 
  69: class RequestOnSettingAsyncInstanceControl {
  70:     public:
  71:         static void AddCallbackByInstanceId(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `9a7da68327154c5f`

- 位置：`wm/include/picture_in_picture_controller.h:50:16`
- Symbol / operation：`mainWindowXComponentController_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`

```cpp
  42:     std::shared_ptr<NativeReference> GetCustomNodeController() override;
  43:     std::shared_ptr<NativeReference> GetTypeNode() const override;
  44:     bool IsTypeNodeEnabled() const override;
  45:     bool IsPullPiPAndHandleNavigation();
  46:     std::string GetPiPNavigationId() const override;
  47:     
  48:     inline std::shared_ptr<XComponentController> GetMainWindowXComponentController() const
  49:     {
  50:         return mainWindowXComponentController_;
  51:     }
  52:     inline void SetMainWindowXComponentController(std::shared_ptr<XComponentController> controller)
  53:     {
  54:         mainWindowXComponentController_ = controller;
  55:     }
  56:     inline int32_t GetFirstHandleId() const { return firstHandleId_; }
  57:     inline void SetFirstHandleId(int32_t id) { firstHandleId_ = id; }
  58: 
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `9b3f9c97a527cc4e`

- 位置：`sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67:86`
- Symbol / operation：`streamListener_` / `read`
- Repository / commit：`openharmony/communication_dsoftbus` / `652f88e0261ce4d0610f73cc451c26b84d2597af`
- source SHA-256：`66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`

```cpp
  59:         {
  60:             listener_->OnRippleStats(data);
  61:         }
  62: 
  63:     private:
  64:         std::shared_ptr<IStreamManagerListener> listener_ = nullptr;
  65:     };
  66: 
  67:     explicit StreamManager(std::shared_ptr<IStreamManagerListener> streamListener) : streamListener_(streamListener) {}
  68:     StreamManager() = delete;
  69:     virtual ~StreamManager() = default;
  70: 
  71:     int32_t CreateStreamClientChannel(IpAndPort &local, IpAndPort remote, Proto protocol,
  72:         int32_t streamType, std::pair<uint8_t*, uint32_t> sessionKey) override;
  73: 
  74:     int32_t CreateStreamServerChannel(IpAndPort &local, Proto protocol, int32_t streamType,
  75:         std::pair<uint8_t*, uint32_t> sessionKey) override;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `9c78273d5197f6b0`

- 位置：`wmserver/include/window_common_event.h:41:64`
- Symbol / operation：`eventHandler_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`2ff4b5f81e9305bb595477281b49ff744d516c90ac962e4c0baf8f34416eb9af`

```cpp
  33:     void UnSubscriberEvent();
  34:     void OnReceiveEvent(const EventFwk::CommonEventData& data);
  35: 
  36: private:
  37:     class EventSubscriber : public EventFwk::CommonEventSubscriber {
  38:     public:
  39:         EventSubscriber(const EventFwk::CommonEventSubscribeInfo& subscriberInfo,
  40:             const std::shared_ptr<WindowCommonEvent>& eventHandler)
  41:             : EventFwk::CommonEventSubscriber(subscriberInfo), eventHandler_(eventHandler) {};
  42:         ~EventSubscriber() = default;
  43:         void OnReceiveEvent(const EventFwk::CommonEventData& data) override
  44:         {
  45:             eventHandler_->OnReceiveEvent(data);
  46:         }
  47:         
  48:     private:
  49:         std::shared_ptr<WindowCommonEvent> eventHandler_;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `a434fff861916fd3`

- 位置：`frameworks/common/js_proxy.h:37:9`
- Symbol / operation：`instance_` / `write`
- Repository / commit：`openharmony/distributeddatamgr_kv_store` / `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- source SHA-256：`38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`

```cpp
  29:     ~JSCreator() = default;
  30: };
  31: 
  32: template<typename T>
  33: class JSProxy {
  34: public:
  35:     void SetInstance(std::shared_ptr<T> instance)
  36:     {
  37:         instance_ = std::move(instance);
  38:     }
  39: 
  40:     std::shared_ptr<T> GetInstance() const
  41:     {
  42:         return instance_;
  43:     }
  44: 
  45: protected:
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `addd5418e89eb1f1`

- 位置：`interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:72:9`
- Symbol / operation：`asyncContextPtr` / `write`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`

```cpp
  64:     {
  65:         result.errorCode = errcode;
  66:     }
  67: };
  68: 
  69: struct RequestAsyncContextHandle {
  70:     explicit RequestAsyncContextHandle(std::shared_ptr<RequestAsyncContext>& requestAsyncContext)
  71:     {
  72:         asyncContextPtr = requestAsyncContext;
  73:     }
  74: 
  75:     std::shared_ptr<RequestAsyncContext> asyncContextPtr;
  76: };
  77: 
  78: class RequestAsyncInstanceControl {
  79:     public:
  80:         static void AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContext>& asyncContext);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `b578e1c0b3670993`

- 位置：`interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h:51:9`
- Symbol / operation：`asyncContextPtr` / `write`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2`

```cpp
  43:     bool releaseFlag = false;
  44:     std::function<void(RetDataBool)> callbackRef = nullptr;
  45: };
  46: 
  47: struct RequestGlobalSwitchAsyncContextHandle {
  48:     explicit RequestGlobalSwitchAsyncContextHandle(
  49:         std::shared_ptr<RequestGlobalSwitchAsyncContext>& requestAsyncContext)
  50:     {
  51:         asyncContextPtr = requestAsyncContext;
  52:     }
  53: 
  54:     std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContextPtr;
  55: };
  56: 
  57: class SwitchOnSettingUICallback {
  58: public:
  59:     explicit SwitchOnSettingUICallback(const std::shared_ptr<RequestGlobalSwitchAsyncContext>& reqContext);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `bc7c8154a71b4ae2`

- 位置：`previewer/include/wm_animation_common.h:289:56`
- Symbol / operation：`excludeFromRecent` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`

```cpp
 281:         if (hasExcludeFromDock && !parcel.WriteBool(*excludeFromDock)) {
 282:             return false;
 283:         }
 284: 
 285:         bool hasExcludeFromRecent = (excludeFromRecent != nullptr);
 286:         if (!parcel.WriteBool(hasExcludeFromRecent)) {
 287:             return false;
 288:         }
 289:         if (hasExcludeFromRecent && !parcel.WriteBool(*excludeFromRecent)) {
 290:             return false;
 291:         }
 292:         return true;
 293:     }
 294: 
 295:     static WindowCreateParams* Unmarshalling(Parcel& parcel)
 296:     {
 297:         auto windowCreateParams = std::make_unique<WindowCreateParams>();
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `bffe538666df990b`

- 位置：`interfaces/kits/napi/float_view_napi/js_float_view_listener.h:32:22`
- Symbol / operation：`jsCallBack_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`fe3710593c477a3c4e450eee87e8ab89267a0312738bacece7f34686d7fa2e1b`

```cpp
  24: namespace OHOS {
  25: namespace Rosen {
  26: 
  27: class JsFloatViewListener : public IFvStateChangeObserver,
  28:                             public IFvRectChangeObserver,
  29:                             public IFvLimitsChangeObserver {
  30: public:
  31:     JsFloatViewListener(napi_env env, const std::shared_ptr<NativeReference>& callback)
  32:         : env_(env), jsCallBack_(callback) {}
  33:     ~JsFloatViewListener() override;
  34:     std::shared_ptr<NativeReference> GetCallbackRef() const;
  35: 
  36:     void OnStateChange(const FloatViewState& state, const std::string& stopReason) override;
  37:     void OnRectangleChange(const Rect& window, double scale, const std::string& reason) override;
  38:     void OnLimitsChange(const FloatViewLimits& limits) override;
  39: 
  40: private:
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `cacae956a5a61860`

- 位置：`utils/include/ui_effect_controller_common.h:53:48`
- Symbol / operation：`effect_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`

```cpp
  45: const int32_t UIEFFECT_INVALID_ID = -1;
  46: class UIEffectParams : public Parcelable {
  47: public:
  48:     bool Marshalling(Parcel& parcel) const override;
  49:     static UIEffectParams* Unmarshalling(Parcel& parcel);
  50: 
  51:     bool IsEmpty()
  52:     {
  53:         return backgroundFilter_ == nullptr && effect_ == nullptr;
  54:     }
  55: 
  56:     napi_status ConvertToJsValue(napi_env env, napi_value& val);
  57:     napi_status ConvertFromJsValue(napi_env env, napi_value val);
  58: 
  59: private:
  60:     std::shared_ptr<Filter> backgroundFilter_ = nullptr;
  61:     std::shared_ptr<VisualEffect> effect_ = nullptr;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `cc38ebb39a402845`

- 位置：`interfaces/innerkits/wm/wm_animation_common.h:289:54`
- Symbol / operation：`excludeFromDock` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`

```cpp
 281:         if (!parcel.WriteBool(minimizeOnStart)) {
 282:             return false;
 283:         }
 284: 
 285:         bool hasExcludeFromDock = (excludeFromDock != nullptr);
 286:         if (!parcel.WriteBool(hasExcludeFromDock)) {
 287:             return false;
 288:         }
 289:         if (hasExcludeFromDock && !parcel.WriteBool(*excludeFromDock)) {
 290:             return false;
 291:         }
 292: 
 293:         bool hasExcludeFromRecent = (excludeFromRecent != nullptr);
 294:         if (!parcel.WriteBool(hasExcludeFromRecent)) {
 295:             return false;
 296:         }
 297:         if (hasExcludeFromRecent && !parcel.WriteBool(*excludeFromRecent)) {
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `ce61b4591bfb3ad9`

- 位置：`interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h:49:9`
- Symbol / operation：`asyncContextPtr` / `write`
- Repository / commit：`openharmony/security_access_token` / `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- source SHA-256：`a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450`

```cpp
  41:     bool uiAbilityFlag = false;
  42:     bool releaseFlag = false;
  43:     std::function<void(RetDataCArrI32)> callbackRef =  nullptr;
  44: };
  45: 
  46: struct RequestOnSettingAsyncContextHandle {
  47:     explicit RequestOnSettingAsyncContextHandle(std::shared_ptr<RequestPermOnSettingAsyncContext>& requestAsyncContext)
  48:     {
  49:         asyncContextPtr = requestAsyncContext;
  50:     }
  51: 
  52:     std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContextPtr;
  53: };
  54: 
  55: class PermissonOnSettingUICallback {
  56: public:
  57:     explicit PermissonOnSettingUICallback(const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext);
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：

## `ea22cf515d93fc90`

- 位置：`utils/include/surface_capture_future.h:73:18`
- Symbol / operation：`pixelMap_` / `read`
- Repository / commit：`openharmony/window_window_manager` / `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- source SHA-256：`6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`

```cpp
  65:  
  66:     std::vector<std::shared_ptr<Media::PixelMap>> GetHDRResult(long timeOut)
  67:     {
  68:         std::unique_lock <std::mutex> lock(mutex_);
  69:         if (!DmUtils::safe_wait_for(conditionVariable_, lock,
  70:             std::chrono::milliseconds(timeOut), [this] { return IsReady(); })) {
  71:             TLOGE(WmsLogTag::DEFAULT, "wait for %{public}ld, timeout.", timeOut);
  72:         }
  73:         return { pixelMap_, hdrPixelMap_ };
  74:     }
  75: 
  76: protected:
  77:     void Call(std::shared_ptr<Media::PixelMap> pixelmap) override
  78:     {
  79:         if (!flag_) {
  80:             pixelMap_ = pixelmap;
  81:             flag_ = true;
```

- 盲审标签：
- 证据位置：
- 排除或保留理由：
- 待补事实：
- 最小复现方向：
