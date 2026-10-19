#pragma once
#include <cstdint>
#include <string>
namespace std { template<class T> class shared_ptr {}; }
class MessageParcel { public: std::string ReadString(); bool WriteBool(bool); };
class MessageOption {};
class IRemoteStub {};
class AppMgrServiceInner {
public:
    bool GetAppRunningStateByBundleName(const std::string &bundleName);
};
class AppMgrStub : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                        MessageOption &option);
    int HandleGetAppRunningStateByBundleName(MessageParcel &data, MessageParcel &reply);
    virtual bool GetAppRunningStateByBundleName(const std::string &bundleName) = 0;
};
class AppMgrService : public AppMgrStub {
public:
    bool GetAppRunningStateByBundleName(const std::string &bundleName) override;
    bool IsReady();
private:
    std::shared_ptr<AppMgrServiceInner> appMgrServiceInner_;
};
class PermissionVerification {
public:
    static PermissionVerification *GetInstance();
    bool IsSACall();
};
