#include "service.h"
int AppMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case 1: return HandleGetAppRunningStateByBundleName(data, reply);
        default: return -1;
    }
}
int AppMgrStub::HandleGetAppRunningStateByBundleName(MessageParcel &data,
                                                     MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    bool result = GetAppRunningStateByBundleName(bundleName);
    reply.WriteBool(result);
    return 0;
}
bool AppMgrService::GetAppRunningStateByBundleName(const std::string &bundleName)
{
    if (!IsReady()) {
        return false;
    }
    return appMgrServiceInner_->GetAppRunningStateByBundleName(bundleName);
}
bool AppMgrServiceInner::GetAppRunningStateByBundleName(const std::string &bundleName)
{
    if (!PermissionVerification::GetInstance()->IsSACall()) {
        return false;
    }
    return false;
}
