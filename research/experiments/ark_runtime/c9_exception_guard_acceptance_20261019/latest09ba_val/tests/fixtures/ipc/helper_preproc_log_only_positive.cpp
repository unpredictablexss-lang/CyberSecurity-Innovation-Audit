// M3 log-only control: the helper decides correctly and the handler branches on
// it, but the branch only logs. Nothing stops the transaction, so the log is not
// a guard and the call after it is still unauthorized on that path.
#include "common_types.h"

constexpr int ROOT_UID = 0;

class IFixturePreprocLogOnly {
public:
    static const char *GetDescriptor();
};

class PreprocLogOnlyStub : public IRemoteStub<IFixturePreprocLogOnly> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleInner(MessageParcel &data, MessageParcel &reply);
    bool IsRootCalling() const;
};

bool PreprocLogOnlyStub::IsRootCalling() const {
#ifndef FIXTURE_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#else
    return false;
#endif
}

void PreprocLogOnlyStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsRootCalling()) {
        LOG("caller is not root");
    }
    int result = GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int PreprocLogOnlyStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixturePreprocLogOnly::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
