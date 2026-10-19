// M3 negative control: the same preprocessor-conditional helper, but the handler
// never asks it. Summarizing the helper must not be mistaken for a guard the
// handler actually performs.
#include "common_types.h"

constexpr int ROOT_UID = 0;
struct AccessTokenIDInner { unsigned type; };

class IFixturePreprocUnguarded {
public:
    static const char *GetDescriptor();
};

class PreprocUnguardedStub : public IRemoteStub<IFixturePreprocUnguarded> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleInner(MessageParcel &data, MessageParcel &reply);
    bool IsRootCalling() const;
};

bool PreprocUnguardedStub::IsRootCalling() const {
#ifndef FIXTURE_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#else
    return false;
#endif
}

void PreprocUnguardedStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    int result = GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int PreprocUnguardedStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixturePreprocUnguarded::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
