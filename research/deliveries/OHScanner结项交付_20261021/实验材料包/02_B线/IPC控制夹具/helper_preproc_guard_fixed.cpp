// M3: the authorization decision is a same-file helper whose returns sit inside a
// preprocessor conditional, so the build variant is unknown. Both arms are read:
// the helper means "a trusted uid is calling" when it returns true, and the
// handler that leaves on the negation of it is protected.
#include "common_types.h"

constexpr int ROOT_UID = 0;
constexpr unsigned TOKEN_NATIVE = 1;
struct AccessTokenIDInner { unsigned type; };

class IFixturePreprocGuard {
public:
    static const char *GetDescriptor();
};

class PreprocGuardStub : public IRemoteStub<IFixturePreprocGuard> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleInner(MessageParcel &data, MessageParcel &reply);
    bool IsRootCalling() const;
    bool IsNativeProcessCalling() const;
};

bool PreprocGuardStub::IsNativeProcessCalling() const {
    unsigned tokenCaller = IPCSkeleton::GetCallingTokenID();
    uint32_t type = (reinterpret_cast<AccessTokenIDInner*>(&tokenCaller))->type;
    return type == TOKEN_NATIVE;
}

bool PreprocGuardStub::IsRootCalling() const {
#ifndef FIXTURE_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#else
    return false;
#endif
}

void PreprocGuardStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsRootCalling() && !IsNativeProcessCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int PreprocGuardStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixturePreprocGuard::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
