// The account is real and the guard is the reviewed one -- and the operation
// behind it is not. `SetPermission` is not one of the three operations the
// access-token service's account is recorded as authorizing, so recognizing the
// caller as that account says nothing about this call and the candidate stays. An
// account is not a permission: a model that let a caller's account satisfy every
// sensitive call behind its guard would be the general authorization injection
// this record exists to prevent.
#include "common_types.h"

static const int32_t ACCESSTOKEN_UID = 3020;

class IFixtureUnrelatedCall {
public:
    static const char *GetDescriptor();
};

class UnrelatedCallStub : public IRemoteStub<IFixtureUnrelatedCall> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void SetPermissionInner(MessageParcel &data, MessageParcel &reply);
    bool IsAccessTokenCalling() const;
};

bool UnrelatedCallStub::IsAccessTokenCalling() const {
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ACCESSTOKEN_UID;
}

void UnrelatedCallStub::SetPermissionInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsAccessTokenCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = this->SetPermission(1);
    reply.WriteInt32(result);
}

int UnrelatedCallStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixtureUnrelatedCall::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        SetPermissionInner(data, reply);
        break;
    }
    return 0;
}
