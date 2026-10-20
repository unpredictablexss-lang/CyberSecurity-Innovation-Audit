// The constant is the reviewed one, the value is the reviewed one, and the
// question asked of it is about the wrong identity domain. A TokenID is not a UID:
// comparing `GetCallingTokenID()` against 3020 compares a token number with an
// account number, which no reviewed record says means anything. The guard is
// recorded as seen-and-not-credited rather than silently ignored, because a
// reviewer has to see that the operation is behind something that failed to
// answer about the caller.
#include "common_types.h"

static const int32_t ACCESSTOKEN_UID = 3020;

class IFixtureTokenIdGuard {
public:
    static const char *GetDescriptor();
};

class TokenIdGuardStub : public IRemoteStub<IFixtureTokenIdGuard> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply);
    bool IsAccessTokenCalling() const;
};

bool TokenIdGuardStub::IsAccessTokenCalling() const {
    unsigned callingToken = IPCSkeleton::GetCallingTokenID();
    return callingToken == ACCESSTOKEN_UID;
}

void TokenIdGuardStub::GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsAccessTokenCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = this->GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int TokenIdGuardStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixtureTokenIdGuard::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        GetRemoteHapTokenInfoInner(data, reply);
        break;
    }
    return 0;
}
